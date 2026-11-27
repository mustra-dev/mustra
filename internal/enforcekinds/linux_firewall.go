package enforcekinds

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Linux Firewall: one form over the three firewalls a Linux fleet actually
// runs -- firewalld, ufw and plain nftables. The endpoint picks the
// backend (or the policy names one), and every check and fix carries the
// code for all three, so one policy holds a mixed fleet.
//
// The checks are u: rules. A host with none of the three, or one whose
// configuration cannot be read, answers "unknown:", and Enforce never
// remediates an unknown. An agent too old to know u: reads the whole
// policy as unknown, which is the same safe answer.
//
// Nothing here may cut off the management path. The agent's NATS
// connection is outbound, so its replies are established traffic: all
// three backends accept established and related packets (firewalld and
// ufw by their own defaults, the mustra nftables table explicitly), the
// fixes never touch outbound policy, and whenever a fix could bring a
// firewall up -- enabling it, or tightening its default -- it first adds
// the SSH allowance (unless the policy turned that off) and, when
// activating, every allowed service, so the firewall comes up with the
// whole policy rather than with a default deny and nothing else.
//
// The policy is additive on firewalld and ufw: it adds what it lists and
// never removes rules somebody else made. On nftables it owns one table,
// inet mustra, and replaces that table atomically; other tables are left
// alone (a packet must be accepted by every base chain on the hook, so
// mustra's table holds the line whatever else is loaded).

// KindLinuxFirewall is the Linux host firewall typed policy.
const KindLinuxFirewall Kind = "linux_firewall"

// LinuxFirewallService is one inbound allowance.
type LinuxFirewallService struct {
	// Name labels the setting; it never reaches a command.
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // tcp | udp
	// Port is one port or a range, 8000-8100 (8000:8100 is accepted).
	Port string `json:"port"`
	// Source optionally limits the allowance to an address or CIDR.
	Source string `json:"source,omitempty"`
}

// LinuxFirewallConfig is the form of a Linux Firewall policy.
type LinuxFirewallConfig struct {
	// Backend is auto (detected on each endpoint), firewalld, ufw or
	// nftables. A named backend that is not installed reports unknown.
	Backend string `json:"backend"`
	// DefaultInbound is drop (discard silently) or deny (refuse: reject
	// with a TCP reset or ICMP error).
	DefaultInbound string `json:"default_inbound"`
	// AllowSSH keeps SSH reachable whatever else the policy says. Absent
	// means on: a policy written by hand that forgets the field must not
	// lock its author out.
	AllowSSH *bool                  `json:"allow_ssh,omitempty"`
	SSHPort  int                    `json:"ssh_port,omitempty"`
	Services []LinuxFirewallService `json:"services"`
}

// DefaultLinuxFirewall is the form a new Linux Firewall policy starts
// from.
func DefaultLinuxFirewall() LinuxFirewallConfig {
	on := true
	return LinuxFirewallConfig{Backend: "auto", DefaultInbound: "drop", AllowSSH: &on, SSHPort: 22, Services: []LinuxFirewallService{}}
}

// lfwRule is a validated, normalised allowance.
type lfwRule struct {
	label  string
	proto  string // tcp | udp
	lo, hi int
	source string // "" | address | network in canonical form
	v6     bool
	ssh    bool
}

func (r lfwRule) port(sep string) string {
	if r.lo == r.hi {
		return strconv.Itoa(r.lo)
	}
	return strconv.Itoa(r.lo) + sep + strconv.Itoa(r.hi)
}

func (r lfwRule) key() string { return r.proto + "/" + r.port("-") + "/" + r.source }

// tag names the rule in the nftables table, derived from what the rule
// is, so a changed rule is a different rule.
func (r lfwRule) tag() string {
	if r.ssh {
		return "mustra-ssh-" + strconv.Itoa(r.lo)
	}
	h := sha1.Sum([]byte(r.key()))
	return "mustra-svc-" + hex.EncodeToString(h[:5])
}

func (r lfwRule) describe() string {
	s := r.port("-") + "/" + r.proto
	if r.source != "" {
		s += " from " + r.source
	}
	return s
}

func compileLinuxFirewall(c LinuxFirewallConfig) ([]proto.EnforceSetting, error) {
	backend := strings.ToLower(strings.TrimSpace(c.Backend))
	switch backend {
	case "":
		backend = "auto"
	case "auto", "firewalld", "ufw", "nftables":
	default:
		return nil, fmt.Errorf("backend must be auto, firewalld, ufw or nftables")
	}
	def := strings.ToLower(strings.TrimSpace(c.DefaultInbound))
	switch def {
	case "":
		def = "drop"
	case "drop", "deny":
	default:
		return nil, fmt.Errorf("default inbound policy must be drop or deny")
	}
	allowSSH := c.AllowSSH == nil || *c.AllowSSH
	sshPort := c.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}
	if sshPort < 1 || sshPort > 65535 {
		return nil, fmt.Errorf("the SSH port must be between 1 and 65535")
	}

	var rules []lfwRule
	if allowSSH {
		rules = append(rules, lfwRule{label: "SSH", proto: "tcp", lo: sshPort, hi: sshPort, ssh: true})
	}
	seen := map[string]string{}
	for i, s := range c.Services {
		r, err := parseLinuxService(s)
		if err != nil {
			label := strings.TrimSpace(s.Name)
			if label == "" {
				label = fmt.Sprintf("service %d", i+1)
			}
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if prev, dup := seen[r.key()]; dup {
			return nil, fmt.Errorf("%s and %s allow the same thing (%s)", prev, r.label, r.describe())
		}
		seen[r.key()] = r.label
		rules = append(rules, r)
	}

	g := lfwGen{backend: backend, def: def, rules: rules}
	var out []proto.EnforceSetting
	for _, r := range rules {
		name := "Linux firewall: allow " + r.label + " (" + r.describe() + ")"
		sev := "medium"
		if r.ssh {
			name = "Linux firewall: SSH stays reachable (" + r.describe() + ")"
			sev = "high"
		}
		out = append(out, proto.EnforceSetting{
			ID: stableID(KindLinuxFirewall, "allow", r.key()), Severity: sev, Name: name,
			Rules:          []string{g.check(g.allowCheck(r))},
			RemediateLinux: g.fix(g.allowFix(r)),
		})
	}
	defName := map[string]string{"drop": "drop (discard silently)", "deny": "deny (refuse with a reset or ICMP error)"}[def]
	out = append(out, proto.EnforceSetting{
		ID: stableID(KindLinuxFirewall, "default-inbound"), Severity: "high",
		Name:           "Linux firewall: inbound default is " + defName,
		Rules:          []string{g.check(g.defaultCheck())},
		RemediateLinux: g.fix(g.defaultFix()),
	})
	out = append(out, proto.EnforceSetting{
		ID: stableID(KindLinuxFirewall, "active"), Severity: "high",
		Name:           "Linux firewall: active now and enabled at boot",
		Rules:          []string{g.check(g.activeCheck())},
		RemediateLinux: g.fix(g.activeFix()),
	})
	return out, nil
}

func parseLinuxService(s LinuxFirewallService) (lfwRule, error) {
	r := lfwRule{label: strings.TrimSpace(s.Name)}
	r.proto = strings.ToLower(strings.TrimSpace(s.Protocol))
	if r.proto == "" {
		r.proto = "tcp"
	}
	if r.proto != "tcp" && r.proto != "udp" {
		return r, fmt.Errorf("protocol must be tcp or udp")
	}
	port := strings.ReplaceAll(strings.TrimSpace(s.Port), ":", "-")
	if !validPort(port) {
		return r, fmt.Errorf("%q is not a port or port range", s.Port)
	}
	lo, hi, isRange := strings.Cut(port, "-")
	r.lo, _ = strconv.Atoi(lo)
	r.hi = r.lo
	if isRange {
		r.hi, _ = strconv.Atoi(hi)
		if r.hi < r.lo {
			return r, fmt.Errorf("port range %q runs backwards", s.Port)
		}
	}
	if src := strings.TrimSpace(s.Source); src != "" && !strings.EqualFold(src, "any") {
		norm, v6, err := normaliseSource(src)
		if err != nil {
			return r, err
		}
		r.source, r.v6 = norm, v6
	}
	if r.label == "" {
		r.label = r.describe()
	}
	return r, nil
}

// normaliseSource reduces an address or CIDR to the form the firewalls
// print back -- network address, bare host for a single address -- since
// the checks compare against what the firewall reports.
func normaliseSource(src string) (string, bool, error) {
	if ip := net.ParseIP(src); ip != nil {
		return ip.String(), ip.To4() == nil, nil
	}
	ip, n, err := net.ParseCIDR(src)
	if err != nil {
		return "", false, fmt.Errorf("source %q is not an IP address or CIDR", src)
	}
	v6 := ip.To4() == nil
	if ones, bits := n.Mask.Size(); ones == bits {
		return n.IP.String(), v6, nil
	}
	return n.String(), v6, nil
}

// --- script generation ---------------------------------------------------
//
// Every rule and fix is one line of POSIX sh: rules are stored and shown
// one per line, and a rule's command ends at its first " -> ", which
// therefore never appears in the generated script. Values that reach the
// shell are validated numbers, protocols and addresses; names never do.

type lfwGen struct {
	backend string
	def     string
	rules   []lfwRule
}

const (
	lfwNftDir  = "/etc/nftables.d"
	lfwNftFile = "/etc/nftables.d/mustra.nft"
	lfwPrelude = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; have() { command -v \"$1\" >/dev/null 2>&1; }; "
	// The nftables service's main file differs by family: Red Hat's
	// lives under sysconfig, Debian's in /etc.
	lfwNftMain = "m=/etc/nftables.conf; [ -f /etc/sysconfig/nftables.conf ] && m=/etc/sysconfig/nftables.conf; "
)

// check wraps a per-backend body into a u: rule. Each body prints "ok",
// "drift: …" or "unknown: …" as its first line.
func (g lfwGen) check(bodies map[string]string) string {
	return "u:" + lfwPrelude + g.detect("echo 'unknown: %s'; exit 0") + g.dispatch(bodies, "echo 'unknown: %s'; exit 0") + " -> r:^ok$"
}

// fix wraps a per-backend body into a remediation command, which fails
// loudly rather than guessing when no backend is present.
func (g lfwGen) fix(bodies map[string]string) string {
	return lfwPrelude + g.detect("echo '%s' >&2; exit 1") + g.dispatch(bodies, "echo '%s' >&2; exit 1")
}

// detect sets $b to the backend to use. With auto, a firewall that is
// running wins over one that is merely installed, so the policy follows
// whatever the host is actually using; among installed-only ones,
// firewalld, then ufw, then nftables.
func (g lfwGen) detect(fail string) string {
	var s string
	switch g.backend {
	case "firewalld":
		s = "b=; have firewall-cmd && b=firewalld; "
		return s + "[ -n \"$b\" ] || { " + fmt.Sprintf(fail, "firewalld (firewall-cmd) is not installed") + "; }; "
	case "ufw":
		s = "b=; have ufw && b=ufw; "
		return s + "[ -n \"$b\" ] || { " + fmt.Sprintf(fail, "ufw is not installed") + "; }; "
	case "nftables":
		s = "b=; have nft && b=nftables; "
		return s + "[ -n \"$b\" ] || { " + fmt.Sprintf(fail, "nftables (nft) is not installed") + "; }; "
	}
	s = "b=; if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then b=firewalld; " +
		"elif have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then b=ufw; " +
		"elif have nft && { systemctl is-active --quiet nftables 2>/dev/null || nft list table inet mustra >/dev/null 2>&1; }; then b=nftables; " +
		"elif have firewall-cmd; then b=firewalld; elif have ufw; then b=ufw; elif have nft; then b=nftables; fi; "
	return s + "[ -n \"$b\" ] || { " + fmt.Sprintf(fail, "no supported firewall (firewalld, ufw or nftables) is installed") + "; }; "
}

func (g lfwGen) dispatch(bodies map[string]string, fail string) string {
	s := "case \"$b\" in "
	for _, b := range []string{"firewalld", "ufw", "nftables"} {
		if g.backend != "auto" && g.backend != b {
			continue
		}
		s += b + ") " + bodies[b] + ";; "
	}
	return s + "*) " + fmt.Sprintf(fail, "unsupported firewall backend") + ";; esac"
}

// --- firewalld -----------------------------------------------------------
//
// fwp reads and writes the permanent configuration -- through the daemon
// when it runs, through firewall-offline-cmd when it does not, so a
// stopped firewalld can still be read and prepared before it is started.
// fwr is the runtime configuration, which only exists while it runs.

const fwdPrelude = "if firewall-cmd --state >/dev/null 2>&1; then r=1; z=$(firewall-cmd --get-default-zone 2>/dev/null); else r=0; z=$(firewall-offline-cmd --get-default-zone 2>/dev/null); fi; " +
	"fwp() { if [ \"$r\" = 1 ]; then firewall-cmd --permanent --zone=\"$z\" \"$@\"; else firewall-offline-cmd --zone=\"$z\" \"$@\"; fi; }; " +
	"fwr() { if [ \"$r\" = 1 ]; then firewall-cmd --zone=\"$z\" \"$@\"; else echo yes; fi; }; "

// fwdCheckPrelude adds q, which turns firewalld's yes/no into a status
// and anything else into unknown.
const fwdCheckPrelude = fwdPrelude +
	"[ -n \"$z\" ] || { echo 'unknown: could not read the firewalld default zone'; exit 0; }; " +
	"q() { o=$(\"$@\" 2>/dev/null); case \"$o\" in yes) return 0;; no) return 1;; esac; echo \"unknown: firewalld did not answer $*\"; exit 0; }; "

const fwdFixPrelude = fwdPrelude +
	"[ -n \"$z\" ] || { echo 'could not read the firewalld default zone' >&2; exit 1; }; "

// fwdQuery is the firewalld option that asks about (query), adds (add)
// one allowance; a sourced one is a rich rule.
func fwdOption(r lfwRule, verb string) string {
	if r.source != "" {
		fam := "ipv4"
		if r.v6 {
			fam = "ipv6"
		}
		return fmt.Sprintf("--%s-rich-rule='rule family=\"%s\" source address=\"%s\" port port=\"%s\" protocol=\"%s\" accept'", verb, fam, r.source, r.port("-"), r.proto)
	}
	return fmt.Sprintf("--%s-port=%s/%s", verb, r.port("-"), r.proto)
}

func fwdAllowCheck(r lfwRule) string {
	cond := "q fwp " + fwdOption(r, "query") + " && q fwr " + fwdOption(r, "query")
	if r.ssh && r.lo == 22 {
		// The stock ssh service is the usual way 22 is open.
		cond = "{ { q fwp --query-service=ssh && q fwr --query-service=ssh; } || { " + cond + "; }; }"
	}
	return fwdCheckPrelude + "if " + cond + "; then echo ok; else echo \"drift: " + r.describe() + " is not allowed in firewalld zone $z\"; fi"
}

func fwdAdd(r lfwRule) string {
	opt := fwdOption(r, "add")
	if r.ssh && r.lo == 22 {
		opt = "--add-service=ssh"
	}
	return "fwp " + opt + " >/dev/null && { [ \"$r\" = 0 ] || fwr " + opt + " >/dev/null; }"
}

func (g lfwGen) fwdSSH() string {
	for _, r := range g.rules {
		if r.ssh {
			return fwdAdd(r) + "; "
		}
	}
	return ""
}

func (g lfwGen) fwdTarget() string {
	if g.def == "drop" {
		return "DROP"
	}
	return "default"
}

// --- ufw -----------------------------------------------------------------
//
// ufw is read from its own files: /etc/default/ufw for the defaults, and
// the "### tuple ###" lines ufw writes into user.rules / user6.rules for
// each rule -- a machine format, unlike `ufw status`, which only lists
// rules while ufw is active.

const ufwCheckPrelude = "[ -r /etc/default/ufw ] && [ -r /etc/ufw/user.rules ] || { echo 'unknown: cannot read the ufw configuration (/etc/default/ufw, /etc/ufw/user.rules)'; exit 0; }; "

// ufwTuple is the extended regex for the tuple ufw records for an
// allowance from src.
func ufwTuple(r lfwRule, src string) string {
	action, proto, app := "allow", r.proto, ""
	if r.ssh {
		// limit is ufw's rate-limited allow, and an app profile such as
		// OpenSSH records its name and protocol "any": all keep SSH open.
		action, proto, app = "(allow|limit)", "("+r.proto+"|any)", "([^ ]+ - )?"
	}
	return "^### tuple ### " + action + " " + proto + " " + r.port(":") + " " + ere(anyAddr(src, false)) + " any " + ere(src) + " " + app + "in( |$)"
}

func anyAddr(src string, v6 bool) string {
	if v6 || strings.Contains(src, ":") {
		return "::/0"
	}
	return "0.0.0.0/0"
}

func ere(s string) string { return strings.ReplaceAll(s, ".", "\\.") }

func ufwAllowCheck(r lfwRule) string {
	drift := "{ echo 'drift: " + r.describe() + " is not allowed in ufw'; exit 0; }"
	var s string
	switch {
	case r.source == "":
		s = "grep -Eq '" + ufwTuple(r, "0.0.0.0/0") + "' /etc/ufw/user.rules || " + drift + "; " +
			"if grep -q '^IPV6=yes' /etc/default/ufw; then grep -Eqs '" + ufwTuple(r, "::/0") + "' /etc/ufw/user6.rules || " + drift + "; fi; "
	case r.v6:
		s = "grep -Eqs '" + ufwTuple(r, r.source) + "' /etc/ufw/user6.rules || " + drift + "; "
	default:
		s = "grep -Eq '" + ufwTuple(r, r.source) + "' /etc/ufw/user.rules || " + drift + "; "
	}
	return ufwCheckPrelude + s + "echo ok"
}

func ufwAdd(r lfwRule) string {
	from := "any"
	if r.source != "" {
		from = r.source
	}
	// ufw skips a rule it already has, so this is safe to repeat.
	return "ufw allow proto " + r.proto + " from " + from + " to any port " + r.port(":") + " comment mustra >/dev/null"
}

func (g lfwGen) ufwSSH() string {
	for _, r := range g.rules {
		if r.ssh {
			return ufwAdd(r) + " && "
		}
	}
	return ""
}

func (g lfwGen) ufwPolicy() (file, command string) {
	if g.def == "drop" {
		return "DROP", "deny" // ufw calls a silent drop "deny"
	}
	return "REJECT", "reject"
}

// --- nftables ------------------------------------------------------------
//
// mustra owns the table inet mustra, written to its own file, loaded
// atomically (create, delete, recreate in one transaction) and included
// from the nftables service's main file so it is back at boot. Every
// nftables fix writes the whole table: it is generated from the whole
// policy, so one fix brings every setting into line.

func (g lfwGen) nftHash() string {
	h := sha1.New()
	h.Write([]byte(g.def))
	for _, r := range g.rules {
		h.Write([]byte("|" + r.tag() + "|" + r.key()))
	}
	return hex.EncodeToString(h.Sum(nil)[:6])
}

func (g lfwGen) nftLines() []string {
	lines := []string{
		"#!/usr/sbin/nft -f",
		"# Managed by mustra (Enforce: Linux firewall). Edits are overwritten.",
		"# mustra-policy " + g.nftHash(),
		"table inet mustra",
		"delete table inet mustra",
		"table inet mustra {",
		"  chain input {",
		"    type filter hook input priority 0; policy drop;",
		"    ct state established,related accept comment \"mustra-established\"",
		"    ct state invalid drop",
		"    iif \"lo\" accept",
		"    meta l4proto { icmp, ipv6-icmp } accept",
		"    ip6 saddr fe80::/10 udp dport 546 accept comment \"mustra-dhcpv6-client\"",
	}
	for _, r := range g.rules {
		match := ""
		if r.source != "" {
			fam := "ip"
			if r.v6 {
				fam = "ip6"
			}
			match = fam + " saddr " + r.source + " "
		}
		lines = append(lines, "    "+match+r.proto+" dport "+r.port("-")+" accept comment \""+r.tag()+"\"")
	}
	if g.def == "deny" {
		lines = append(lines,
			"    meta l4proto tcp reject with tcp reset comment \"mustra-default-reject\"",
			"    reject with icmpx type admin-prohibited comment \"mustra-default-reject\"")
	}
	return append(lines, "  }", "}")
}

// nftApply writes, validates, loads and persists the table. nft -c checks
// the file before it replaces the old one, so a bad file never lands.
// The service is enabled but not started: starting it would load the
// main file, which on Debian begins with "flush ruleset" and would wipe
// every other table on the host, Docker's and libvirt's included.
func (g lfwGen) nftApply() string {
	q := make([]string, 0, 24)
	for _, l := range g.nftLines() {
		q = append(q, "'"+l+"'")
	}
	inc := "include \"" + lfwNftFile + "\""
	return lfwNftMain + "mkdir -p " + lfwNftDir + " && printf '%s\\n' " + strings.Join(q, " ") + " > " + lfwNftFile + ".tmp" +
		" && nft -c -f " + lfwNftFile + ".tmp && mv " + lfwNftFile + ".tmp " + lfwNftFile + " && nft -f " + lfwNftFile +
		" && { [ -f \"$m\" ] || printf '%s\\n' '#!/usr/sbin/nft -f' > \"$m\"; }" +
		" && { grep -qF '" + inc + "' \"$m\" || printf '%s\\n' '" + inc + "' >> \"$m\"; }" +
		" && { ! have systemctl || systemctl enable nftables >/dev/null 2>&1; }"
}

const nftCheckPrelude = "nft list tables >/dev/null 2>&1 || { echo 'unknown: nft could not list the ruleset'; exit 0; }; " +
	"nft list table inet mustra >/dev/null 2>&1 || { echo 'drift: the mustra nftables table is not loaded'; exit 0; }; " +
	"c=$(nft list chain inet mustra input 2>/dev/null); "

// --- the three settings, per backend ---------------------------------------

func (g lfwGen) allowCheck(r lfwRule) map[string]string {
	return map[string]string{
		"firewalld": fwdAllowCheck(r),
		"ufw":       ufwAllowCheck(r),
		"nftables": nftCheckPrelude + "if printf '%s\\n' \"$c\" | grep -qF 'comment \"" + r.tag() + "\"'; then echo ok; else echo 'drift: " +
			r.describe() + " is not allowed in the mustra nftables table'; fi",
	}
}

func (g lfwGen) allowFix(r lfwRule) map[string]string {
	return map[string]string{
		"firewalld": fwdFixPrelude + fwdAdd(r),
		"ufw":       ufwAdd(r),
		"nftables":  g.nftApply(),
	}
}

func (g lfwGen) defaultCheck() map[string]string {
	target := g.fwdTarget()
	accept := "DROP"
	if target == "default" {
		accept = "default|%%REJECT%%|REJECT"
	}
	file, _ := g.ufwPolicy()
	nft := nftCheckPrelude + "printf '%s\\n' \"$c\" | grep -q 'policy drop;' || { echo 'drift: the mustra input chain does not default to drop'; exit 0; }; "
	if g.def == "deny" {
		nft += "printf '%s\\n' \"$c\" | grep -qF 'mustra-default-reject' || { echo 'drift: the mustra input chain drops instead of refusing'; exit 0; }; "
	} else {
		nft += "! printf '%s\\n' \"$c\" | grep -qF 'mustra-default-reject' || { echo 'drift: the mustra input chain refuses instead of dropping'; exit 0; }; "
	}
	return map[string]string{
		"firewalld": fwdCheckPrelude + "t=$(fwp --get-target 2>/dev/null); case \"$t\" in " + accept + ") echo ok;; '') echo \"unknown: could not read the target of firewalld zone $z\";; *) echo \"drift: firewalld zone $z has target $t\";; esac",
		"ufw": ufwCheckPrelude + "p=$(grep -E '^DEFAULT_INPUT_POLICY=' /etc/default/ufw | tr -d '\"' | cut -d= -f2); " +
			"case \"$p\" in " + file + ") echo ok;; '') echo 'unknown: /etc/default/ufw sets no DEFAULT_INPUT_POLICY';; *) echo \"drift: ufw default incoming policy is $p\";; esac",
		"nftables": nft + "echo ok",
	}
}

func (g lfwGen) defaultFix() map[string]string {
	_, cmd := g.ufwPolicy()
	return map[string]string{
		// The target is permanent-only in firewalld, so it takes a reload;
		// --reload keeps established connections, unlike --complete-reload.
		"firewalld": fwdFixPrelude + g.fwdSSH() + "fwp --set-target=" + g.fwdTarget() + " >/dev/null && { [ \"$r\" = 0 ] || firewall-cmd --reload >/dev/null; }",
		"ufw":       g.ufwSSH() + "ufw default " + cmd + " incoming >/dev/null",
		"nftables":  g.nftApply(),
	}
}

func (g lfwGen) activeCheck() map[string]string {
	noSystemctl := "have systemctl || { echo 'unknown: there is no systemctl, so starting at boot cannot be read'; exit 0; }; "
	return map[string]string{
		"firewalld": noSystemctl + "firewall-cmd --state >/dev/null 2>&1 || { echo 'drift: firewalld is not running'; exit 0; }; " +
			"e=$(systemctl is-enabled firewalld 2>/dev/null); [ \"$e\" = enabled ] || { echo \"drift: firewalld is not enabled at boot ($e)\"; exit 0; }; echo ok",
		"ufw": "[ -r /etc/ufw/ufw.conf ] || { echo 'unknown: cannot read /etc/ufw/ufw.conf'; exit 0; }; " +
			"ufw status 2>/dev/null | grep -q '^Status: active' || { echo 'drift: ufw is not active'; exit 0; }; " +
			"grep -q '^ENABLED=yes' /etc/ufw/ufw.conf || { echo 'drift: ufw is not enabled at boot (ENABLED in /etc/ufw/ufw.conf)'; exit 0; }; " +
			"if have systemctl; then e=$(systemctl is-enabled ufw 2>/dev/null); case \"$e\" in enabled|static|alias|not-found|'') ;; *) echo \"drift: ufw.service is $e at boot\"; exit 0;; esac; fi; echo ok",
		"nftables": nftCheckPrelude + noSystemctl + lfwNftMain +
			"grep -qF '# mustra-policy " + g.nftHash() + "' " + lfwNftFile + " 2>/dev/null || { echo 'drift: " + lfwNftFile + " does not hold this policy, so it would not survive a reboot'; exit 0; }; " +
			"grep -qF 'include \"" + lfwNftFile + "\"' \"$m\" 2>/dev/null || { echo \"drift: $m does not include " + lfwNftFile + "\"; exit 0; }; " +
			"e=$(systemctl is-enabled nftables 2>/dev/null); [ \"$e\" = enabled ] || { echo \"drift: nftables.service is not enabled at boot ($e)\"; exit 0; }; echo ok",
	}
}

// activeFix brings the firewall up with the whole policy already in it.
func (g lfwGen) activeFix() map[string]string {
	fwd := fwdFixPrelude + "if [ \"$r\" = 1 ]; then systemctl enable firewalld; else "
	for _, r := range g.rules {
		fwd += lfwJoin(r, fwdAdd(r))
	}
	fwd += "fwp --set-target=" + g.fwdTarget() + " >/dev/null && { systemctl unmask firewalld >/dev/null 2>&1; systemctl enable --now firewalld; }; fi"

	ufw := ""
	for _, r := range g.rules {
		ufw += lfwJoin(r, ufwAdd(r))
	}
	_, cmd := g.ufwPolicy()
	ufw += "ufw default " + cmd + " incoming >/dev/null && { ! have systemctl || systemctl enable ufw >/dev/null 2>&1; true; } && ufw --force enable"

	return map[string]string{"firewalld": fwd, "ufw": ufw, "nftables": g.nftApply()}
}

// lfwJoin chains one allowance into an activation fix. SSH must land
// before the firewall comes up, so its failure stops the fix; a service
// that cannot be added (an IPv6 source on a host without IPv6, say) is
// reported by its own setting and does not keep the firewall down.
func lfwJoin(r lfwRule, add string) string {
	if r.ssh {
		return add + " && "
	}
	return "{ " + add + " || true; } && "
}
