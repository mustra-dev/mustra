package enforcekinds

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func compileLFW(t *testing.T, c LinuxFirewallConfig) []proto.EnforceSetting {
	t.Helper()
	settings, err := Compile(KindLinuxFirewall, mustJSON(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return settings
}

func lfwWeb() LinuxFirewallConfig {
	c := DefaultLinuxFirewall()
	c.Services = []LinuxFirewallService{
		{Name: "HTTPS from the LAN", Protocol: "tcp", Port: "443", Source: "10.0.0.0/8"},
		{Name: "Syslog", Protocol: "udp", Port: "514"},
		{Name: "App range", Protocol: "tcp", Port: "8000:8100"},
	}
	return c
}

func settingNamed(t *testing.T, settings []proto.EnforceSetting, prefix string) proto.EnforceSetting {
	t.Helper()
	for _, s := range settings {
		if strings.HasPrefix(s.Name, prefix) {
			return s
		}
	}
	t.Fatalf("no setting named %q*", prefix)
	return proto.EnforceSetting{}
}

func TestLinuxFirewallCompilesInOrder(t *testing.T) {
	settings := compileLFW(t, lfwWeb())
	var names []string
	for _, s := range settings {
		names = append(names, s.Name)
		if len(s.Rules) != 1 || !strings.HasPrefix(s.Rules[0], "u:") || !strings.HasSuffix(s.Rules[0], " -> r:^ok$") {
			t.Errorf("%s: want one u: rule matching ok, got %q", s.Name, s.Rules)
		}
		// A rule's command ends at its first " -> ".
		if strings.Count(s.Rules[0], " -> ") != 1 || strings.Contains(s.RemediateLinux, " -> ") {
			t.Errorf("%s: a generated script contains \" -> \"", s.Name)
		}
		if strings.ContainsAny(s.Rules[0]+s.RemediateLinux, "\n\r") {
			t.Errorf("%s: a generated script spans lines", s.Name)
		}
		if s.RemediateLinux == "" || s.RemediateWindows != "" || s.RemediateDarwin != "" {
			t.Errorf("%s: fixes must be Linux-only", s.Name)
		}
		// Names are labels; they never reach the shell.
		if strings.Contains(s.Rules[0]+s.RemediateLinux, "HTTPS from the LAN") {
			t.Errorf("%s: a service name reached a script", s.Name)
		}
	}
	// SSH first and activation last: when fixes run in order, the
	// allowance exists before the firewall can come up.
	want := []string{
		"Linux firewall: SSH stays reachable (22/tcp)",
		"Linux firewall: allow HTTPS from the LAN (443/tcp from 10.0.0.0/8)",
		"Linux firewall: allow Syslog (514/udp)",
		"Linux firewall: allow App range (8000-8100/tcp)",
		"Linux firewall: inbound default is drop (discard silently)",
		"Linux firewall: active now and enabled at boot",
	}
	if strings.Join(names, "\n") != strings.Join(want, "\n") {
		t.Errorf("settings:\n%s\nwant:\n%s", strings.Join(names, "\n"), strings.Join(want, "\n"))
	}
	again := compileLFW(t, lfwWeb())
	for i := range settings {
		if settings[i].ID != again[i].ID {
			t.Errorf("ids are not stable: %s vs %s", settings[i].ID, again[i].ID)
		}
	}
}

func TestLinuxFirewallPerBackend(t *testing.T) {
	for _, tc := range []struct {
		backend    string
		has, hasnt []string
	}{
		{"firewalld", []string{"firewall-cmd", "firewall-offline-cmd", `--add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="443" protocol="tcp" accept'`, "--add-port=514/udp", "--add-port=8000-8100/tcp", "--add-service=ssh", "--set-target=DROP"},
			[]string{"ufw ", "nft "}},
		{"ufw", []string{"ufw allow proto tcp from 10.0.0.0/8 to any port 443 comment mustra", "ufw allow proto tcp from any to any port 8000:8100", "ufw default deny incoming", "ufw --force enable",
			`^### tuple ### allow tcp 443 0\.0\.0\.0/0 any 10\.0\.0\.0/8 in( |$)`},
			[]string{"firewall-cmd", "nft "}},
		{"nftables", []string{"nft -c -f /etc/nftables.d/mustra.nft.tmp", `'    ip saddr 10.0.0.0/8 tcp dport 443 accept comment "mustra-svc-`, `'    udp dport 514 accept comment "mustra-svc-`, `'    tcp dport 22 accept comment "mustra-ssh-22"'`, `ct state established,related accept`, "systemctl enable nftables"},
			[]string{"firewall-cmd", "ufw ", "enable --now nftables", "reject with"}},
	} {
		c := lfwWeb()
		c.Backend = tc.backend
		all := ""
		for _, s := range compileLFW(t, c) {
			all += s.Rules[0] + "\n" + s.RemediateLinux + "\n"
		}
		for _, h := range tc.has {
			if !strings.Contains(all, h) {
				t.Errorf("%s: missing %s", tc.backend, h)
			}
		}
		for _, h := range tc.hasnt {
			if strings.Contains(all, h) {
				t.Errorf("%s: should not contain %s", tc.backend, h)
			}
		}
	}

	// deny refuses rather than drops, in each backend's own words.
	c := lfwWeb()
	c.DefaultInbound = "deny"
	all := ""
	for _, s := range compileLFW(t, c) {
		all += s.Rules[0] + "\n" + s.RemediateLinux + "\n"
	}
	for _, h := range []string{"--set-target=default", "ufw default reject incoming", "reject with tcp reset", "REJECT) echo ok"} {
		if !strings.Contains(all, h) {
			t.Errorf("deny: missing %s", h)
		}
	}
}

func TestLinuxFirewallSSH(t *testing.T) {
	// A hand-written config that omits allow_ssh keeps SSH open.
	settings, err := Compile(KindLinuxFirewall, []byte(`{"backend":"ufw","services":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	ssh := settingNamed(t, settings, "Linux firewall: SSH")
	if !strings.Contains(ssh.RemediateLinux, "port 22 ") {
		t.Errorf("ssh fix: %s", ssh.RemediateLinux)
	}
	// Activation and tightening the default both add SSH first.
	for _, name := range []string{"Linux firewall: inbound default", "Linux firewall: active"} {
		fix := settingNamed(t, settings, name).RemediateLinux
		i, j := strings.Index(fix, "port 22 "), strings.Index(fix, "ufw default")
		if i < 0 || j < 0 || i > j {
			t.Errorf("%s: SSH is not allowed before the default changes: %s", name, fix)
		}
	}

	off := false
	c := DefaultLinuxFirewall()
	c.AllowSSH, c.Backend = &off, "nftables"
	for _, s := range compileLFW(t, c) {
		if strings.Contains(s.Name, "SSH") || strings.Contains(s.RemediateLinux, "dport 22") {
			t.Errorf("SSH turned off, but %s still allows it", s.Name)
		}
	}
	c = DefaultLinuxFirewall()
	c.SSHPort, c.Backend = 2222, "firewalld"
	ssh = settingNamed(t, compileLFW(t, c), "Linux firewall: SSH")
	if !strings.Contains(ssh.RemediateLinux, "--add-port=2222/tcp") || strings.Contains(ssh.RemediateLinux, "--add-service=ssh") {
		t.Errorf("a custom SSH port is opened as a port: %s", ssh.RemediateLinux)
	}
}

func TestLinuxFirewallRefusesBadInput(t *testing.T) {
	for name, mutate := range map[string]func(*LinuxFirewallConfig){
		"backend":        func(c *LinuxFirewallConfig) { c.Backend = "iptables" },
		"default":        func(c *LinuxFirewallConfig) { c.DefaultInbound = "allow" },
		"ssh port":       func(c *LinuxFirewallConfig) { c.SSHPort = 70000 },
		"protocol":       func(c *LinuxFirewallConfig) { c.Services[0].Protocol = "icmp" },
		"port":           func(c *LinuxFirewallConfig) { c.Services[0].Port = "443; reboot" },
		"backwards":      func(c *LinuxFirewallConfig) { c.Services[0].Port = "9000-8000" },
		"source":         func(c *LinuxFirewallConfig) { c.Services[0].Source = "10.0.0.0/8'; reboot; '" },
		"duplicate":      func(c *LinuxFirewallConfig) { c.Services[1] = c.Services[0] },
		"port too large": func(c *LinuxFirewallConfig) { c.Services[0].Port = "65536" },
	} {
		c := lfwWeb()
		mutate(&c)
		if _, err := Compile(KindLinuxFirewall, mustJSON(t, c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Sources reach the firewall in the form it prints back.
	for in, want := range map[string]string{"10.1.2.3/8": "10.0.0.0/8", "192.0.2.7/32": "192.0.2.7", "2001:DB8::/32": "2001:db8::/32", "any": ""} {
		r, err := parseLinuxService(LinuxFirewallService{Protocol: "tcp", Port: "443", Source: in})
		if err != nil || r.source != want {
			t.Errorf("source %q: got %q, %v; want %q", in, r.source, err, want)
		}
	}
}

// --- running the generated scripts against fixtures ------------------------
//
// The scripts are run for real under /bin/sh, with firewall-cmd, ufw, nft
// and systemctl replaced by stubs that answer the way the real tools do
// (fixtures copied from real hosts' output) and /etc moved into a
// temporary directory. The agent's u: semantics are reproduced: the first
// line decides.

type lfwHost struct {
	t    *testing.T
	root string // stands in for /
	bin  string
}

func newHost(t *testing.T) *lfwHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the generated scripts are POSIX shell")
	}
	h := &lfwHost{t: t, root: t.TempDir()}
	h.bin = filepath.Join(h.root, "bin")
	os.MkdirAll(h.bin, 0o755)
	os.MkdirAll(filepath.Join(h.root, "state"), 0o755)
	// Only the tools the scripts are allowed to rely on, so a firewall
	// installed on the machine running the test cannot leak in.
	for _, tool := range []string{"grep", "tr", "cut", "mkdir", "mv", "cat", "sed", "cp", "rm", "touch"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available", tool)
		}
		os.Symlink(p, filepath.Join(h.bin, tool))
	}
	return h
}

func (h *lfwHost) file(path, content string) {
	h.t.Helper()
	p := filepath.Join(h.root, path)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *lfwHost) stub(name, body string) {
	h.t.Helper()
	body = strings.ReplaceAll(body, "@STATE@", filepath.Join(h.root, "state"))
	body = strings.ReplaceAll(body, "@ROOT@", h.root)
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *lfwHost) run(script string) (string, error) {
	script = strings.Replace(script, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PATH="+h.bin, 1)
	script = strings.ReplaceAll(script, "/etc/", h.root+"/etc/")
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	return string(out), err
}

// check runs a setting's rule and answers ok, drift or unknown with the
// first line, as the agent would.
func (h *lfwHost) check(s proto.EnforceSetting) (string, string) {
	h.t.Helper()
	script := strings.TrimSuffix(strings.TrimPrefix(s.Rules[0], "u:"), " -> r:^ok$")
	out, _ := h.run(script)
	line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	switch {
	case line == "ok":
		return "ok", line
	case strings.HasPrefix(line, "unknown:"):
		return "unknown", line
	}
	return "drift", line
}

func (h *lfwHost) fix(s proto.EnforceSetting) {
	h.t.Helper()
	if out, err := h.run(s.RemediateLinux); err != nil {
		h.t.Fatalf("%s: fix failed: %v\n%s", s.Name, err, out)
	}
}

func systemctlStub(h *lfwHost, enabled string) {
	h.stub("systemctl", `case "$1" in
is-enabled) case " `+enabled+` $(cat @STATE@/enabled 2>/dev/null) " in *" $2 "*) echo enabled; exit 0;; esac; echo disabled; exit 1;;
is-active) exit 3;;
enable|unmask) echo "$*" >> @STATE@/systemctl; if [ "$1" = enable ]; then for a; do :; done; printf '%s ' "$a" >> @STATE@/enabled; fi; case "$*" in *"--now firewalld"*) touch @STATE@/running;; esac;;
esac`)
}

func TestLinuxFirewallNoBackendIsUnknown(t *testing.T) {
	h := newHost(t)
	for _, backend := range []string{"auto", "firewalld", "ufw", "nftables"} {
		c := lfwWeb()
		c.Backend = backend
		for _, s := range compileLFW(t, c) {
			state, line := h.check(s)
			if state != "unknown" {
				t.Errorf("%s / %s on a host with no firewall: %s (%s)", backend, s.Name, state, line)
			}
			if out, err := h.run(s.RemediateLinux); err == nil {
				t.Errorf("%s / %s: the fix claimed success with no firewall: %s", backend, s.Name, out)
			}
		}
	}
}

const ufwStatusActive = `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       10.0.0.0/8                 # mustra
22/tcp (v6)                ALLOW       Anywhere (v6)
`

const ufwUserRules = `*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT -m comment --comment 'dapp_OpenSSH'

### tuple ### allow tcp 443 0.0.0.0/0 any 10.0.0.0/8 in comment=6d7573747261
-A ufw-user-input -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT

### tuple ### allow udp 514 0.0.0.0/0 any 0.0.0.0/0 in_eth1
-A ufw-user-input -i eth1 -p udp --dport 514 -j ACCEPT

### tuple ### allow tcp 8000:8100 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp -m multiport --dports 8000:8100 -j ACCEPT

### END RULES ###
COMMIT
`

const ufwUser6Rules = `*filter
### RULES ###

### tuple ### allow tcp 22 ::/0 any ::/0 OpenSSH - in
-A ufw6-user-input -p tcp --dport 22 -j ACCEPT -m comment --comment 'dapp_OpenSSH'

### tuple ### allow tcp 8000:8100 ::/0 any ::/0 in
-A ufw6-user-input -p tcp -m multiport --dports 8000:8100 -j ACCEPT

### END RULES ###
COMMIT
`

func TestLinuxFirewallUFWFixtures(t *testing.T) {
	h := newHost(t)
	h.file("etc/default/ufw", "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n")
	h.file("etc/ufw/ufw.conf", "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n")
	h.file("etc/ufw/user.rules", ufwUserRules)
	h.file("etc/ufw/user6.rules", ufwUser6Rules)
	h.file("state/status", ufwStatusActive)
	h.stub("ufw", `case "$1" in status) cat @STATE@/status;; *) echo "$*" >> @STATE@/ufw;; esac`)
	systemctlStub(h, "ufw")

	got := map[string]string{}
	for _, s := range compileLFW(t, lfwWeb()) {
		state, line := h.check(s)
		got[s.Name] = state + " " + line
	}
	for name, want := range map[string]string{
		// The OpenSSH app profile counts as SSH.
		"Linux firewall: SSH stays reachable (22/tcp)":                       "ok ok",
		"Linux firewall: allow HTTPS from the LAN (443/tcp from 10.0.0.0/8)": "ok ok",
		// Only on eth1, which is not what the policy asked for.
		"Linux firewall: allow Syslog (514/udp)":                     "drift drift: 514/udp is not allowed in ufw",
		"Linux firewall: allow App range (8000-8100/tcp)":            "ok ok",
		"Linux firewall: inbound default is drop (discard silently)": "ok ok",
		"Linux firewall: active now and enabled at boot":             "ok ok",
	} {
		if got[name] != want {
			t.Errorf("%s: got %q, want %q", name, got[name], want)
		}
	}

	// IPv6 on: a rule missing from user6.rules is drift.
	h.file("etc/ufw/user6.rules", "*filter\nCOMMIT\n")
	if state, line := h.check(settingNamed(t, compileLFW(t, lfwWeb()), "Linux firewall: allow App range")); state != "drift" {
		t.Errorf("missing v6 rule: %s %s", state, line)
	}

	h.file("etc/default/ufw", "IPV6=yes\nDEFAULT_INPUT_POLICY=\"ACCEPT\"\n")
	h.file("etc/ufw/ufw.conf", "ENABLED=no\n")
	h.file("state/status", "Status: inactive\n")
	for prefix, want := range map[string]string{
		"Linux firewall: inbound default": "drift: ufw default incoming policy is ACCEPT",
		"Linux firewall: active":          "drift: ufw is not active",
	} {
		if _, line := h.check(settingNamed(t, compileLFW(t, lfwWeb()), prefix)); line != want {
			t.Errorf("%s: %q, want %q", prefix, line, want)
		}
	}
	h.file("state/status", ufwStatusActive)
	if _, line := h.check(settingNamed(t, compileLFW(t, lfwWeb()), "Linux firewall: active")); !strings.Contains(line, "not enabled at boot") {
		t.Errorf("ENABLED=no: %q", line)
	}

	// Activation adds SSH and the services before enabling.
	h.fix(settingNamed(t, compileLFW(t, lfwWeb()), "Linux firewall: active"))
	calls, _ := os.ReadFile(filepath.Join(h.root, "state/ufw"))
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "allow proto tcp from any to any port 22 ") || lines[len(lines)-1] != "--force enable" {
		t.Errorf("activation order:\n%s", calls)
	}

	// A configuration it cannot read is unknown.
	os.Remove(filepath.Join(h.root, "etc/default/ufw"))
	if state, _ := h.check(settingNamed(t, compileLFW(t, lfwWeb()), "Linux firewall: allow Syslog")); state != "unknown" {
		t.Errorf("unreadable ufw config: %s", state)
	}
}

// firewalldStub keeps the zone's permanent configuration in a state file:
// a query answers yes/no from it, an add appends to it -- the yes/no and
// ALREADY_ENABLED behaviour of the real firewall-cmd.
const firewalldStub = `S=@STATE@
case "$*" in
*--state*) [ -f $S/running ] && { echo running; exit 0; }; echo "not running"; exit 252;;
*--get-default-zone*) [ -f $S/nozone ] && exit 1; echo public;;
*--get-target*) cat $S/target;;
*--query-*) a=$(printf '%s\n' "$*" | sed 's/.*--query-//'); grep -qxF -- "$a" $S/allowed 2>/dev/null && { echo yes; exit 0; }; echo no; exit 1;;
*--add-*) a=$(printf '%s\n' "$*" | sed 's/.*--add-//'); grep -qxF -- "$a" $S/allowed 2>/dev/null && { echo "Warning: ALREADY_ENABLED: $a" >&2; echo success; exit 0; }; printf '%s\n' "$a" >> $S/allowed; echo success;;
*--set-target=*) printf '%s\n' "$*" | sed 's/.*--set-target=//' > $S/target; echo success;;
*--reload*) echo reload >> $S/calls; echo success;;
esac`

func TestLinuxFirewallFirewalldFixtures(t *testing.T) {
	h := newHost(t)
	h.stub("firewall-cmd", firewalldStub)
	h.stub("firewall-offline-cmd", firewalldStub)
	systemctlStub(h, "firewalld")
	h.file("state/running", "")
	h.file("state/target", "default\n")
	h.file("state/allowed", "service=ssh\nport=514/udp\n")

	settings := compileLFW(t, lfwWeb())
	for prefix, want := range map[string]string{
		"Linux firewall: SSH":                    "ok",
		"Linux firewall: allow Syslog":           "ok",
		"Linux firewall: allow HTTPS":            "drift: 443/tcp from 10.0.0.0/8 is not allowed in firewalld zone public",
		"Linux firewall: allow App range":        "drift: 8000-8100/tcp is not allowed in firewalld zone public",
		"Linux firewall: inbound default":        "drift: firewalld zone public has target default",
		"Linux firewall: active now and enabled": "ok",
	} {
		if _, line := h.check(settingNamed(t, settings, prefix)); line != want {
			t.Errorf("%s: %q, want %q", prefix, line, want)
		}
	}

	// Fixing is idempotent and the re-check passes.
	for i := 0; i < 2; i++ {
		for _, s := range settings {
			h.fix(s)
			if state, line := h.check(s); state != "ok" {
				t.Errorf("pass %d, %s after its fix: %s", i, s.Name, line)
			}
		}
	}
	allowed, _ := os.ReadFile(filepath.Join(h.root, "state/allowed"))
	if strings.Count(string(allowed), "port=8000-8100/tcp") != 1 {
		t.Errorf("a repeated fix added the rule twice:\n%s", allowed)
	}

	// A stopped firewalld is read offline; activating it puts the policy
	// in place first and starts it last.
	os.Remove(filepath.Join(h.root, "state/running"))
	h.file("state/allowed", "")
	h.file("state/target", "default\n")
	active := settingNamed(t, settings, "Linux firewall: active")
	if _, line := h.check(active); line != "drift: firewalld is not running" {
		t.Errorf("stopped firewalld: %q", line)
	}
	if state, line := h.check(settingNamed(t, settings, "Linux firewall: SSH")); state != "drift" {
		t.Errorf("stopped firewalld, SSH not in the permanent config: %s %s", state, line)
	}
	h.fix(active)
	for _, s := range settings {
		if state, line := h.check(s); state != "ok" {
			t.Errorf("after activation, %s: %s", s.Name, line)
		}
	}

	// A zone it cannot read is unknown, never drift.
	h.file("state/nozone", "")
	if state, line := h.check(settingNamed(t, settings, "Linux firewall: allow Syslog")); state != "unknown" {
		t.Errorf("unreadable zone: %s %s", state, line)
	}
}

const nftChainFixture = `table inet mustra {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept comment "mustra-established"
		ct state invalid drop
		iif "lo" accept
		meta l4proto { icmp, ipv6-icmp } accept
		ip6 saddr fe80::/10 udp dport 546 accept comment "mustra-dhcpv6-client"
		tcp dport 22 accept comment "mustra-ssh-22"
	}
}
`

// nftStub: "loaded" is the table the kernel holds; nft -f loads a file
// into it and list prints it back.
const nftStub = `S=@STATE@
case "$*" in
"list tables") [ -f $S/broken ] && { echo "Error: cannot open netlink socket" >&2; exit 1; }; echo "table inet filter";;
"list table inet mustra") [ -f $S/loaded ] || { echo "Error: No such file or directory" >&2; exit 1; }; cat $S/loaded;;
"list chain inet mustra input") [ -f $S/loaded ] && cat $S/loaded;;
"-c -f "*) [ -f "$3" ];;
"-f "*) cp "$2" $S/loaded;;
esac`

func TestLinuxFirewallNftablesFixtures(t *testing.T) {
	h := newHost(t)
	h.stub("nft", nftStub)
	systemctlStub(h, "")
	c := lfwWeb()
	c.Backend = "nftables"
	settings := compileLFW(t, c)

	// Not loaded yet: drift, not unknown -- the fix can create it.
	if state, line := h.check(settings[0]); state != "drift" || !strings.Contains(line, "not loaded") {
		t.Errorf("no mustra table: %s %s", state, line)
	}
	h.file("state/loaded", nftChainFixture)
	if state, _ := h.check(settingNamed(t, settings, "Linux firewall: SSH")); state != "ok" {
		t.Errorf("ssh in the fixture: %s", state)
	}
	if _, line := h.check(settingNamed(t, settings, "Linux firewall: allow Syslog")); !strings.HasPrefix(line, "drift: 514/udp") {
		t.Errorf("syslog missing from the fixture: %q", line)
	}
	if state, _ := h.check(settingNamed(t, settings, "Linux firewall: inbound default")); state != "ok" {
		t.Errorf("policy drop in the fixture: %s", state)
	}
	if _, line := h.check(settingNamed(t, settings, "Linux firewall: active")); !strings.Contains(line, "would not survive a reboot") {
		t.Errorf("unpersisted table: %q", line)
	}

	// One fix writes the whole table, persists it, and every setting holds.
	h.file("etc/nftables.conf", "#!/usr/sbin/nft -f\nflush ruleset\n")
	for i := 0; i < 2; i++ {
		h.fix(settingNamed(t, settings, "Linux firewall: allow Syslog"))
	}
	for _, s := range settings {
		if state, line := h.check(s); state != "ok" {
			t.Errorf("after the nftables fix, %s: %s", s.Name, line)
		}
	}
	conf, _ := os.ReadFile(filepath.Join(h.root, "etc/nftables.conf"))
	if strings.Count(string(conf), `/etc/nftables.d/mustra.nft"`) != 1 || !strings.HasPrefix(string(conf), "#!/usr/sbin/nft -f\nflush ruleset\n") {
		t.Errorf("main file:\n%s", conf)
	}
	calls, _ := os.ReadFile(filepath.Join(h.root, "state/systemctl"))
	if strings.TrimSpace(string(calls)) == "" || strings.Contains(string(calls), "--now") {
		t.Errorf("nftables.service must be enabled, never started (it would flush every table): %q", calls)
	}

	// Changing the policy makes the persisted file stale.
	c.DefaultInbound = "deny"
	changed := compileLFW(t, c)
	if _, line := h.check(settingNamed(t, changed, "Linux firewall: inbound default")); !strings.Contains(line, "drops instead of refusing") {
		t.Errorf("deny against a drop table: %q", line)
	}
	if state, _ := h.check(settingNamed(t, changed, "Linux firewall: active")); state != "drift" {
		t.Errorf("a stale persisted file is drift: %s", state)
	}

	h.file("state/broken", "")
	if state, _ := h.check(settings[0]); state != "unknown" {
		t.Errorf("an unreadable ruleset: %s", state)
	}
}

func TestLinuxFirewallAutoPrefersTheRunningFirewall(t *testing.T) {
	h := newHost(t)
	// firewalld installed but stopped, ufw active: ufw is what the host uses.
	h.stub("firewall-cmd", firewalldStub)
	h.stub("ufw", `case "$1" in status) cat @STATE@/status;; esac`)
	h.file("state/status", ufwStatusActive)
	h.file("etc/default/ufw", "IPV6=no\nDEFAULT_INPUT_POLICY=\"DROP\"\n")
	h.file("etc/ufw/user.rules", ufwUserRules)
	systemctlStub(h, "")
	if _, line := h.check(settingNamed(t, compileLFW(t, lfwWeb()), "Linux firewall: allow Syslog")); line != "drift: 514/udp is not allowed in ufw" {
		t.Errorf("auto picked the wrong backend: %q", line)
	}
}
