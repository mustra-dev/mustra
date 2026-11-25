package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// OS provisioning (#95): network boot and reimaging.
//
// A machine that network-boots iPXE asks the boot server for its script by
// MAC address. A MAC the server does not know, or knows but has not been
// told to install, is told to boot its own disk: never an installer. An
// armed machine gets the installer of its image, with a fresh random answer
// token in the URLs of its answer file. The answer file is rendered per
// machine from the image's template, carries a short-lived single-use
// enrollment token, and can be fetched once: fetching it clears the
// machine's "install next boot" flag.
//
// The boot endpoints cannot authenticate the machine — firmware has no
// credential to present — so what they serve without a token is limited to
// what is not secret: boot scripts and boot files (kernels, initrds, WinPE).
// Everything that is (answer files with their enrollment tokens and
// passwords, the Windows share's credentials) is behind the per-install
// token. The feature is off until an administrator turns it on, and can be
// confined to source networks and to a listener of its own.

const (
	settingProvisioning = "provisioning.config"

	provisioningAnswerTokenPrefix = "mpa_"
	provisioningStatusTokenPrefix = "mps_"

	defaultAnswerTTLMinutes = 60
	defaultArmHours         = 24
	defaultEnrollTTLHours   = 6
	// An installer's callbacks are accepted this long after its script was
	// served: a Windows install with updates takes hours, not days.
	provisioningStatusWindow = 24 * time.Hour

	maxAnswerTemplateBytes = 64 << 10
)

var provisioningFamilies = []string{"ubuntu", "debian", "windows"}

// provisioningAssetRoles are the boot files each family needs, in the
// order the iPXE script loads them.
var provisioningAssetRoles = map[string][]string{
	"ubuntu":  {"kernel", "initrd"},
	"debian":  {"kernel", "initrd"},
	"windows": {"wimboot", "bcd", "boot.sdi", "boot.wim"},
}

func validFamily(f string) bool {
	for _, v := range provisioningFamilies {
		if v == f {
			return true
		}
	}
	return false
}

// provisioningConfig is the feature's server-wide settings.
type provisioningConfig struct {
	// Enabled turns the boot endpoints on. Off, every /boot/ path answers
	// 404 and nothing can be armed.
	Enabled bool `json:"enabled"`
	// BootURL is the address machines reach the boot endpoints at, written
	// into every boot script, e.g. http://10.0.0.5:8069. Plain HTTP is
	// allowed: iPXE's TLS does not know a private CA.
	BootURL string `json:"boot_url"`
	// AllowedNetworks, when set, are the only source networks (CIDR) the
	// boot endpoints answer.
	AllowedNetworks []string `json:"allowed_networks"`
	// AnswerTTLMinutes is how long after its boot script an answer file
	// may be fetched.
	AnswerTTLMinutes int `json:"answer_ttl_minutes"`
	// ArmHours is how long "install next boot" stays set without a boot.
	ArmHours int `json:"arm_hours"`
	// EnrollTTLHours is the life of the enrollment token in an answer file,
	// counted from the fetch: the install, then the first boot, must fit.
	EnrollTTLHours int `json:"enroll_ttl_hours"`
	// Site is the site newly installed endpoints enroll into.
	Site string `json:"site"`
}

func (c *provisioningConfig) applyDefaults() {
	if c.AnswerTTLMinutes <= 0 {
		c.AnswerTTLMinutes = defaultAnswerTTLMinutes
	}
	if c.ArmHours <= 0 {
		c.ArmHours = defaultArmHours
	}
	if c.EnrollTTLHours <= 0 {
		c.EnrollTTLHours = defaultEnrollTTLHours
	}
	if c.AllowedNetworks == nil {
		c.AllowedNetworks = []string{}
	}
}

func (c provisioningConfig) validate() error {
	if c.BootURL != "" {
		if _, err := normalizeBootURL(c.BootURL); err != nil {
			return err
		}
	}
	if c.Enabled && c.BootURL == "" {
		return errors.New("set the boot URL machines reach this server at before turning provisioning on")
	}
	for _, n := range c.AllowedNetworks {
		if _, _, err := net.ParseCIDR(n); err != nil {
			return fmt.Errorf("allowed network %q is not a CIDR such as 10.0.0.0/24", n)
		}
	}
	if c.AnswerTTLMinutes < 5 || c.AnswerTTLMinutes > 24*60 {
		return errors.New("the answer file lifetime must be between 5 minutes and 24 hours")
	}
	if c.ArmHours < 1 || c.ArmHours > 24*14 {
		return errors.New("\"install next boot\" may stay set between 1 hour and 14 days")
	}
	if c.EnrollTTLHours < 1 || c.EnrollTTLHours > 72 {
		return errors.New("the enrollment token lifetime must be between 1 and 72 hours")
	}
	if c.Site != "" && !validSite(c.Site) {
		return errors.New("site may contain only letters, digits, '-' and '_' (at most 64)")
	}
	return nil
}

func (s *Server) provisioningConfig(ctx context.Context) (provisioningConfig, error) {
	var c provisioningConfig
	if s.store == nil {
		c.applyDefaults()
		return c, nil
	}
	raw, err := s.store.GetSetting(ctx, settingProvisioning)
	if err != nil {
		return c, err
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return c, fmt.Errorf("provisioning settings are unreadable: %w", err)
		}
	}
	c.applyDefaults()
	return c, nil
}

// --- validation ------------------------------------------------------------

// bootURLChars is what the boot URL may contain. It lands in iPXE scripts,
// kernel command lines and answer files, so it is held to a charset none of
// them treat specially: no whitespace, quotes, '$' (iPXE settings), '\'
// or ';' (cloud-init's nocloud separator).
var bootURLChars = regexp.MustCompile(`^https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/\-]*)?$`)

func normalizeBootURL(raw string) (string, error) {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	if !bootURLChars.MatchString(u) {
		return "", errors.New("the boot URL must be http(s)://host[:port][/path] with no query, e.g. http://10.0.0.5:8069")
	}
	return u, nil
}

// assetURLChars is what an operator-given boot file URL may contain: a
// URL's characters less those iPXE or a kernel command line would read
// (whitespace, quotes, '$', '\', '#').
var assetURLChars = regexp.MustCompile(`^https?://[A-Za-z0-9._~:/?\[\]@!&()*+,;=%\-]+$`)

func validAssetURL(u string) bool {
	if !assetURLChars.MatchString(u) {
		return false
	}
	p, err := url.Parse(u)
	return err == nil && p.Host != ""
}

// kernelArgPattern is one extra kernel argument. Kernel arguments are
// written into the iPXE script, so they get the same treatment as URLs.
var kernelArgPattern = regexp.MustCompile(`^[A-Za-z0-9._:/=,+@%~\-]+$`)

func validKernelArgs(args string) error {
	if len(args) > 1024 {
		return errors.New("kernel arguments are too long")
	}
	for _, a := range strings.Fields(args) {
		if !kernelArgPattern.MatchString(a) {
			return fmt.Errorf("kernel argument %q has a character the boot script cannot carry", a)
		}
	}
	return nil
}

// normalizeMAC accepts aa:bb:.., aa-bb-.. and aabb.. and returns the lower
// case, colon-separated form, or "" when s is not a 48-bit MAC.
func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(s) != 12 {
		return ""
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

// provisioningVariables are the answer variables a machine or an image may
// set, each with the pattern its value must match. Values reach answer
// files and, for some, kernel command lines and iPXE scripts, so each is
// held to the narrowest charset its meaning allows; the templates escape
// them for their format on top of that.
var provisioningVariables = map[string]*regexp.Regexp{
	"hostname":    regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`),
	"locale":      regexp.MustCompile(`^[A-Za-z]{2,3}([_-][A-Za-z]{2,4})?(\.[A-Za-z0-9-]{1,16})?$`),
	"keyboard":    regexp.MustCompile(`^[A-Za-z0-9_:-]{1,40}$`),
	"timezone":    regexp.MustCompile(`^[A-Za-z0-9_+./ -]{1,64}$`),
	"disk":        regexp.MustCompile(`^(/dev/[A-Za-z0-9/_.-]{1,64}|[0-9]{1,2})$`),
	"admin_user":  regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`),
	"ssh_key":     regexp.MustCompile(`^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-[a-z0-9@.-]{1,64}) [A-Za-z0-9+/=]{16,1000}( [A-Za-z0-9@._:+-]{0,128})?$`),
	"image_index": regexp.MustCompile(`^[0-9]{1,2}$`),
	"product_key": regexp.MustCompile(`^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$`),
}

// variableNames lists the variables in a stable order, for messages.
func variableNames() []string {
	out := make([]string, 0, len(provisioningVariables))
	for k := range provisioningVariables {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateVariables refuses an unknown variable or a value outside its
// pattern, and drops empty ones.
func validateVariables(vars map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range vars {
		v = strings.TrimSpace(v)
		re, ok := provisioningVariables[k]
		if !ok {
			return nil, fmt.Errorf("unknown variable %q (known: %s)", k, strings.Join(variableNames(), ", "))
		}
		if v == "" {
			continue
		}
		if !re.MatchString(v) || strings.Contains(v, "..") {
			return nil, fmt.Errorf("variable %s: %q is not a valid value", k, v)
		}
		out[k] = v
	}
	return out, nil
}

// validAdminPassword keeps a password that has to survive an XML answer
// file and a crypt hash to printable characters on one line.
func validAdminPassword(p string) error {
	if len(p) < 8 || len(p) > 127 {
		return errors.New("the administrator password must be 8 to 127 characters")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return errors.New("the administrator password may not contain control characters")
		}
	}
	return nil
}

// windowsShare is a UNC path WinPE maps with `net use`.
var windowsShare = regexp.MustCompile(`^\\\\[A-Za-z0-9._-]{1,253}(\\[A-Za-z0-9 ._$-]{1,80}){1,8}$`)

// windowsShareUser is a share account, plain or DOMAIN\user or user@domain.
var windowsShareUser = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}(\\[A-Za-z0-9._-]{1,64})?$`)

// cmdUnsafe are the characters cmd.exe would interpret even inside double
// quotes (or that end the quoting). A share password containing one is
// refused rather than escaped: cmd's escaping rules differ between a
// command line and a batch file and are easy to get wrong.
const cmdUnsafe = "\"%^&|<>!\r\n"

func validShareSecret(p string) error {
	if len(p) > 127 {
		return errors.New("the share password is too long")
	}
	if strings.ContainsAny(p, cmdUnsafe) {
		return errors.New(`the share password may not contain " % ^ & | < > ! or line breaks: WinPE's install script could not pass it safely`)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return errors.New("the share password may not contain control characters")
		}
	}
	return nil
}

// validateImage checks an image for the family it says it is.
func validateImage(im *store.ProvisioningImage) error {
	im.Name = strings.TrimSpace(im.Name)
	if im.Name == "" || len(im.Name) > 120 {
		return errors.New("an image needs a name of at most 120 characters")
	}
	if !validFamily(im.Family) {
		return errors.New("family must be ubuntu, debian or windows")
	}
	roles := provisioningAssetRoles[im.Family]
	for role := range im.Assets {
		if !containsString(roles, role) {
			return fmt.Errorf("%s images have no %q boot file (they use %s)", im.Family, role, strings.Join(roles, ", "))
		}
	}
	for role, a := range im.Assets {
		if a.URL != "" && !validAssetURL(a.URL) {
			return fmt.Errorf("the %s URL must be http(s) with no spaces, quotes, '$', '\\' or '#'", role)
		}
	}
	if err := validKernelArgs(im.KernelArgs); err != nil {
		return err
	}
	im.InstallSource = strings.TrimSpace(im.InstallSource)
	switch im.Family {
	case "ubuntu", "debian":
		if im.InstallSource != "" && !validAssetURL(im.InstallSource) {
			return errors.New("the install source must be an http(s) URL (Ubuntu: the live-server ISO; Debian: a mirror)")
		}
		if im.Family == "ubuntu" && im.InstallSource == "" {
			return errors.New("an Ubuntu image needs the URL of its live-server ISO as the install source")
		}
		if im.SourceUser != "" {
			return errors.New("share credentials apply to Windows images only")
		}
	case "windows":
		if !windowsShare.MatchString(im.InstallSource) {
			return errors.New(`a Windows image needs the share holding the installation media as its install source, e.g. \\fileserver\win11`)
		}
		if im.SourceUser != "" && !windowsShareUser.MatchString(im.SourceUser) {
			return errors.New("the share user may be user, DOMAIN\\user or user@domain")
		}
	}
	defaults, err := validateVariables(im.Defaults)
	if err != nil {
		return fmt.Errorf("defaults: %w", err)
	}
	im.Defaults = defaults
	if len(im.AnswerTemplate) > maxAnswerTemplateBytes {
		return errors.New("the answer template is larger than 64 KB")
	}
	if strings.TrimSpace(im.AnswerTemplate) != "" {
		if err := checkAnswerTemplate(im.Family, im.AnswerTemplate); err != nil {
			return err
		}
	}
	return nil
}

// imageReady says what an image still lacks before a machine can boot it,
// or "" when nothing.
func imageReady(im *store.ProvisioningImage) string {
	var missing []string
	for _, role := range provisioningAssetRoles[im.Family] {
		a := im.Assets[role]
		if a.URL == "" && a.FileID == "" {
			missing = append(missing, role)
		}
	}
	if len(missing) > 0 {
		return "boot files missing: " + strings.Join(missing, ", ")
	}
	return ""
}

// --- tokens ----------------------------------------------------------------

func newProvisioningToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

var provisioningTokenPattern = regexp.MustCompile(`^mp[as]_[A-Za-z0-9_-]{43}$`)

// statusTokenFor derives an install's status token from its answer token.
// The database keeps only hashes of both, and the answer file is the one
// place an installer can learn the status token: deriving it lets the
// answer file carry it without the server keeping a plain copy anywhere.
// Knowing a status token does not reveal the answer token.
func statusTokenFor(answerToken string) string {
	mac := hmac.New(sha256.New, []byte(answerToken))
	mac.Write([]byte("mustra provisioning status token"))
	return provisioningStatusTokenPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// --- answer templates --------------------------------------------------------

// answerData is what an answer template sees. Every string in it has been
// validated against its variable's pattern or built by the server; the
// template functions escape it for the file's format on top of that.
type answerData struct {
	Hostname, Locale, LocaleTag, Keyboard, Timezone, Disk string
	AdminUser, AdminPassword, AdminPasswordHash           string
	SSHKey, ImageIndex, ProductKey                        string
	InstallSource, SourceUser, SourcePassword             string
	MirrorHost, MirrorPath                                string
	// StatusURL takes POSTs of status=installing|installed|failed.
	StatusURL string
	// EnrollUnix and EnrollWindows are the commands that enroll the
	// installed system's mustra agent; FirstbootScript runs EnrollUnix
	// with retries until the network is up.
	EnrollUnix, EnrollWindows, FirstbootScript string
	InstallID                                  string
}

// sampleAnswerData is what a template is test-rendered with when it is
// saved, so a broken one is refused then rather than at somebody's boot.
func sampleAnswerData() answerData {
	return answerData{
		Hostname: "sample", Locale: "en_US.UTF-8", LocaleTag: "en-US", Keyboard: "us", Timezone: "Etc/UTC",
		Disk: "/dev/sda", AdminUser: "localadmin", AdminPassword: "sample-password",
		AdminPasswordHash: "$6$sample$sample", SSHKey: "", ImageIndex: "1",
		InstallSource: "http://deb.debian.org/debian", MirrorHost: "deb.debian.org", MirrorPath: "/debian",
		StatusURL: "http://boot.example/boot/status/token", EnrollUnix: "true", EnrollWindows: "exit 0",
		FirstbootScript: "#!/bin/sh\ntrue\n", InstallID: "pin-sample",
	}
}

var errTemplateValue = errors.New("value cannot be written safely into this answer file")

// answerFuncs are the escapers answer templates use. Each either produces
// a value that the format reads as exactly that data, or fails the render:
// an answer file is never produced with a value that could change its
// meaning.
var answerFuncs = template.FuncMap{
	// yaml writes a YAML double-quoted scalar (JSON is a subset of YAML).
	"yaml": func(v string) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	// xml escapes element text and attribute values.
	"xml": func(v string) (string, error) {
		var b bytes.Buffer
		if err := xml.EscapeText(&b, []byte(v)); err != nil {
			return "", err
		}
		return b.String(), nil
	},
	// sh single-quotes for a POSIX shell.
	"sh": func(v string) string { return shQuote(v) },
	// line is a value for a line-based format (preseed): one line, no
	// control characters.
	"line": func(v string) (string, error) {
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return "", errTemplateValue
			}
		}
		return v, nil
	},
	// cmd is a value for a double-quoted argument in a Windows batch file.
	"cmd": func(v string) (string, error) {
		if strings.ContainsAny(v, cmdUnsafe) {
			return "", errTemplateValue
		}
		return `"` + v + `"`, nil
	},
	// b64 is standard base64, for content a shell decodes itself.
	"b64": func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) },
}

func parseAnswerTemplate(name, text string) (*template.Template, error) {
	return template.New(name).Funcs(answerFuncs).Option("missingkey=error").Parse(text)
}

// checkAnswerTemplate parses and test-renders a template.
func checkAnswerTemplate(family, text string) error {
	t, err := parseAnswerTemplate(family, text)
	if err != nil {
		return fmt.Errorf("the answer template does not parse: %w", err)
	}
	if err := t.Execute(&bytes.Buffer{}, sampleAnswerData()); err != nil {
		return fmt.Errorf("the answer template does not render: %w", err)
	}
	return nil
}

// renderAnswer renders the image's template (or its family's built-in one).
func renderAnswer(im *store.ProvisioningImage, d answerData) ([]byte, error) {
	text := im.AnswerTemplate
	if strings.TrimSpace(text) == "" {
		text = defaultAnswerTemplates[im.Family]
	}
	t, err := parseAnswerTemplate(im.Family, text)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, d); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// answerFileName is the file an installer's answer is fetched as.
var answerFileName = map[string]string{"ubuntu": "user-data", "debian": "preseed.cfg", "windows": "unattend.xml"}

// localeTag turns en_US.UTF-8 into en-US for Windows.
func localeTag(locale string) string {
	l, _, _ := strings.Cut(locale, ".")
	return strings.ReplaceAll(l, "_", "-")
}

// posixLocale turns en-US into en_US.UTF-8 for Linux, leaving a locale
// that already names its encoding alone.
func posixLocale(locale string) string {
	if strings.Contains(locale, ".") {
		return locale
	}
	return strings.ReplaceAll(locale, "-", "_") + ".UTF-8"
}

// mergedVariables is the image's defaults overlaid by the machine's own.
func mergedVariables(im *store.ProvisioningImage, m *store.ProvisioningMachine) map[string]string {
	out := map[string]string{}
	for k, v := range im.Defaults {
		out[k] = v
	}
	for k, v := range m.Variables {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// hostnameFor picks the installed system's hostname: the machine's
// variable, else its name if that is a valid hostname, else one made from
// its MAC.
func hostnameFor(vars map[string]string, m *store.ProvisioningMachine) string {
	if h := vars["hostname"]; h != "" {
		return h
	}
	if provisioningVariables["hostname"].MatchString(m.Name) {
		return m.Name
	}
	return "host-" + strings.ReplaceAll(m.MAC, ":", "")
}

// firstbootScript retries the enrollment command until the network and
// the console are reachable, for at most about ten minutes.
func firstbootScript(enroll string) string {
	return "#!/bin/sh\n" +
		"# Enrolls this machine's mustra agent at first boot; written by the installer from mustra's answer file.\n" +
		"i=0\n" +
		"until " + enroll + "; do\n" +
		"  i=$((i+1)); [ \"$i\" -ge 30 ] && exit 1\n" +
		"  sleep 20\n" +
		"done\n"
}

// enrollCommands are the plain install one-liners for a freshly minted
// token, run as root (Linux) or SYSTEM/administrator (Windows) at the
// installed system's first boot.
func enrollCommands(base, token, site string) (unix, windows string) {
	q := ""
	if site != "" {
		q = "?site=" + site
	}
	auth := "Authorization: Bearer " + token
	unix = "curl -fsSL -H " + shQuote(auth) + " " + shQuote(base+"/install.sh"+q) + " | bash"
	windows = "irm -UseBasicParsing -Headers @{Authorization=" + psQuoteString("Bearer "+token) + "} " +
		psQuoteString(base+"/install.ps1"+q) + " | iex"
	return unix, windows
}

// --- iPXE scripts ------------------------------------------------------------

// ipxeLocalBoot is the script for any machine that is not to install: no
// menu and no prompt, straight back to the firmware's next boot device.
const ipxeLocalBoot = "#!ipxe\n" +
	"echo mustra: no installation is assigned to this machine, booting from the local disk\n" +
	"exit\n"

// ipxeChainScript re-asks for the boot script with the MAC of the
// interface iPXE booted from; iPXE expands ${netX/mac} itself.
func ipxeChainScript(bootURL string) string {
	base, err := normalizeBootURL(bootURL)
	if err != nil {
		return ipxeLocalBoot
	}
	return "#!ipxe\nchain " + base + "/boot/ipxe?mac=${netX/mac} || exit\n"
}

// ipxeSafe reports whether s can be written into an iPXE script as one
// argument: iPXE expands ${...} and splits on whitespace.
func ipxeSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("$\"'\\#", r) {
			return false
		}
	}
	return true
}

// ipxeBoot is what an armed machine's script needs.
type ipxeBoot struct {
	Family     string
	Assets     map[string]string // role -> URL the machine fetches
	AnswerBase string            // bootURL/boot/answer/<token>
	Source     string            // Ubuntu ISO URL, Debian mirror
	KernelArgs string
	Hostname   string
	Locale     string
	Keyboard   string
}

// ipxeScript renders an installer's boot script. Every value is checked
// with ipxeSafe; a script that cannot be written safely is an error, and
// the caller then sends the local-boot script instead.
func ipxeScript(b ipxeBoot) (string, error) {
	args := strings.Fields(b.KernelArgs)
	var lines []string
	add := func(parts ...string) error {
		for _, p := range parts {
			if !ipxeSafe(p) {
				return fmt.Errorf("value %q cannot be written into a boot script", p)
			}
		}
		lines = append(lines, strings.Join(parts, " "))
		return nil
	}
	asset := func(role string) string { return b.Assets[role] }
	var err error
	switch b.Family {
	case "ubuntu":
		k := []string{"kernel", asset("kernel"), "initrd=initrd", "ip=dhcp", "url=" + b.Source, "autoinstall",
			"ds=nocloud-net;s=" + b.AnswerBase + "/", "cloud-config-url=/dev/null"}
		k = append(k, args...)
		if err = add(k...); err == nil {
			err = add("initrd", "--name", "initrd", asset("initrd"))
		}
	case "debian":
		k := []string{"kernel", asset("kernel"), "initrd=initrd.gz", "auto=true", "priority=critical",
			"url=" + b.AnswerBase + "/preseed.cfg", "netcfg/get_hostname=" + b.Hostname,
			"debian-installer/locale=" + posixLocale(b.Locale), "keyboard-configuration/xkb-keymap=" + b.Keyboard}
		k = append(k, args...)
		if err = add(k...); err == nil {
			err = add("initrd", "--name", "initrd.gz", asset("initrd"))
		}
	case "windows":
		// wimboot injects every file that is not a boot file into
		// X:\Windows\System32. The answer file is loaded last of the
		// token's files, because loading it uses the token up.
		steps := [][]string{
			append([]string{"kernel", asset("wimboot")}, args...),
			{"initrd", "--name", "BCD", asset("bcd")},
			{"initrd", "--name", "boot.sdi", asset("boot.sdi")},
			{"initrd", "--name", "winpeshl.ini", b.AnswerBase + "/winpeshl.ini"},
			{"initrd", "--name", "mustra-install.cmd", b.AnswerBase + "/mustra-install.cmd"},
			{"initrd", "--name", "unattend.xml", b.AnswerBase + "/unattend.xml"},
			{"initrd", "--name", "boot.wim", asset("boot.wim")},
		}
		for _, st := range steps {
			if err = add(st...); err != nil {
				break
			}
		}
	default:
		err = fmt.Errorf("unknown family %q", b.Family)
	}
	if err != nil {
		return "", err
	}
	return "#!ipxe\n" +
		"echo mustra: installing on this machine\n" +
		strings.Join(lines, "\n") + "\nboot\n", nil
}

// windowsLauncher is WinPE's winpeshl.ini: run the install script instead
// of a command prompt.
const windowsLauncher = "[LaunchApps]\r\n%SYSTEMROOT%\\System32\\cmd.exe, /c %SYSTEMROOT%\\System32\\mustra-install.cmd\r\n"

// windowsInstallScript maps the installation share and starts Setup with
// the answer file wimboot placed next to it. Every value is validated
// against cmdUnsafe (validateImage, validShareSecret) and quoted.
func windowsInstallScript(share, user, password, statusURL string) (string, error) {
	q := answerFuncs["cmd"].(func(string) (string, error))
	shareQ, err := q(share)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("rem mustra: WinPE install script, served once per install.\r\n")
	b.WriteString("wpeinit\r\n")
	b.WriteString("wpeutil WaitForNetwork\r\n")
	b.WriteString("set tries=0\r\n")
	b.WriteString(":map\r\n")
	if user != "" {
		userQ, err := q(user)
		if err != nil {
			return "", err
		}
		pwQ, err := q(password)
		if err != nil {
			return "", err
		}
		b.WriteString("net use Z: " + shareQ + " /user:" + userQ + " " + pwQ + " >nul\r\n")
	} else {
		b.WriteString("net use Z: " + shareQ + " >nul\r\n")
	}
	b.WriteString("if errorlevel 1 (\r\n  set /a tries+=1\r\n  if %tries% GEQ 10 goto failed\r\n  ping -n 6 127.0.0.1 >nul\r\n  goto map\r\n)\r\n")
	b.WriteString("Z:\\setup.exe /unattend:X:\\Windows\\System32\\unattend.xml\r\n")
	b.WriteString("exit /b 0\r\n")
	b.WriteString(":failed\r\n")
	b.WriteString("echo mustra: could not map the installation share " + share + "\r\n")
	b.WriteString("cmd.exe\r\n")
	_ = statusURL // WinPE has no HTTP client to report with; the installed system reports instead.
	return b.String(), nil
}

// mirrorParts splits a Debian mirror URL into the host (with port) and
// path preseed asks for separately.
func mirrorParts(source string) (host, path string) {
	if source == "" {
		return "deb.debian.org", "/debian"
	}
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return "deb.debian.org", "/debian"
	}
	path = u.Path
	if path == "" {
		path = "/"
	}
	return u.Host, path
}

// sealProvisioningSecret seals a secret for one row and field.
func (s *Server) sealProvisioningSecret(plain, kind, id string) ([]byte, error) {
	if plain == "" {
		return nil, nil
	}
	if s.vault == nil {
		return nil, errors.New("the credential vault is not available")
	}
	return s.vault.Seal(plain, provisioningAAD(kind, id))
}

func (s *Server) openProvisioningSecret(sealed []byte, kind, id string) (string, error) {
	if len(sealed) == 0 {
		return "", nil
	}
	if s.vault == nil {
		return "", errors.New("the credential vault is not available")
	}
	plain, _, err := s.vault.Open(sealed, provisioningAAD(kind, id))
	return plain, err
}

// provisioningAAD binds a sealed secret to its row, so one cannot be
// copied onto another.
func provisioningAAD(kind, id string) string {
	return "provisioning/" + kind + "/" + id
}
