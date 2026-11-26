package server

import (
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"52:54:00:AA:bb:cc": "52:54:00:aa:bb:cc", "52-54-00-aa-bb-cc": "52:54:00:aa:bb:cc",
		"525400aabbcc": "52:54:00:aa:bb:cc", " 5254.00aa.bbcc ": "52:54:00:aa:bb:cc",
		"": "", "52:54:00:aa:bb": "", "52:54:00:aa:bb:zz": "", "${net0/mac}": "", "52:54:00:aa:bb:cc\nkernel": "",
	} {
		if got := normalizeMAC(in); got != want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

// Variables reach answer files, kernel command lines and iPXE scripts, so
// anything outside each one's narrow pattern is refused up front.
func TestValidateVariablesRefusesInjection(t *testing.T) {
	bad := map[string]string{
		"hostname":    "web-01\nkernel http://evil/vmlinuz",
		"locale":      "en_US.UTF-8 ${net0/ip}",
		"keyboard":    "us\"",
		"timezone":    "UTC\r\nd-i preseed/late_command string rm -rf /",
		"disk":        "/dev/../etc/shadow",
		"admin_user":  "root; reboot",
		"ssh_key":     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOfakefakefake\nssh-rsa AAAA evil",
		"image_index": "1</Value>",
		"product_key": "x",
	}
	for k, v := range bad {
		if _, err := validateVariables(map[string]string{k: v}); err == nil {
			t.Errorf("%s=%q was accepted", k, v)
		}
	}
	if _, err := validateVariables(map[string]string{"bootloader": "x"}); err == nil {
		t.Error("an unknown variable was accepted")
	}
	good := map[string]string{"hostname": "lab-07", "locale": "en_US.UTF-8", "keyboard": "us", "timezone": "W. Europe Standard Time",
		"disk": "/dev/nvme0n1", "admin_user": "localadmin", "image_index": "6", "product_key": "VK7JG-NPHTM-C97JM-9MPGT-3V66T",
		"ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqmXc7bS1nJ7aN7rL0Q5r3S4V6y7z8x9w0v1u2t3s4r ops@example"}
	out, err := validateVariables(good)
	if err != nil {
		t.Fatalf("valid variables refused: %v", err)
	}
	if len(out) != len(good) {
		t.Fatalf("lost variables: %v", out)
	}
}

func TestIPXEScriptRefusesUnsafeValues(t *testing.T) {
	ok := ipxeBoot{Family: "ubuntu", Assets: map[string]string{"kernel": "http://m.example/casper/vmlinuz", "initrd": "http://m.example/casper/initrd"},
		AnswerBase: "http://10.0.0.5:8069/boot/answer/mpa_tok", Source: "http://m.example/u.iso", KernelArgs: "console=ttyS0"}
	script, err := ipxeScript(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#!ipxe\n", "kernel http://m.example/casper/vmlinuz initrd=initrd ip=dhcp url=http://m.example/u.iso autoinstall ds=nocloud-net;s=http://10.0.0.5:8069/boot/answer/mpa_tok/ cloud-config-url=/dev/null console=ttyS0\n",
		"initrd --name initrd http://m.example/casper/initrd\n", "boot\n"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	for name, mutate := range map[string]func(*ipxeBoot){
		"settings expansion in an argument": func(b *ipxeBoot) { b.KernelArgs = "x=${net0/ip}" },
		"newline in a URL":                  func(b *ipxeBoot) { b.Assets["kernel"] = "http://m.example/k\nchain http://evil/" },
		"space in a URL":                    func(b *ipxeBoot) { b.Source = "http://m.example/u.iso kernel=x" },
		"quote in a URL":                    func(b *ipxeBoot) { b.Assets["initrd"] = `http://m.example/"x` },
		"missing boot file":                 func(b *ipxeBoot) { delete(b.Assets, "initrd") },
	} {
		b := ok
		b.Assets = map[string]string{"kernel": ok.Assets["kernel"], "initrd": ok.Assets["initrd"]}
		mutate(&b)
		if s, err := ipxeScript(b); err == nil {
			t.Errorf("%s: a script was produced:\n%s", name, s)
		}
	}
	// The Debian line carries machine variables on the kernel command line.
	deb := ipxeBoot{Family: "debian", Assets: map[string]string{"kernel": "http://d.example/linux", "initrd": "http://d.example/initrd.gz"},
		AnswerBase: "http://b.example/boot/answer/mpa_t", Hostname: "lab 07", Locale: "en_US", Keyboard: "us"}
	if _, err := ipxeScript(deb); err == nil {
		t.Error("a hostname with a space reached the Debian kernel command line")
	}
	// Windows loads the answer file after the files that do not use the
	// token up.
	win := ipxeBoot{Family: "windows", Assets: map[string]string{"wimboot": "http://w/wimboot", "bcd": "http://w/BCD", "boot.sdi": "http://w/boot.sdi", "boot.wim": "http://w/boot.wim"},
		AnswerBase: "http://b.example/boot/answer/mpa_t"}
	ws, err := ipxeScript(win)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(ws, "mustra-install.cmd") > strings.Index(ws, "unattend.xml") {
		t.Errorf("the install script must be fetched before the answer file uses the token up:\n%s", ws)
	}
}

// A machine that is not to install is sent to its disk with no menu and no
// way to pick an installer.
func TestLocalBootScriptHasNoInstaller(t *testing.T) {
	for _, w := range []string{"kernel", "chain", "initrd", "menu", "boot\n", "sanboot"} {
		if strings.Contains(ipxeLocalBoot, w) {
			t.Errorf("the local-boot script contains %q", w)
		}
	}
	if !strings.HasPrefix(ipxeLocalBoot, "#!ipxe\n") || !strings.HasSuffix(ipxeLocalBoot, "exit\n") {
		t.Errorf("unexpected local-boot script %q", ipxeLocalBoot)
	}
}

// The escapers keep a value data in every format, even one that got past
// validation (a password, which is free text).
func TestDefaultTemplatesEscapeValues(t *testing.T) {
	hostile := `p"a'ss</Value><x>&amp;$(reboot)` + "`id`"
	d := sampleAnswerData()
	d.AdminPassword = hostile
	d.AdminPasswordHash = sha512Crypt(hostile, "saltsalt")
	d.SSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqmXc7bS1nJ7aN7rL0Q5r3S4V6y7z8x9w0v1u2t3s4r ops@example"
	d.EnrollWindows = "irm -Headers @{Authorization='Bearer mte_x'} 'https://c.example/install.ps1' | iex"

	win, err := renderAnswer(&store.ProvisioningImage{Family: "windows"}, d)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Settings []struct {
			Components []struct {
				UserAccounts struct {
					Accounts []struct {
						Password struct {
							Value string `xml:"Value"`
						} `xml:"Password"`
					} `xml:"LocalAccounts>LocalAccount"`
				} `xml:"UserAccounts"`
			} `xml:"component"`
		} `xml:"settings"`
	}
	if err := xml.Unmarshal(win, &doc); err != nil {
		t.Fatalf("the Windows answer file is not XML: %v\n%s", err, win)
	}
	found := false
	for _, st := range doc.Settings {
		for _, c := range st.Components {
			for _, a := range c.UserAccounts.Accounts {
				if a.Password.Value == hostile {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("the password did not round-trip through the XML:\n%s", win)
	}
	if strings.Contains(string(win), "Bearer mte_x") {
		t.Error("the enrollment command must travel encoded, not as XML text cmd would parse")
	}

	ub, err := renderAnswer(&store.ProvisioningImage{Family: "ubuntu"}, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(ub), "\n") {
		if strings.Contains(line, "password:") && !strings.Contains(line, `password: "$6$saltsalt$`) {
			t.Errorf("the password hash is not a quoted YAML scalar: %q", line)
		}
	}

	deb, err := renderAnswer(&store.ProvisioningImage{Family: "debian"}, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(deb), "d-i passwd/user-password-crypted password $6$saltsalt$") {
		t.Errorf("the preseed has no crypted password:\n%s", deb)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(deb)), "\n") {
		if !strings.HasPrefix(line, "d-i ") && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "tasksel ") && !strings.HasPrefix(line, "popularity-contest ") {
			t.Errorf("a preseed line does not start a question: %q", line)
		}
	}

	// A line-based value with a line break fails the render rather than
	// adding a preseed question.
	d.Timezone = "UTC\nd-i preseed/late_command string reboot"
	if _, err := renderAnswer(&store.ProvisioningImage{Family: "debian"}, d); err == nil {
		t.Error("a line break was written into the preseed")
	}
	// And cmd refuses what cmd.exe would interpret.
	if _, err := windowsInstallScript(`\\files\win11`, "installer", "pa%PATH%ss", ""); err == nil {
		t.Error("a share password with % reached the WinPE script")
	}
	if s, err := windowsInstallScript(`\\files\win11`, `CORP\installer`, "pa ss$word", ""); err != nil || !strings.Contains(s, `net use Z: "\\files\win11" /user:"CORP\installer" "pa ss$word"`) {
		t.Errorf("the WinPE script did not quote the share: %v\n%s", err, s)
	}
}

func TestCheckAnswerTemplate(t *testing.T) {
	for fam, tmpl := range defaultAnswerTemplates {
		if err := checkAnswerTemplate(fam, tmpl); err != nil {
			t.Errorf("the built-in %s template does not check: %v", fam, err)
		}
	}
	for _, bad := range []string{"{{.Hostname", "{{.NoSuchField}}", "{{yaml .Hostname .Locale}}", "{{call .Report}}"} {
		if err := checkAnswerTemplate("ubuntu", bad); err == nil {
			t.Errorf("template %q was accepted", bad)
		}
	}
}

func TestSHA512Crypt(t *testing.T) {
	// Vectors from glibc's crypt(3), checked with `openssl passwd -6`.
	for _, c := range []struct{ pw, salt, want string }{
		{"Hello world!", "saltstring", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		{"pässwörd with a long tail that goes beyond sixty four bytes of length for sure ok", "abc",
			"$6$abc$mZEesesCcRBN49m8BxD.FVYre8M.ENsqErjOiwUme8Wmt6nl6HN7s0dGD5mwK8AxBPHuDlfGFNrpTXmVuBDV71"},
	} {
		if got := sha512Crypt(c.pw, c.salt); got != c.want {
			t.Errorf("sha512Crypt(%q, %q) = %q, want %q", c.pw, c.salt, got, c.want)
		}
	}
	// With an explicit round count: the spec's own vector, and the count
	// installers get, both checked against glibc's crypt(3).
	for _, c := range []struct {
		pw, salt string
		rounds   int
		want     string
	}{
		{"Hello world!", "saltstringsaltstring", 10000,
			"$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
		{"hunter2", "abcdefghABCDEFGH", installerCryptRounds,
			"$6$rounds=100000$abcdefghABCDEFGH$UBiD2.RUsjOeDpCvjjSfKWc1iOtyvVYgy5ULKUp2fwvq5JwenlaEuOcbbZoTfKHuGe.jKvEMe3OAbCqxHwu6G1"},
	} {
		if got := sha512CryptRounds(c.pw, c.salt, c.rounds); got != c.want {
			t.Errorf("sha512CryptRounds(%q, %q, %d) = %q, want %q", c.pw, c.salt, c.rounds, got, c.want)
		}
	}
	if s := newCryptSalt(); len(s) != 16 || strings.ContainsAny(s, "$:\n") {
		t.Errorf("bad salt %q", s)
	}
}

func TestStatusTokenFor(t *testing.T) {
	a := newProvisioningToken(provisioningAnswerTokenPrefix)
	st := statusTokenFor(a)
	if !provisioningTokenPattern.MatchString(a) || !provisioningTokenPattern.MatchString(st) {
		t.Fatalf("tokens do not match their pattern: %q %q", a, st)
	}
	if !strings.HasPrefix(st, provisioningStatusTokenPrefix) || st == a || statusTokenFor(a) != st {
		t.Fatalf("status token must be derived deterministically and differ: %q from %q", st, a)
	}
	if statusTokenFor(newProvisioningToken(provisioningAnswerTokenPrefix)) == st {
		t.Fatal("two answer tokens gave one status token")
	}
}

func TestBootLimiterAndNetworks(t *testing.T) {
	l := newBootLimiter(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.allow("10.0.0.9", now) {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.allow("10.0.0.9", now) {
		t.Fatal("the fourth request in a window was allowed")
	}
	if !l.allow("10.0.0.10", now) || !l.allow("10.0.0.9", now.Add(time.Minute)) {
		t.Fatal("another address, or the next window, was refused")
	}
	if !ipAllowed("192.0.2.7", nil) || !ipAllowed("10.0.20.5", []string{"10.0.20.0/24"}) {
		t.Fatal("an allowed address was refused")
	}
	if ipAllowed("10.0.21.5", []string{"10.0.20.0/24"}) || ipAllowed("not-an-ip", []string{"10.0.20.0/24"}) {
		t.Fatal("an address outside the networks was allowed")
	}
}

func TestProvisioningConfigValidation(t *testing.T) {
	c := provisioningConfig{Enabled: true}
	c.applyDefaults()
	if err := c.validate(); err == nil {
		t.Fatal("provisioning turned on without a boot URL")
	}
	c.BootURL = "http://10.0.0.5:8069"
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"http://10.0.0.5:8069/?x=${net0/ip}", "ftp://x", "http://a b", "http://h/'"} {
		if _, err := normalizeBootURL(u); err == nil {
			t.Errorf("boot URL %q accepted", u)
		}
	}
	c.AllowedNetworks = []string{"10.0.0.0/33"}
	if err := c.validate(); err == nil {
		t.Fatal("a bad CIDR was accepted")
	}
}

// A reimage names one endpoint, in the URL: a body that tries to name
// more, or groups, is refused before anything is looked up, and the gate
// resolves exactly the URL's endpoint.
func TestReimageTargetsExactlyOneEndpoint(t *testing.T) {
	s := &Server{logger: slog.Default()}
	for _, body := range []string{
		`{"image_id":"pim-1","mac":"52:54:00:aa:bb:cc","confirm_hostname":"web-01","agent_ids":["agt-2","agt-3"]}`,
		`{"image_id":"pim-1","mac":"52:54:00:aa:bb:cc","confirm_hostname":"web-01","group_ids":["cgrp-1"]}`,
		`{"image_id":"pim-1","mac":"52:54:00:aa:bb:cc","confirm_hostname":"web-01","group_id":"cgrp-1"}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/agents/agt-1/reimage", strings.NewReader(body))
		r.SetPathValue("id", "agt-1")
		w := httptest.NewRecorder()
		s.handleReimage(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/agents/agt-1/reimage", strings.NewReader(`{"agent_ids":["agt-2"]}`))
	r.SetPathValue("id", "agt-1")
	a, err := resolveReimage(s, r, []byte(`{"agent_ids":["agt-2"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Explicit) != 1 || a.Explicit[0] != "agt-1" || a.Fleet != nil || a.NarrowFleet || a.Module != "provisioning" || !a.ApprovalByCaller {
		t.Fatalf("the gate resolved %+v, want exactly agt-1 with the handler's approval", a)
	}
}

// The reimage route is registered behind deploy.manage and the action gate,
// and its handler key is replayable once approved.
func TestReimageRouteIsGatedAndReplayable(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	var found bool
	for _, e := range s.routeLog.entries {
		if e.Pattern != reimageHandlerKey {
			continue
		}
		found = true
		pg, ok := e.Handler.(*permGuard)
		if !ok || len(pg.perms) != 1 || pg.perms[0] != "deploy.manage" {
			t.Fatalf("the reimage route is not behind deploy.manage: %#v", e.Handler)
		}
		if _, ok := pg.next.(*actionGate); !ok {
			t.Fatal("the reimage route does not lead to the action gate")
		}
	}
	if !found {
		t.Fatal("the reimage route is not registered")
	}
	if s.replayable()[reimageHandlerKey] == nil {
		t.Fatal("an approved reimage could not be replayed")
	}
	if !validModule("provisioning") {
		t.Fatal("approval policies cannot name the provisioning module")
	}
}

// The boot endpoints answer nothing while provisioning is off, on the
// console's listener and on one of their own.
func TestBootEndpointsAreOffByDefault(t *testing.T) {
	s := &Server{logger: slog.Default()}
	for name, h := range map[string]http.Handler{"console listener": s.routes(), "boot listener": s.bootRoutes()} {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "/boot/ipxe?mac=52:54:00:aa:bb:cc", nil),
			httptest.NewRequest(http.MethodGet, "/boot/answer/mpa_"+strings.Repeat("a", 43)+"/user-data", nil),
			httptest.NewRequest(http.MethodPost, "/boot/status/mps_"+strings.Repeat("a", 43), strings.NewReader("status=installed")),
		} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound || w.Header().Get("Location") != "" {
				t.Errorf("%s %s: status %d, want a plain 404 while provisioning is off", name, req.URL.Path, w.Code)
			}
		}
	}
}

// A DHCP server that can only hand out a fixed URL gets a script that asks
// again with the booting interface's MAC.
func TestChainScript(t *testing.T) {
	got := ipxeChainScript("http://10.0.0.5:8069")
	if got != "#!ipxe\nchain http://10.0.0.5:8069/boot/ipxe?mac=${netX/mac} || exit\n" {
		t.Fatalf("chain script %q", got)
	}
	if ipxeChainScript("http://bad host/") != ipxeLocalBoot {
		t.Fatal("a bad boot URL must give the local-boot script")
	}
}

// The enrollment command fails when its download does: a retry loop
// around "curl | bash" would take a failed download for success.
func TestEnrollCommandFailsWhenTheDownloadFails(t *testing.T) {
	unix, win := enrollCommands("https://console.example.com", "mte_abc", "lab")
	if strings.Contains(unix, "| bash") || !strings.Contains(unix, `-o "$f" && bash "$f"`) || !strings.HasSuffix(unix, `[ "$s" -eq 0 ]`) {
		t.Fatalf("unix enrollment command %q", unix)
	}
	if !strings.Contains(unix, "'https://console.example.com/install.sh?site=lab'") || !strings.Contains(win, "'https://console.example.com/install.ps1?site=lab'") {
		t.Fatalf("commands do not name the install scripts: %q %q", unix, win)
	}
	if !strings.Contains(firstbootScript(unix), "until "+unix+"; do") {
		t.Fatal("the first-boot script does not retry the command")
	}
}
