package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The boot endpoints: what a network-booting machine talks to.
//
// Unauthenticated by nature, so held to this:
//   - off (404) until an administrator turns provisioning on;
//   - optionally answered only to configured source networks;
//   - rate limited per source address;
//   - without a token, only boot scripts and boot files are served. A boot
//     script names a token only when its MAC is armed, and then it is the
//     one place that token appears;
//   - answer files, and the Windows install script carrying the share's
//     credentials, need the install's answer token, which expires and is
//     used up by the answer file itself;
//   - installer status reports need the install's separate status token.
//
// Every failure looks the same to the caller (404), so probing tokens or
// MACs teaches nothing.

// registerBootRoutes adds the boot endpoints to mux. The server registers
// them on the console's listener, or on a listener of their own when one
// is configured (Config.BootHTTPAddr), never on both.
func (s *Server) registerBootRoutes(mux *http.ServeMux) {
	if s.bootLimiter == nil {
		s.bootLimiter = newBootLimiter(120, time.Minute)
	}
	mux.Handle("GET /boot/ipxe", s.bootGuard(http.HandlerFunc(s.handleBootScript)))
	mux.Handle("GET /boot/assets/{image}/{role}", s.bootGuard(http.HandlerFunc(s.handleBootAsset)))
	mux.Handle("GET /boot/answer/{token}/{name}", s.bootGuard(http.HandlerFunc(s.handleBootAnswer)))
	mux.Handle("POST /boot/status/{token}", s.bootGuard(http.HandlerFunc(s.handleBootStatus)))
}

// bootRoutes is the handler of the boot-only listener.
func (s *Server) bootRoutes() http.Handler {
	mux := http.NewServeMux()
	s.registerBootRoutes(mux)
	return s.secureHandler(mux)
}

// bootGuard applies the feature switch, the network allowlist and the rate
// limit, and marks every answer uncacheable: a proxy that kept an answer
// file would serve a used-up token's content again.
func (s *Server) bootGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		cfg, err := s.provisioningConfig(r.Context())
		if err != nil {
			s.logger.Warn("provisioning settings unreadable", "error", err)
			http.NotFound(w, r)
			return
		}
		if !cfg.Enabled {
			http.NotFound(w, r)
			return
		}
		ip := auth.ClientIP(r)
		if !ipAllowed(ip, cfg.AllowedNetworks) {
			s.logger.Warn("boot request from outside the allowed networks", "ip", ip, "path", redactBootPath(r.URL.Path))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !s.bootLimiter.allow(ip, time.Now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bootConfigKey{}, cfg)))
	})
}

type bootConfigKey struct{}

func bootConfigFrom(ctx context.Context) provisioningConfig {
	c, _ := ctx.Value(bootConfigKey{}).(provisioningConfig)
	return c
}

// redactBootPath keeps tokens out of logs.
func redactBootPath(p string) string {
	for _, pre := range []string{"/boot/answer/", "/boot/status/"} {
		if strings.HasPrefix(p, pre) {
			return pre + "…"
		}
	}
	return p
}

func ipAllowed(ip string, networks []string) bool {
	if len(networks) == 0 {
		return true
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, n := range networks {
		if _, cidr, err := net.ParseCIDR(n); err == nil && cidr.Contains(addr) {
			return true
		}
	}
	return false
}

// bootLimiter is a fixed-window counter per source address. Booting a
// machine takes a handful of requests; a burst of hundreds is somebody
// guessing.
type bootLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	seen   map[string]*bootWindow
}

type bootWindow struct {
	start time.Time
	n     int
}

func newBootLimiter(limit int, window time.Duration) *bootLimiter {
	return &bootLimiter{limit: limit, window: window, seen: map[string]*bootWindow{}}
}

func (l *bootLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.seen[key]
	if w == nil || now.Sub(w.start) >= l.window {
		if len(l.seen) > 10000 {
			for k, v := range l.seen {
				if now.Sub(v.start) >= l.window {
					delete(l.seen, k)
				}
			}
		}
		l.seen[key] = &bootWindow{start: now, n: 1}
		return true
	}
	w.n++
	return w.n <= l.limit
}

func writeIPXE(w http.ResponseWriter, script string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(script))
}

// GET /boot/ipxe?mac=aa:bb:cc:dd:ee:ff
func (s *Server) handleBootScript(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := bootConfigFrom(ctx)
	ip := auth.ClientIP(r)
	if !r.URL.Query().Has("mac") {
		// No MAC at all: a DHCP server that can only hand out a fixed
		// filename. iPXE asks again with the MAC of the interface it
		// booted from.
		writeIPXE(w, ipxeChainScript(cfg.BootURL))
		return
	}
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		writeIPXE(w, ipxeLocalBoot)
		return
	}
	m, err := s.store.GetProvisioningMachineByMAC(ctx, mac)
	if err != nil {
		s.logger.Warn("boot script lookup failed", "mac", mac, "error", err)
		writeIPXE(w, ipxeLocalBoot)
		return
	}
	if m == nil {
		writeIPXE(w, ipxeLocalBoot)
		return
	}
	_ = s.store.TouchProvisioningBoot(ctx, m.ID, ip)
	if !m.Armed(time.Now()) {
		writeIPXE(w, ipxeLocalBoot)
		return
	}
	script, err := s.armedBootScript(ctx, cfg, m, ip)
	if err != nil {
		// Never an installer by accident: anything wrong with the armed
		// machine's image sends it to its own disk, and says why where an
		// operator will look.
		s.logger.Warn("armed machine sent to its local disk", "mac", mac, "error", err)
		s.audit(ctx, auditEvent{Action: "provisioning.boot_refused", Actor: "boot server", Target: firstNonEmptyString(m.Name, m.MAC),
			Outcome: "failed", Severity: "warning", Detail: map[string]any{"mac": m.MAC, "reason": err.Error(), "ip": ip}})
		writeIPXE(w, ipxeLocalBoot)
		return
	}
	writeIPXE(w, script)
}

// armedBootScript records an install and returns its installer script.
func (s *Server) armedBootScript(ctx context.Context, cfg provisioningConfig, m *store.ProvisioningMachine, ip string) (string, error) {
	im, err := s.store.GetProvisioningImage(ctx, m.ImageID)
	if err != nil {
		return "", err
	}
	if im == nil {
		return "", errors.New("the machine's image no longer exists")
	}
	if why := imageReady(im); why != "" {
		return "", errors.New(why)
	}
	vars, err := validateVariables(mergedVariables(im, m))
	if err != nil {
		return "", err
	}
	base, err := normalizeBootURL(cfg.BootURL)
	if err != nil {
		return "", err
	}
	answerToken := newProvisioningToken(provisioningAnswerTokenPrefix)
	statusToken := statusTokenFor(answerToken)
	hostname := hostnameFor(vars, m)
	assets := map[string]string{}
	for _, role := range provisioningAssetRoles[im.Family] {
		a := im.Assets[role]
		if a.URL != "" {
			assets[role] = a.URL
		} else {
			assets[role] = base + "/boot/assets/" + im.ID + "/" + role
		}
	}
	script, err := ipxeScript(ipxeBoot{
		Family: im.Family, Assets: assets, AnswerBase: base + "/boot/answer/" + answerToken,
		Source: im.InstallSource, KernelArgs: im.KernelArgs, Hostname: hostname,
		Locale: firstNonEmptyString(vars["locale"], "en_US.UTF-8"), Keyboard: firstNonEmptyString(vars["keyboard"], "us"),
	})
	if err != nil {
		return "", err
	}
	now := time.Now()
	installID := idgen.New("pin-")
	if err := s.store.StartProvisioningInstall(ctx, store.NewProvisioningInstall{
		ID: installID, MachineID: m.ID, MAC: m.MAC, Hostname: hostname, ImageID: im.ID, ImageName: im.Name, Family: im.Family,
		AnswerTokenHash: hashToken(answerToken), StatusTokenHash: hashToken(statusToken),
		AnswerExpiresAt: now.Add(time.Duration(cfg.AnswerTTLMinutes) * time.Minute),
		StatusExpiresAt: now.Add(provisioningStatusWindow),
		ScriptIP:        ip, ArmedBy: m.ArmedBy, ReimageOf: m.AgentID,
	}); err != nil {
		return "", err
	}
	s.audit(ctx, auditEvent{Action: "provisioning.boot", Actor: "boot server", Target: hostname, AgentID: m.AgentID, Severity: "notice",
		Detail: map[string]any{"mac": m.MAC, "image": im.Name, "install": installID, "ip": ip, "armed_by": m.ArmedBy}})
	return script, nil
}

// provisioningFileDir is where uploaded boot files live, beside package
// payloads (and so in backups with them).
func provisioningFileDir() string { return filepath.Join(packageFileDir(), "provisioning") }

var provisioningFileID = regexp.MustCompile(`^pbf-[A-Za-z0-9_-]{8,64}$`)

func provisioningFilePath(id string) (string, error) {
	if !provisioningFileID.MatchString(id) {
		return "", errors.New("invalid boot file id")
	}
	return pathWithin(provisioningFileDir(), id)
}

// GET /boot/assets/{image}/{role}: an uploaded boot file. Public by
// design: kernels, initrds and WinPE carry nothing secret, and firmware
// cannot authenticate. Only a file an image names for a role of its
// family is served.
func (s *Server) handleBootAsset(w http.ResponseWriter, r *http.Request) {
	im, err := s.store.GetProvisioningImage(r.Context(), r.PathValue("image"))
	if err != nil || im == nil {
		http.NotFound(w, r)
		return
	}
	role := r.PathValue("role")
	if !containsString(provisioningAssetRoles[im.Family], role) {
		http.NotFound(w, r)
		return
	}
	a := im.Assets[role]
	path, err := provisioningFilePath(a.FileID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

// GET /boot/answer/{token}/{name}
func (s *Server) handleBootAnswer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token, name := r.PathValue("token"), r.PathValue("name")
	if !provisioningTokenPattern.MatchString(token) || !strings.HasPrefix(token, provisioningAnswerTokenPrefix) {
		http.NotFound(w, r)
		return
	}
	hash := hashToken(token)
	peek, err := s.store.PeekProvisioningAnswer(ctx, hash)
	if err != nil || peek == nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case name == answerFileName[peek.Family]:
		s.serveAnswerFile(w, r, token)
	case peek.Family == "ubuntu" && name == "meta-data":
		// cloud-init reads this before user-data; it holds nothing the
		// answer file does not, so it does not use the token up.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "instance-id: mustra-%s\nlocal-hostname: %s\n", peek.InstallID, peek.Hostname)
	case peek.Family == "windows" && name == "winpeshl.ini":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(windowsLauncher))
	case peek.Family == "windows" && name == "mustra-install.cmd":
		s.serveWindowsInstallScript(w, r, peek)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveWindowsInstallScript(w http.ResponseWriter, r *http.Request, peek *store.ProvisioningAnswerClaim) {
	ctx := r.Context()
	m, err := s.store.GetProvisioningMachine(ctx, peek.MachineID)
	if err != nil || m == nil {
		http.NotFound(w, r)
		return
	}
	im, err := s.store.GetProvisioningImage(ctx, m.ImageID)
	if err != nil || im == nil {
		http.NotFound(w, r)
		return
	}
	password, err := s.openProvisioningSecret(im.SourceSecret, "image-source", im.ID)
	if err != nil {
		s.logger.Error("opening the share password failed", "image", im.ID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	script, err := windowsInstallScript(im.InstallSource, im.SourceUser, password, "")
	if err != nil {
		s.logger.Error("rendering the WinPE install script failed", "image", im.ID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(script))
}

// serveAnswerFile uses the token up, then renders the answer file.
func (s *Server) serveAnswerFile(w http.ResponseWriter, r *http.Request, answerToken string) {
	ctx := r.Context()
	cfg := bootConfigFrom(ctx)
	ip := auth.ClientIP(r)
	claim, err := s.store.ClaimProvisioningAnswer(ctx, hashToken(answerToken), ip)
	if err != nil || claim == nil {
		http.NotFound(w, r)
		return
	}
	body, err := s.renderInstallAnswer(ctx, cfg, claim, statusTokenFor(answerToken))
	if err != nil {
		// The token is spent and the machine disarmed: the installer
		// stops here, visibly, rather than running half-configured.
		s.logger.Error("rendering an answer file failed", "install", claim.InstallID, "error", err)
		_ = s.store.FailProvisioningInstall(ctx, claim.InstallID, "the answer file could not be rendered: "+err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "provisioning.answer_served", Actor: "boot server", Target: claim.Hostname, Severity: "notice",
		Detail: map[string]any{"install": claim.InstallID, "ip": ip}})
	ct := "text/plain; charset=utf-8"
	if claim.Family == "windows" {
		ct = "application/xml; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(body)
}

// renderInstallAnswer builds one install's answer file: variables, the
// sealed passwords, a fresh single-use enrollment token, and the status
// URL.
func (s *Server) renderInstallAnswer(ctx context.Context, cfg provisioningConfig, claim *store.ProvisioningAnswerClaim, statusToken string) ([]byte, error) {
	m, err := s.store.GetProvisioningMachine(ctx, claim.MachineID)
	if err != nil || m == nil {
		return nil, errors.New("the machine record is gone")
	}
	im, err := s.store.GetProvisioningImage(ctx, m.ImageID)
	if err != nil || im == nil {
		return nil, errors.New("the image is gone")
	}
	vars, err := validateVariables(mergedVariables(im, m))
	if err != nil {
		return nil, err
	}
	adminPassword, err := s.openProvisioningSecret(m.AdminSecret, "machine-admin", m.ID)
	if err != nil {
		return nil, err
	}
	if adminPassword == "" {
		if adminPassword, err = s.openProvisioningSecret(im.AdminSecret, "image-admin", im.ID); err != nil {
			return nil, err
		}
	}
	sourcePassword, err := s.openProvisioningSecret(im.SourceSecret, "image-source", im.ID)
	if err != nil {
		return nil, err
	}
	base, err := s.agentPublicURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("the console's public URL (Client Management → Settings) is needed to enroll the new system: %w", err)
	}
	bootURL, err := normalizeBootURL(cfg.BootURL)
	if err != nil {
		return nil, err
	}
	hostname := claim.Hostname
	token, rec, err := s.mintEnrollToken(ctx, "provisioning: "+hostname, cfg.Site, "provisioning", 1,
		time.Duration(cfg.EnrollTTLHours)*time.Hour)
	if err != nil {
		return nil, err
	}
	_ = s.store.SetProvisioningInstallEnrollToken(ctx, claim.InstallID, rec.ID)
	enrollUnix, enrollWindows := enrollCommands(base, token, cfg.Site)
	statusURL := bootURL + "/boot/status/" + statusToken
	d := answerData{
		Hostname: hostname, Keyboard: vars["keyboard"], Timezone: vars["timezone"], Disk: vars["disk"],
		AdminUser: firstNonEmptyString(vars["admin_user"], "localadmin"), AdminPassword: adminPassword,
		SSHKey: vars["ssh_key"], ImageIndex: firstNonEmptyString(vars["image_index"], "1"), ProductKey: vars["product_key"],
		InstallSource: im.InstallSource, SourceUser: im.SourceUser, SourcePassword: sourcePassword,
		StatusURL: statusURL, EnrollUnix: enrollUnix, EnrollWindows: enrollWindows,
		FirstbootScript: firstbootScript(enrollUnix), InstallID: claim.InstallID,
	}
	locale := firstNonEmptyString(vars["locale"], "en_US.UTF-8")
	if im.Family == "windows" {
		d.Locale, d.LocaleTag = localeTag(locale), localeTag(locale)
		d.Keyboard = firstNonEmptyString(d.Keyboard, d.LocaleTag)
		d.Timezone = firstNonEmptyString(d.Timezone, "UTC")
		if len(hostname) > 15 {
			return nil, fmt.Errorf("the Windows computer name %q is longer than 15 characters", hostname)
		}
		if adminPassword == "" {
			return nil, errors.New("a Windows install needs an administrator password (on the machine or the image)")
		}
	} else {
		d.Locale, d.LocaleTag = posixLocale(locale), localeTag(locale)
		d.Keyboard = firstNonEmptyString(d.Keyboard, "us")
		d.Timezone = firstNonEmptyString(d.Timezone, "Etc/UTC")
		d.MirrorHost, d.MirrorPath = mirrorParts(im.InstallSource)
		switch {
		case adminPassword != "":
			d.AdminPasswordHash = sha512Crypt(adminPassword, newCryptSalt())
		case d.SSHKey != "":
			// No password: the account is reachable by its SSH key only.
			d.AdminPasswordHash = "!"
		default:
			return nil, errors.New("a Linux install needs an administrator password or an SSH key")
		}
	}
	return renderAnswer(im, d)
}

// POST /boot/status/{token} with status=installing|installed|failed and an
// optional detail.
func (s *Server) handleBootStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")
	if !provisioningTokenPattern.MatchString(token) || !strings.HasPrefix(token, provisioningStatusTokenPrefix) {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	status := r.PostForm.Get("status")
	if status != "installing" && status != "installed" && status != "failed" {
		http.Error(w, "status must be installing, installed or failed", http.StatusBadRequest)
		return
	}
	detail := cleanStatusDetail(r.PostForm.Get("detail"))
	in, err := s.store.ReportProvisioningStatus(ctx, hashToken(token), status, detail)
	if err != nil || in == nil {
		http.NotFound(w, r)
		return
	}
	if status != "installing" {
		sev := "notice"
		if status == "failed" {
			sev = "warning"
		}
		s.audit(ctx, auditEvent{Action: "provisioning.install_" + status, Actor: "installer", Target: in.Hostname, Severity: sev,
			Detail: map[string]any{"install": in.ID, "image": in.ImageName, "mac": in.MAC, "ip": auth.ClientIP(r)}})
	}
	w.WriteHeader(http.StatusNoContent)
}

// cleanStatusDetail keeps an installer's note to one short printable line.
func cleanStatusDetail(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 300 {
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
