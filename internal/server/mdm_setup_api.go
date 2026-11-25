package server

// Apple MDM setup: the push certificate, the MDM CA that issues device
// identities, the optional profile-signing identity, the on/off switch and
// enrollment tokens. The protocol is internal/mdm; the device endpoints
// are mdm_protocol.go and the console's device and command routes
// mdm_api.go. docs/guides/apple-mdm.md (Help → Apple MDM) is the operator's guide.
//
// Every private key here is sealed by the credential vault, so the feature
// needs MUSTRA_CREDENTIAL_ENCRYPTION_KEY: without it nothing is stored and
// the routes say why.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/mdm"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// mdmRuntime is the MDM state kept in memory: the APNs client, reused
// across pushes because Apple asks providers to keep their HTTP/2
// connections open rather than open one per notification.
type mdmRuntime struct {
	mu       sync.Mutex
	pusher   *mdm.Pusher
	pusherFP string
	// apnsBase and apnsRoots point pushes at a stand-in in tests.
	apnsBase  string
	apnsRoots *x509.CertPool
}

// The vault binds each sealed MDM secret to what it is.
const (
	mdmAADCAKey      = "mdm/ca_key"
	mdmAADPushKey    = "mdm/push_key"
	mdmAADPushCSRKey = "mdm/push_csr_key"
	mdmAADSignKey    = "mdm/sign_key"
)

func mdmPayloadAAD(uuid string) string { return "mdm_command/payload/" + uuid }
func mdmPINAAD(uuid string) string     { return "mdm_command/pin/" + uuid }

var errMDMNoVault = errors.New("Apple MDM keeps its private keys in the credential vault, and none is configured (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)")

// mdmSeal seals a secret, refusing rather than storing it plain.
func (s *Server) mdmSeal(aad, value string) (string, error) {
	if s.vault == nil {
		return "", errMDMNoVault
	}
	return sealWith(s.vault, aad, value)
}

func (s *Server) mdmOpen(aad, stored string) (string, error) {
	if stored == "" {
		return "", errors.New("no key is stored")
	}
	return openWith(s.vault, aad, stored)
}

// mdmCA returns the MDM CA; with its key only when withKey.
func (s *Server) mdmCA(cfg *store.MDMConfig, withKey bool) (*mdm.CA, error) {
	if cfg.CACertPEM == "" {
		return nil, errors.New("no MDM CA has been created")
	}
	if !withKey {
		cert, err := mdm.ParseCertPEM(cfg.CACertPEM)
		if err != nil {
			return nil, err
		}
		return &mdm.CA{Cert: cert}, nil
	}
	keyPEM, err := s.mdmOpen(mdmAADCAKey, cfg.CAKeySealed)
	if err != nil {
		return nil, err
	}
	return mdm.ParseCA(cfg.CACertPEM, keyPEM)
}

// mdmMissing lists what stops the MDM from working, in the order an
// operator sets it up.
func (s *Server) mdmMissing(ctx context.Context, cfg *store.MDMConfig) []string {
	var out []string
	if s.vault == nil {
		out = append(out, "the credential vault (MUSTRA_CREDENTIAL_ENCRYPTION_KEY)")
	}
	if cfg.PushCertPEM == "" {
		out = append(out, "an APNs MDM push certificate")
	} else if cfg.PushExpiresAt != nil && time.Now().After(*cfg.PushExpiresAt) {
		out = append(out, "a push certificate that has not expired")
	}
	if cfg.CACertPEM == "" {
		out = append(out, "the MDM CA")
	}
	if base, err := s.agentPublicURL(ctx); err != nil || !strings.HasPrefix(base, "https://") {
		out = append(out, "an https public URL (Administration → Agent Identity)")
	}
	return out
}

// mdmCertSummary describes a certificate for the settings page.
type mdmCertSummary struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	Fingerprint string    `json:"fingerprint"`
}

func summarizeCert(c *x509.Certificate) *mdmCertSummary {
	if c == nil {
		return nil
	}
	return &mdmCertSummary{Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: mdm.SerialHex(c),
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, DaysLeft: daysLeft(c.NotAfter, time.Now()), Fingerprint: mdm.Fingerprint(c)}
}

func summarizeCertPEM(p string) *mdmCertSummary {
	if p == "" {
		return nil
	}
	c, err := mdm.ParseCertPEM(p)
	if err != nil {
		return nil
	}
	return summarizeCert(c)
}

// mdmSettingsResponse is what GET /api/mdm/settings answers.
type mdmSettingsResponse struct {
	// Enabled is the switch; Ready says nothing is missing; Active is
	// both, and is when devices can enroll and check in.
	Enabled bool     `json:"enabled"`
	Ready   bool     `json:"ready"`
	Active  bool     `json:"active"`
	Missing []string `json:"missing"`
	// Organization is shown on the Mac as who manages it.
	Organization string `json:"organization"`
	// CheckInURL and ServerURL are what enrollment profiles point Macs at.
	CheckInURL string `json:"checkin_url,omitempty"`
	ServerURL  string `json:"server_url,omitempty"`
	// PushTopic is the push certificate's topic, com.apple.mgmt.External.<uuid>.
	PushTopic string          `json:"push_topic,omitempty"`
	Push      *mdmCertSummary `json:"push,omitempty"`
	// PushWarning is set when the push certificate expires within 30 days:
	// renew it at Apple with the same Apple ID, or every Mac must enroll again.
	PushWarning string `json:"push_warning,omitempty"`
	// PendingCSR is a certificate signing request generated here and
	// waiting for its signed certificate.
	PendingCSR string          `json:"pending_csr,omitempty"`
	CA         *mdmCertSummary `json:"ca,omitempty"`
	Signing    *mdmCertSummary `json:"signing,omitempty"`
	Devices    int             `json:"devices"`
	// CanChange says whether the caller may change the setup
	// (integrations.manage, or an administrator).
	CanChange bool `json:"can_change"`
}

func (s *Server) mdmSettingsView(ctx context.Context) (*mdmSettingsResponse, error) {
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil {
		return nil, err
	}
	missing := s.mdmMissing(ctx, cfg)
	v := &mdmSettingsResponse{Enabled: cfg.Enabled, Ready: len(missing) == 0, Missing: missing, Organization: cfg.Organization,
		PushTopic: cfg.PushTopic, Push: summarizeCertPEM(cfg.PushCertPEM), PendingCSR: cfg.PushCSRPEM,
		CA: summarizeCertPEM(cfg.CACertPEM), Signing: summarizeCertPEM(cfg.SignCertPEM),
		CanChange: s.callerMayChange(ctx, auth.PermIntegrationsManage)}
	if v.Missing == nil {
		v.Missing = []string{}
	}
	v.Active = v.Enabled && v.Ready
	if base, err := s.agentPublicURL(ctx); err == nil {
		v.CheckInURL, v.ServerURL = base+"/mdm/checkin", base+"/mdm/connect"
	}
	if v.Push != nil && v.Push.DaysLeft <= 30 {
		v.PushWarning = "The push certificate expires in " + mdmPlural(v.Push.DaysLeft, "day") +
			". Renew it in the Apple Push Certificates Portal with the same Apple ID and upload the renewed certificate here; a new certificate has a new topic, and every Mac would have to enroll again."
		if v.Push.DaysLeft < 0 {
			v.PushWarning = "The push certificate has expired: Macs can no longer be woken to fetch commands. Renew it in the Apple Push Certificates Portal with the same Apple ID."
		}
	}
	if devs, err := s.store.ListMDMDevices(ctx, ""); err == nil {
		for _, d := range devs {
			if d.Enrolled {
				v.Devices++
			}
		}
	}
	return v, nil
}

func mdmPlural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// GET /api/mdm/settings
func (s *Server) handleGetMDMSettings(w http.ResponseWriter, r *http.Request) {
	v, err := s.mdmSettingsView(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, v)
}

// saveMDMSettingsRequest is the body of PUT /api/mdm/settings. An omitted
// field is left as it is.
type saveMDMSettingsRequest struct {
	// Enabled turns the MDM on or off. It turns on only once nothing is
	// missing. Off, devices cannot enroll or check in; nothing is erased.
	Enabled *bool `json:"enabled"`
	// Organization is shown on the Mac as who manages it.
	Organization *string `json:"organization"`
}

// PUT /api/mdm/settings
func (s *Server) handleSaveMDMSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change Apple MDM") {
		return
	}
	var req saveMDMSettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Organization != nil {
		org := strings.TrimSpace(*req.Organization)
		if len(org) > 120 || strings.ContainsAny(org, "<>\x00") {
			http.Error(w, "the organization name is limited to 120 characters, without < or >", http.StatusBadRequest)
			return
		}
		cfg.Organization = org
	}
	if req.Enabled != nil {
		if *req.Enabled {
			if missing := s.mdmMissing(ctx, cfg); len(missing) > 0 {
				http.Error(w, "Apple MDM cannot be turned on yet; it still needs "+strings.Join(missing, ", "), http.StatusConflict)
				return
			}
		}
		cfg.Enabled = *req.Enabled
	}
	cfg.UpdatedBy = auth.CurrentUser(ctx).Username
	if err := s.store.SaveMDMConfig(ctx, *cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.settings", Actor: cfg.UpdatedBy, Target: "Apple MDM", Severity: "notice",
		Detail: map[string]any{"enabled": cfg.Enabled, "organization": cfg.Organization}})
	s.handleGetMDMSettings(w, r)
}

// mdmPushCSRRequest is the body of POST /api/mdm/push-csr.
type mdmPushCSRRequest struct {
	// Email goes into the request; some signing services ask for it.
	Email string `json:"email"`
}

// mdmPushCSRResponse carries the request to have signed.
type mdmPushCSRResponse struct {
	CSR string `json:"csr_pem"`
}

// POST /api/mdm/push-csr
func (s *Server) handleMDMPushCSR(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change Apple MDM") {
		return
	}
	var req mdmPushCSRRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if len(req.Email) > 254 || strings.ContainsAny(req.Email, " <>\x00") {
		http.Error(w, "that is not an email address", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if s.vault == nil {
		http.Error(w, errMDMNoVault.Error(), http.StatusServiceUnavailable)
		return
	}
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	csr, keyPEM, err := mdm.NewPushCSR(cfg.Organization, req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sealed, err := s.mdmSeal(mdmAADPushCSRKey, keyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.PushCSRPEM, cfg.PushCSRKeySealed, cfg.UpdatedBy = csr, sealed, auth.CurrentUser(ctx).Username
	if err := s.store.SaveMDMConfig(ctx, *cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.push_csr", Actor: cfg.UpdatedBy, Target: "Apple MDM push certificate request", Severity: "notice"})
	writeJSONResponse(w, mdmPushCSRResponse{CSR: csr})
}

// mdmPushCertRequest is the body of POST /api/mdm/push-certificate: the
// certificate as PEM (with its key as PEM, or none to use the key made
// with the pending request), or a .p12 with its password.
type mdmPushCertRequest struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem" api:"writeonly"`
	// P12 is a base64 PKCS#12 file, as Keychain Access exports it.
	P12      string `json:"p12" api:"writeonly"`
	Password string `json:"password" api:"writeonly"`
	// ReplaceTopic accepts a certificate for a different topic while Macs
	// are enrolled under the current one. Those Macs can no longer be
	// pushed to and must enroll again.
	ReplaceTopic bool `json:"replace_topic"`
}

// POST /api/mdm/push-certificate
func (s *Server) handleMDMPushCert(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change Apple MDM") {
		return
	}
	var req mdmPushCertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if s.vault == nil {
		http.Error(w, errMDMNoVault.Error(), http.StatusServiceUnavailable)
		return
	}
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var pc *mdm.PushCert
	usedCSR := false
	switch {
	case req.P12 != "":
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(req.P12))
		if derr != nil {
			http.Error(w, "p12 is not base64", http.StatusBadRequest)
			return
		}
		pc, err = mdm.ParsePushCertP12(raw, req.Password)
	case req.CertPEM != "" && req.KeyPEM != "":
		pc, err = mdm.ParsePushCertPEM(req.CertPEM, req.KeyPEM)
	case req.CertPEM != "":
		if cfg.PushCSRKeySealed == "" {
			http.Error(w, "no key came with the certificate and no certificate request is pending; upload the key too, or a .p12", http.StatusBadRequest)
			return
		}
		keyPEM, oerr := s.mdmOpen(mdmAADPushCSRKey, cfg.PushCSRKeySealed)
		if oerr != nil {
			http.Error(w, oerr.Error(), http.StatusInternalServerError)
			return
		}
		pc, err = mdm.ParsePushCertPEM(req.CertPEM, keyPEM)
		usedCSR = true
	default:
		http.Error(w, "send cert_pem (with key_pem, or after a certificate request made here), or p12 and password", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if time.Now().After(pc.Cert.NotAfter) {
		http.Error(w, "that push certificate has expired", http.StatusBadRequest)
		return
	}
	if cfg.PushTopic != "" && !strings.EqualFold(cfg.PushTopic, pc.Topic) && !req.ReplaceTopic {
		n := 0
		if devs, err := s.store.ListMDMDevices(ctx, ""); err == nil {
			for _, d := range devs {
				if d.Enrolled {
					n++
				}
			}
		}
		if n > 0 {
			http.Error(w, "this certificate is for topic "+pc.Topic+", not "+cfg.PushTopic+": the "+mdmPlural(n, "Mac")+
				" enrolled under the current topic could no longer be reached and would have to enroll again. Renew the existing certificate with the same Apple ID instead, or send replace_topic to accept that.", http.StatusConflict)
			return
		}
	}
	keyPEM, err := mdm.KeyPEM(pc.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sealed, err := s.mdmSeal(mdmAADPushKey, keyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	exp := pc.Cert.NotAfter
	oldTopic := cfg.PushTopic
	cfg.PushCertPEM, cfg.PushKeySealed, cfg.PushTopic, cfg.PushExpiresAt = mdm.CertPEM(pc.Cert), sealed, pc.Topic, &exp
	if usedCSR {
		cfg.PushCSRPEM, cfg.PushCSRKeySealed = "", ""
	}
	cfg.UpdatedBy = auth.CurrentUser(ctx).Username
	if err := s.store.SaveMDMConfig(ctx, *cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.push_certificate", Actor: cfg.UpdatedBy, Target: pc.Topic, Severity: "notice",
		Detail: map[string]any{"expires": exp, "previous_topic": oldTopic, "serial": mdm.SerialHex(pc.Cert)}})
	s.handleGetMDMSettings(w, r)
}

// POST /api/mdm/ca
func (s *Server) handleMDMCreateCA(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change Apple MDM") {
		return
	}
	ctx := r.Context()
	if s.vault == nil {
		http.Error(w, errMDMNoVault.Error(), http.StatusServiceUnavailable)
		return
	}
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Replacing the CA would cut off every enrolled Mac at once, since
	// their identities chain to it; there is no route that does that.
	if cfg.CACertPEM != "" {
		http.Error(w, "the MDM CA already exists", http.StatusConflict)
		return
	}
	certPEM, keyPEM, err := mdm.NewCA(cfg.Organization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sealed, err := s.mdmSeal(mdmAADCAKey, keyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.CACertPEM, cfg.CAKeySealed, cfg.UpdatedBy = certPEM, sealed, auth.CurrentUser(ctx).Username
	if err := s.store.SaveMDMConfig(ctx, *cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.ca_created", Actor: cfg.UpdatedBy, Target: "Apple MDM CA", Severity: "notice"})
	s.handleGetMDMSettings(w, r)
}

// mdmSigningRequest is the body of PUT /api/mdm/signing-identity: a
// certificate (with any intermediates after it) and its key, both PEM,
// that enrollment profiles are signed with. A certificate a Mac already
// trusts, such as the console's own TLS certificate, makes the profile
// show as verified.
type mdmSigningRequest struct {
	CertPEM string `json:"cert_pem" api:"required"`
	KeyPEM  string `json:"key_pem" api:"required,writeonly"`
}

// PUT /api/mdm/signing-identity
func (s *Server) handleMDMSetSigning(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change Apple MDM") {
		return
	}
	var req mdmSigningRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		http.Error(w, "cert_pem and key_pem are required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if s.vault == nil {
		http.Error(w, errMDMNoVault.Error(), http.StatusServiceUnavailable)
		return
	}
	certs, err := mdm.ParseCertsPEM(req.CertPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key, err := mdm.ParseKeyPEM(req.KeyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !mdm.KeyMatches(certs[0], key) {
		http.Error(w, "the key does not belong to the certificate", http.StatusBadRequest)
		return
	}
	if _, err := mdm.SignProfile([]byte("<plist/>"), certs[0], key, certs[1:]); err != nil {
		http.Error(w, "that certificate and key cannot sign: "+err.Error(), http.StatusBadRequest)
		return
	}
	if time.Now().After(certs[0].NotAfter) {
		http.Error(w, "that certificate has expired", http.StatusBadRequest)
		return
	}
	keyPEM, err := mdm.KeyPEM(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sealed, err := s.mdmSeal(mdmAADSignKey, keyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var chain strings.Builder
	for _, c := range certs {
		chain.WriteString(mdm.CertPEM(c))
	}
	cfg.SignCertPEM, cfg.SignKeySealed, cfg.UpdatedBy = chain.String(), sealed, auth.CurrentUser(ctx).Username
	if err := s.store.SaveMDMConfig(ctx, *cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.signing_identity", Actor: cfg.UpdatedBy, Target: certs[0].Subject.String(), Severity: "notice"})
	s.handleGetMDMSettings(w, r)
}

// DELETE /api/mdm/signing-identity
func (s *Server) handleMDMClearSigning(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminOr(w, r, auth.PermIntegrationsManage, "change Apple MDM") {
		return
	}
	ctx := r.Context()
	cfg, err := s.store.GetMDMConfig(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.SignCertPEM, cfg.SignKeySealed, cfg.UpdatedBy = "", "", auth.CurrentUser(ctx).Username
	if err := s.store.SaveMDMConfig(ctx, *cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.signing_identity_removed", Actor: cfg.UpdatedBy, Target: "Apple MDM", Severity: "notice"})
	s.handleGetMDMSettings(w, r)
}

// --- enrollment tokens ------------------------------------------------------

const (
	mdmTokenPrefix     = "mdm_"
	mdmMaxTokenUses    = 1000
	mdmMaxTokenTTL     = 30 * 24 * time.Hour
	mdmDefaultTokenTTL = 7 * 24 * time.Hour
)

func newMDMEnrollToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return mdmTokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// mdmEnrollTokenRow is an entry of GET /api/mdm/enroll-tokens.
type mdmEnrollTokenRow struct {
	store.MDMEnrollToken
	Usable bool `json:"usable"`
}

// mdmEnrollTokensResponse is what GET /api/mdm/enroll-tokens answers.
type mdmEnrollTokensResponse struct {
	Tokens []mdmEnrollTokenRow `json:"tokens"`
}

// GET /api/mdm/enroll-tokens
func (s *Server) handleListMDMEnrollTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.store.ListMDMEnrollTokens(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := mdmEnrollTokensResponse{Tokens: []mdmEnrollTokenRow{}}
	now := time.Now()
	for _, t := range toks {
		out.Tokens = append(out.Tokens, mdmEnrollTokenRow{MDMEnrollToken: t, Usable: t.RevokedAt == nil && now.Before(t.ExpiresAt) && t.Uses < t.MaxUses})
	}
	writeJSONResponse(w, out)
}

// createMDMEnrollTokenRequest is the body of POST /api/mdm/enroll-tokens.
type createMDMEnrollTokenRequest struct {
	Label string `json:"label"`
	// MaxUses is how many enrollment profiles the link hands out (one per
	// Mac, and one more each time a page is reloaded); 1 by default, at
	// most 1000.
	MaxUses int `json:"max_uses"`
	// TTLHours is how long the link works; a week by default, at most 30 days.
	TTLHours int `json:"ttl_hours"`
}

// createMDMEnrollTokenResponse shows the token, and the link built from it,
// this once.
type createMDMEnrollTokenResponse struct {
	Token  string               `json:"token"`
	URL    string               `json:"url"`
	Record store.MDMEnrollToken `json:"record"`
}

// POST /api/mdm/enroll-tokens
func (s *Server) handleCreateMDMEnrollToken(w http.ResponseWriter, r *http.Request) {
	var req createMDMEnrollTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.MaxUses == 0 {
		req.MaxUses = 1
	}
	if req.MaxUses < 1 || req.MaxUses > mdmMaxTokenUses {
		http.Error(w, "max_uses must be between 1 and 1000", http.StatusBadRequest)
		return
	}
	ttl := mdmDefaultTokenTTL
	if req.TTLHours != 0 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}
	if ttl <= 0 || ttl > mdmMaxTokenTTL {
		http.Error(w, "ttl_hours must be between 1 and 720", http.StatusBadRequest)
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if len(req.Label) > 120 {
		http.Error(w, "the label is limited to 120 characters", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	base, err := s.agentPublicURL(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	token := newMDMEnrollToken()
	t := store.MDMEnrollToken{ID: newID("mdmt-"), Label: req.Label, MaxUses: req.MaxUses,
		ExpiresAt: time.Now().Add(ttl).UTC(), CreatedBy: auth.CurrentUser(ctx).Username, CreatedAt: time.Now().UTC()}
	if err := s.store.CreateMDMEnrollToken(ctx, t, hashToken(token)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.enroll_token_created", Actor: t.CreatedBy, Target: firstNonEmptyString(t.Label, t.ID), Severity: "notice",
		Detail: map[string]any{"id": t.ID, "max_uses": t.MaxUses, "expires": t.ExpiresAt}})
	w.WriteHeader(http.StatusCreated)
	writeJSONResponse(w, createMDMEnrollTokenResponse{Token: token, URL: base + "/mdm/enroll/" + token, Record: t})
}

// mdmRevokeResponse is what DELETE /api/mdm/enroll-tokens/{id} answers.
type mdmRevokeResponse struct {
	Revoked bool `json:"revoked"`
}

// DELETE /api/mdm/enroll-tokens/{id}
func (s *Server) handleRevokeMDMEnrollToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ok, err := s.store.RevokeMDMEnrollToken(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no live enrollment token with that id", http.StatusNotFound)
		return
	}
	s.audit(ctx, auditEvent{Action: "mdm.enroll_token_revoked", Actor: auth.CurrentUser(ctx).Username, Target: r.PathValue("id"), Severity: "notice"})
	writeJSONResponse(w, mdmRevokeResponse{Revoked: true})
}

// mdmPusher returns the APNs client for the current push certificate.
func (s *Server) mdmPusher(cfg *store.MDMConfig) (*mdm.Pusher, error) {
	if cfg.PushCertPEM == "" {
		return nil, errors.New("no push certificate")
	}
	sum := sha256.Sum256([]byte(cfg.PushCertPEM))
	fp := hex.EncodeToString(sum[:])
	s.mdmRT.mu.Lock()
	defer s.mdmRT.mu.Unlock()
	if s.mdmRT.pusher != nil && s.mdmRT.pusherFP == fp {
		return s.mdmRT.pusher, nil
	}
	keyPEM, err := s.mdmOpen(mdmAADPushKey, cfg.PushKeySealed)
	if err != nil {
		return nil, err
	}
	pc, err := mdm.ParsePushCertPEM(cfg.PushCertPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	base := s.mdmRT.apnsBase
	if base == "" {
		base = mdm.ProductionAPNs
	}
	s.mdmRT.pusher, s.mdmRT.pusherFP = mdm.NewPusher(pc, base, s.mdmRT.apnsRoots), fp
	return s.mdmRT.pusher, nil
}
