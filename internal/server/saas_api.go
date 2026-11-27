package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/saasmon"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// SaaS experience monitoring, the server's half: the app library and the
// on/off switch agents are told about, the aggregates they send, the
// scores computed from them, and the packaged browser extension served to
// browsers so a policy can force-install it.
//
// Off until an administrator turns it on. While off, agents register no
// native messaging host and hand the extension no apps, and aggregates
// that arrive anyway are discarded.

const (
	settingSaaS = "saas_monitor"
	// saasExtensionPath is where browsers fetch the update manifest and the
	// package. Unauthenticated: a browser installing a policy's extension
	// has no console session.
	saasUpdatePath       = "/saas-extension/update.xml"
	saasCRXPath          = "/saas-extension/mustra-saas-monitor.crx"
	saasRetentionDefault = 30
	saasRetentionMax     = 365
)

// saasSettings is GET/PUT /api/saas/settings's configuration.
type saasSettings struct {
	// Enabled turns monitoring on for every endpoint whose browser has the
	// extension.
	Enabled bool `json:"enabled"`
	// RetentionDays is how long five-minute aggregates are kept, 1-365;
	// default 30.
	RetentionDays int `json:"retention_days"`
	// ExtensionID is the extension's ID when it is not the uploaded
	// package's: one packed and hosted elsewhere. An uploaded package's ID
	// wins.
	ExtensionID string `json:"extension_id"`
}

func (s *Server) saasSettings(ctx context.Context) saasSettings {
	var t saasSettings
	if raw, err := s.store.GetSetting(ctx, settingSaaS); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &t)
	}
	if t.RetentionDays <= 0 {
		t.RetentionDays = saasRetentionDefault
	}
	if t.RetentionDays > saasRetentionMax {
		t.RetentionDays = saasRetentionMax
	}
	return t
}

// saasExtensionID is the ID agents admit to their native host.
func (s *Server) saasExtensionID(ctx context.Context, t saasSettings) string {
	if ext, _, err := s.store.GetSaaSExtension(ctx, false); err == nil && ext != nil {
		return ext.ExtensionID
	}
	return t.ExtensionID
}

// saasConfigFor answers an agent's "saas_config".
func (s *Server) saasConfigFor(ctx context.Context) proto.SaaSConfig {
	t := s.saasSettings(ctx)
	cfg := proto.SaaSConfig{Apps: []proto.SaaSApp{}}
	if t.Enabled {
		apps, err := s.store.ListSaaSApps(ctx)
		if err != nil {
			// Unknown is not "off": say nothing, and the agent keeps what it
			// had. An empty reply would switch every endpoint off on a
			// database hiccup.
			return proto.SaaSConfig{Revision: "unavailable", Enabled: false, Apps: []proto.SaaSApp{}}
		}
		cfg.Enabled = true
		cfg.ExtensionID = s.saasExtensionID(ctx, t)
		cfg.WindowSeconds = proto.SaaSWindowSeconds
		for _, a := range apps {
			cfg.Apps = append(cfg.Apps, proto.SaaSApp{ID: a.ID, Name: a.Name, Domains: a.Domains})
		}
	}
	raw, _ := json.Marshal(cfg)
	sum := sha256.Sum256(raw)
	cfg.Revision = hex.EncodeToString(sum[:])[:12]
	return cfg
}

// saasEndpointRow is what the saas_experience sensor cache holds per
// endpoint: the last batch, summarised, for the endpoint page.
type saasEndpointRow struct {
	App         string   `json:"app"`
	Browser     string   `json:"browser"`
	WindowStart string   `json:"window_start"`
	Navigations int      `json:"navigations"`
	TTFBP75Ms   *float64 `json:"ttfb_p75_ms"`
	LoadP75Ms   *float64 `json:"load_p75_ms"`
	Errors      int      `json:"errors"`
	JSErrors    int      `json:"js_errors"`
}

// recordSaaSReport stores a batch. Aggregates that no longer fit (an app
// removed from the library since, a window past retention) are dropped one
// by one; the rest of the batch still counts.
func (s *Server) recordSaaSReport(ctx context.Context, snap proto.SensorSnapshot) error {
	var rep proto.SaaSReport
	if err := json.Unmarshal(snap.Data, &rep); err != nil {
		return nil // normalizeSnapshotData already decoded it; cannot happen
	}
	t := s.saasSettings(ctx)
	if !t.Enabled {
		return nil
	}
	if err := saasmon.ValidateReportHeader(rep); err != nil {
		s.logger.Warn("discarding SaaS report with a malformed header", "agent_id", snap.AgentID, "error", err)
		return nil
	}
	apps, err := s.store.ListSaaSApps(ctx)
	if err != nil {
		return err
	}
	lib := saasLibrary(apps)
	maxAge := time.Duration(t.RetentionDays) * 24 * time.Hour
	now := time.Now()
	var keep []proto.SaaSAggregate
	dropped := 0
	for _, a := range rep.Aggregates {
		if len(keep) >= saasmon.MaxAggregates {
			dropped++
			continue
		}
		if err := saasmon.ValidateAggregate(a, lib, now, maxAge); err != nil {
			dropped++
			continue
		}
		keep = append(keep, a)
	}
	if dropped > 0 {
		s.logger.Info("SaaS aggregates dropped", "agent_id", snap.AgentID, "dropped", dropped, "kept", len(keep))
	}
	if len(keep) == 0 {
		return nil
	}
	applied, err := s.store.RecordSaaSBatch(ctx, snap.AgentID, rep.BatchID, rep.ExtensionVersion, keep)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			// The endpoint's row does not exist (removed, or not registered
			// yet). Nothing to attach the numbers to.
			return nil
		}
		return err
	}
	if !applied {
		return nil
	}
	rows := make([]saasEndpointRow, 0, len(keep))
	for _, a := range keep {
		var tot saasmon.Totals
		tot.Add(a)
		r := saasmon.Compute(tot)
		rows = append(rows, saasEndpointRow{App: a.App, Browser: a.Browser, WindowStart: a.WindowStart.UTC().Format(time.RFC3339),
			Navigations: a.Navigations, TTFBP75Ms: r.TTFBP75Ms, LoadP75Ms: r.LoadP75Ms,
			Errors: a.Nav5xx + a.NavFailed + a.Req5xx + a.ReqFailed, JSErrors: a.JSErrors})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].App < rows[j].App || rows[i].App == rows[j].App && rows[i].WindowStart > rows[j].WindowStart
	})
	if raw, err := json.Marshal(rows); err == nil {
		if err := s.store.UpsertSensorData(ctx, snap.AgentID, string(proto.SensorSaaS), snap.Timestamp, raw); err != nil {
			s.logger.Debug("saas sensor cache", "error", err)
		}
	}
	return nil
}

func saasLibrary(apps []store.SaaSApp) saasmon.Library {
	pa := make([]proto.SaaSApp, 0, len(apps))
	for _, a := range apps {
		pa = append(pa, proto.SaaSApp{ID: a.ID, Domains: a.Domains})
	}
	return saasmon.NewLibrary(pa)
}

// saasPruneLoop applies retention every hour.
func (s *Server) saasPruneLoop(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		days := s.saasSettings(ctx).RetentionDays
		if n, err := s.store.PruneSaaS(ctx, time.Now().Add(-time.Duration(days)*24*time.Hour)); err != nil {
			s.logger.Warn("prune SaaS aggregates", "error", err)
		} else if n > 0 {
			s.logger.Debug("pruned SaaS aggregates", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// --- settings and deployment ------------------------------------------------

// saasPolicies are ready-to-use force-install policies for the extension.
type saasPolicies struct {
	// WindowsReg is a .reg file for Chrome and Edge.
	WindowsReg string `json:"windows_reg"`
	// LinuxJSON is a managed policy file for /etc/opt/chrome/policies/managed,
	// /etc/chromium/policies/managed and /etc/opt/edge/policies/managed.
	LinuxJSON string `json:"linux_json"`
	// MacOSMobileconfig is a configuration profile for an MDM to install.
	MacOSMobileconfig string `json:"macos_mobileconfig"`
}

// saasSettingsResponse is what GET and PUT /api/saas/settings answer.
type saasSettingsResponse struct {
	Settings saasSettings `json:"settings"`
	// Extension is the uploaded package, null when none is.
	Extension *store.SaaSExtension `json:"extension"`
	// EffectiveExtensionID is the ID agents admit: the package's, else the
	// configured one.
	EffectiveExtensionID string `json:"effective_extension_id"`
	// UpdateURL is the update manifest browsers are pointed at; empty
	// until the console's public URL is set.
	UpdateURL      string `json:"update_url"`
	PublicURLError string `json:"public_url_error,omitempty"`
	// Policies are filled when both the ID and the update URL are known.
	Policies *saasPolicies `json:"policies,omitempty"`
	// Endpoints is how many endpoints have reported within retention.
	Endpoints int `json:"endpoints"`
	// CanManage says whether this viewer may change any of it.
	CanManage bool `json:"can_manage"`
}

func (s *Server) saasSettingsView(ctx context.Context) (saasSettingsResponse, error) {
	t := s.saasSettings(ctx)
	ext, _, err := s.store.GetSaaSExtension(ctx, false)
	if err != nil {
		return saasSettingsResponse{}, err
	}
	out := saasSettingsResponse{Settings: t, Extension: ext, EffectiveExtensionID: s.saasExtensionID(ctx, t)}
	if base, err := s.agentPublicURL(ctx); err != nil {
		out.PublicURLError = err.Error()
	} else {
		out.UpdateURL = strings.TrimSuffix(base, "/") + saasUpdatePath
	}
	if out.EffectiveExtensionID != "" && out.UpdateURL != "" {
		p := saasForcelistPolicies(out.EffectiveExtensionID, out.UpdateURL)
		out.Policies = &p
	}
	if eps, err := s.store.ListSaaSEndpoints(ctx); err == nil {
		out.Endpoints = len(eps)
	}
	if u := auth.CurrentUser(ctx); u != nil {
		ok, err := s.auth.HasPermission(ctx, u, auth.PermSettingsManage)
		out.CanManage = err == nil && ok
	}
	return out, nil
}

// saasForcelistPolicies writes ExtensionInstallForcelist for each platform.
// The Windows value name is 100 so it does not overwrite the low-numbered
// entries an existing policy is likely to use.
func saasForcelistPolicies(id, updateURL string) saasPolicies {
	entry := id + ";" + updateURL
	reg := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist]\r\n" +
		"\"100\"=\"" + entry + "\"\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist]\r\n" +
		"\"100\"=\"" + entry + "\"\r\n"
	linux, _ := json.MarshalIndent(map[string]any{"ExtensionInstallForcelist": []string{entry}}, "", "  ")
	uuid := func(seed string) string {
		h := sha256.Sum256([]byte("mustra-saas|" + id + "|" + seed))
		x := hex.EncodeToString(h[:16])
		return strings.ToUpper(x[0:8] + "-" + x[8:12] + "-4" + x[13:16] + "-a" + x[17:20] + "-" + x[20:32])
	}
	payload := func(domain, seed string) string {
		return `		<dict>
			<key>PayloadType</key><string>` + domain + `</string>
			<key>PayloadIdentifier</key><string>dev.mustra.saas.` + domain + `</string>
			<key>PayloadUUID</key><string>` + uuid(seed) + `</string>
			<key>PayloadVersion</key><integer>1</integer>
			<key>PayloadDisplayName</key><string>mustra SaaS monitoring</string>
			<key>ExtensionInstallForcelist</key>
			<array><string>` + html.EscapeString(entry) + `</string></array>
		</dict>
`
	}
	mobileconfig := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadIdentifier</key><string>dev.mustra.saas</string>
	<key>PayloadUUID</key><string>` + uuid("profile") + `</string>
	<key>PayloadVersion</key><integer>1</integer>
	<key>PayloadDisplayName</key><string>mustra SaaS experience monitoring</string>
	<key>PayloadScope</key><string>System</string>
	<key>PayloadContent</key>
	<array>
` + payload("com.google.Chrome", "chrome") + payload("com.microsoft.Edge", "edge") + `	</array>
</dict>
</plist>
`
	return saasPolicies{WindowsReg: reg, LinuxJSON: string(linux) + "\n", MacOSMobileconfig: mobileconfig}
}

func (s *Server) handleGetSaaSSettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.saasSettingsView(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, out)
}

func (s *Server) handlePutSaaSSettings(w http.ResponseWriter, r *http.Request) {
	var t saasSettings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&t); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if t.RetentionDays == 0 {
		t.RetentionDays = saasRetentionDefault
	}
	if t.RetentionDays < 1 || t.RetentionDays > saasRetentionMax {
		http.Error(w, fmt.Sprintf("retention_days must be 1-%d", saasRetentionMax), http.StatusBadRequest)
		return
	}
	t.ExtensionID = strings.TrimSpace(t.ExtensionID)
	if t.ExtensionID != "" && !saasmon.ValidExtensionID(t.ExtensionID) {
		http.Error(w, "extension_id must be a 32-letter extension ID (letters a to p)", http.StatusBadRequest)
		return
	}
	raw, _ := json.Marshal(t)
	actor := auth.CurrentUser(r.Context()).Username
	if err := s.store.SetSetting(r.Context(), settingSaaS, string(raw), actor); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "saas.settings", Actor: actor, Target: "SaaS experience monitoring", Severity: "notice",
		Detail: map[string]any{"enabled": t.Enabled, "retention_days": t.RetentionDays, "extension_id": t.ExtensionID}})
	s.handleGetSaaSSettings(w, r)
}

// handleUploadSaaSExtension stores a packed extension after checking it
// the way a browser would. The body is the .crx file itself.
func (s *Server) handleUploadSaaSExtension(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, saasmon.MaxCRXBytes))
	if err != nil {
		http.Error(w, fmt.Sprintf("the package must be at most %d MB", saasmon.MaxCRXBytes>>20), http.StatusRequestEntityTooLarge)
		return
	}
	info, err := saasmon.ParseCRX(data)
	if err != nil {
		http.Error(w, "not a usable extension package: "+err.Error(), http.StatusBadRequest)
		return
	}
	actor := auth.CurrentUser(r.Context()).Username
	sum := sha256.Sum256(data)
	meta := store.SaaSExtension{ExtensionID: info.ID, Version: info.Version, Name: info.Name, SHA256: hex.EncodeToString(sum[:]), UploadedBy: actor}
	if prev, _, err := s.store.GetSaaSExtension(r.Context(), false); err == nil && prev != nil && prev.ExtensionID != info.ID {
		// A different key: browsers would treat it as another extension, and
		// every agent's native host would stop admitting the installed one.
		if r.URL.Query().Get("replace_id") != "1" {
			http.Error(w, "this package's extension ID ("+info.ID+") differs from the current one ("+prev.ExtensionID+
				"): it was packed with a different key. Pack it with the original key, or upload with replace_id=1 to switch extensions", http.StatusConflict)
			return
		}
	}
	if err := s.store.PutSaaSExtension(r.Context(), meta, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "saas.extension_upload", Actor: actor, Target: info.Name + " " + info.Version, Severity: "notice",
		Detail: map[string]any{"extension_id": info.ID, "version": info.Version, "sha256": meta.SHA256}})
	stored, _, err := s.store.GetSaaSExtension(r.Context(), false)
	if err != nil || stored == nil {
		http.Error(w, "the package was stored but could not be read back", http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, stored)
}

func (s *Server) handleDeleteSaaSExtension(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSaaSExtension(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "saas.extension_delete", Actor: auth.CurrentUser(r.Context()).Username, Target: "SaaS extension package", Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// handleSaaSUpdateManifest is the update manifest a browser reads, by the
// ID in the policy, to find the package and its version.
func (s *Server) handleSaaSUpdateManifest(w http.ResponseWriter, r *http.Request) {
	ext, _, err := s.store.GetSaaSExtension(r.Context(), false)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	base, perr := s.agentPublicURL(r.Context())
	if ext == nil || perr != nil {
		// An empty answer is a valid "no update" to a browser.
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+`<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0"></gupdate>`+"\n")
		return
	}
	codebase := strings.TrimSuffix(base, "/") + saasCRXPath + "?v=" + ext.Version
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="%s">
    <updatecheck codebase="%s" version="%s" hash_sha256="%s"/>
  </app>
</gupdate>
`, html.EscapeString(ext.ExtensionID), html.EscapeString(codebase), html.EscapeString(ext.Version), html.EscapeString(ext.SHA256))
}

func (s *Server) handleSaaSCRX(w http.ResponseWriter, r *http.Request) {
	ext, data, err := s.store.GetSaaSExtension(r.Context(), true)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if ext == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-chrome-extension")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// --- the app library --------------------------------------------------------

// saasAppsResponse is what GET /api/saas/apps answers.
type saasAppsResponse struct {
	Apps []store.SaaSApp `json:"apps"`
}

// saasAppRequest is the body of POST /api/saas/apps and PUT
// /api/saas/apps/{id}.
type saasAppRequest struct {
	// ID is chosen on creation (lower-case letters, digits, - and _), or
	// derived from the name when empty; it cannot change.
	ID   string `json:"id,omitempty"`
	Name string `json:"name" api:"required"`
	// Domains belong to the app with their subdomains: slack.com covers
	// app.slack.com. Each may belong to only one app.
	Domains []string `json:"domains" api:"required"`
}

func (s *Server) handleListSaaSApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListSaaSApps(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, saasAppsResponse{Apps: apps})
}

// cleanSaaSApp validates a request against the library. self is the app
// being edited ("" on create), whose own domains do not conflict.
func cleanSaaSApp(req saasAppRequest, existing []store.SaaSApp, self string) (store.SaaSApp, error) {
	if strings.TrimSpace(req.Name) == "" {
		return store.SaaSApp{}, errors.New("name is required")
	}
	a := store.SaaSApp{ID: self, Name: strings.TrimSpace(req.Name)}
	if len(a.Name) > 100 {
		return a, errors.New("name is at most 100 characters")
	}
	if len(req.Domains) == 0 {
		return a, errors.New("give at least one domain")
	}
	if len(req.Domains) > saasmon.MaxDomainsPerApp {
		return a, fmt.Errorf("at most %d domains", saasmon.MaxDomainsPerApp)
	}
	owner := map[string]string{}
	for _, e := range existing {
		if e.ID == self {
			continue
		}
		for _, d := range e.Domains {
			owner[d] = e.Name
		}
	}
	seen := map[string]bool{}
	for _, raw := range req.Domains {
		d, err := saasmon.NormalizeDomain(raw)
		if err != nil {
			return a, err
		}
		if o, taken := owner[d]; taken {
			return a, fmt.Errorf("%s already belongs to %s", d, o)
		}
		if !seen[d] {
			seen[d] = true
			a.Domains = append(a.Domains, d)
		}
	}
	sort.Strings(a.Domains)
	if self == "" {
		id := strings.TrimSpace(req.ID)
		if id == "" {
			id = saasSlug(a.Name)
		}
		if !saasmon.ValidAppID(id) {
			return a, errors.New("id must be lower-case letters, digits, - and _ (at most 64)")
		}
		a.ID = id
	}
	if len(existing) >= saasmon.MaxApps && self == "" {
		return a, fmt.Errorf("the library holds at most %d apps", saasmon.MaxApps)
	}
	return a, nil
}

func saasSlug(name string) string {
	var b strings.Builder
	dash := false
	for _, c := range strings.ToLower(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 60 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func (s *Server) handleCreateSaaSApp(w http.ResponseWriter, r *http.Request) {
	var req saasAppRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	existing, err := s.store.ListSaaSApps(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app, err := cleanSaaSApp(req, existing, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, e := range existing {
		if e.ID == app.ID {
			http.Error(w, "an app with id "+app.ID+" exists", http.StatusConflict)
			return
		}
	}
	created, err := s.store.CreateSaaSApp(r.Context(), app)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "saas.app_create", Actor: auth.CurrentUser(r.Context()).Username, Target: created.Name,
		Detail: map[string]any{"id": created.ID, "domains": created.Domains}})
	writeJSONStatus(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateSaaSApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req saasAppRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	existing, err := s.store.ListSaaSApps(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app, err := cleanSaaSApp(req, existing, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	updated, err := s.store.UpdateSaaSApp(r.Context(), app)
	if errors.Is(err, store.ErrSaaSAppNotFound) {
		http.Error(w, "no such app", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "saas.app_update", Actor: auth.CurrentUser(r.Context()).Username, Target: updated.Name,
		Detail: map[string]any{"id": updated.ID, "domains": updated.Domains}})
	writeJSONResponse(w, updated)
}

func (s *Server) handleDeleteSaaSApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSaaSApp(r.Context(), id); errors.Is(err, store.ErrSaaSAppNotFound) {
		http.Error(w, "no such app", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "saas.app_delete", Actor: auth.CurrentUser(r.Context()).Username, Target: id, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// --- scores -----------------------------------------------------------------

// saasPeriod reads ?hours= (1 to retention; default 24).
func (s *Server) saasPeriod(r *http.Request) (since, until time.Time, hours int, err error) {
	hours = 24
	if v := r.URL.Query().Get("hours"); v != "" {
		hours, err = strconv.Atoi(v)
		if err != nil || hours < 1 || hours > saasRetentionMax*24 {
			return since, until, 0, fmt.Errorf("hours must be 1-%d", saasRetentionMax*24)
		}
	}
	until = time.Now().UTC().Truncate(time.Minute).Add(time.Minute)
	since = until.Add(-time.Duration(hours) * time.Hour)
	return since, until, hours, nil
}

// saasAppScore is an app's row in the overview.
type saasAppScore struct {
	AppID     string   `json:"app_id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Endpoints int      `json:"endpoints"`
	saasmon.Result
}

// saasOverviewResponse is what GET /api/saas/overview answers.
type saasOverviewResponse struct {
	Enabled bool      `json:"enabled"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
	Hours   int       `json:"hours"`
	// Fleet is every app's page loads together.
	Fleet saasmon.Result `json:"fleet"`
	// Endpoints is how many endpoints reported in the period.
	Endpoints int `json:"endpoints"`
	// Apps, worst score first; apps without enough data last.
	Apps []saasAppScore `json:"apps"`
}

func (s *Server) handleSaaSOverview(w http.ResponseWriter, r *http.Request) {
	since, until, hours, err := s.saasPeriod(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	apps, err := s.store.ListSaaSApps(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := s.store.SaaSRollup(ctx, store.SaaSRollupQuery{Since: since, Until: until, GroupBy: store.SaaSByApp})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	byApp := map[string]store.SaaSRollupRow{}
	var fleet saasmon.Totals
	for _, row := range rows {
		byApp[row.Key] = row
		addTotals(&fleet, row.Totals)
	}
	agents, err := s.store.SaaSRollup(ctx, store.SaaSRollupQuery{Since: since, Until: until, GroupBy: store.SaaSByAgent})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := saasOverviewResponse{Enabled: s.saasSettings(ctx).Enabled, Since: since, Until: until, Hours: hours,
		Fleet: saasmon.Compute(fleet), Endpoints: len(agents), Apps: []saasAppScore{}}
	for _, a := range apps {
		row := byApp[a.ID]
		out.Apps = append(out.Apps, saasAppScore{AppID: a.ID, Name: a.Name, Domains: a.Domains, Endpoints: row.Endpoints, Result: saasmon.Compute(row.Totals)})
	}
	sortSaaSScores(out.Apps, func(i int) (*int, string) { return out.Apps[i].Score, out.Apps[i].Name })
	writeJSONResponse(w, out)
}

// sortSaaSScores orders worst first, unscored last, then by name.
func sortSaaSScores[T any](rows []T, key func(int) (*int, string)) {
	sort.SliceStable(rows, func(i, j int) bool {
		si, ni := key(i)
		sj, nj := key(j)
		switch {
		case si == nil && sj == nil:
			return strings.ToLower(ni) < strings.ToLower(nj)
		case si == nil:
			return false
		case sj == nil:
			return true
		case *si != *sj:
			return *si < *sj
		}
		return strings.ToLower(ni) < strings.ToLower(nj)
	})
}

func addTotals(into *saasmon.Totals, t saasmon.Totals) {
	into.Navigations += t.Navigations
	into.Nav4xx += t.Nav4xx
	into.Nav5xx += t.Nav5xx
	into.NavFailed += t.NavFailed
	into.Requests += t.Requests
	into.Req4xx += t.Req4xx
	into.Req5xx += t.Req5xx
	into.ReqFailed += t.ReqFailed
	into.JSErrors += t.JSErrors
	add := func(a, b []int64) []int64 {
		if len(a) < len(b) {
			a = append(a, make([]int64, len(b)-len(a))...)
		}
		for i := range b {
			a[i] += b[i]
		}
		return a
	}
	into.TTFBHist, into.DCLHist, into.LoadHist = add(into.TTFBHist, t.TTFBHist), add(into.DCLHist, t.DCLHist), add(into.LoadHist, t.LoadHist)
}

// saasEndpointScore is one endpoint's row in an app's drill-down.
type saasEndpointScore struct {
	AgentID          string     `json:"agent_id"`
	Hostname         string     `json:"hostname"`
	OS               string     `json:"os"`
	ExtensionVersion string     `json:"extension_version"`
	LastReportAt     *time.Time `json:"last_report_at"`
	saasmon.Result
}

// saasAppEndpointsResponse is what GET /api/saas/apps/{id}/endpoints
// answers.
type saasAppEndpointsResponse struct {
	App       store.SaaSApp       `json:"app"`
	Since     time.Time           `json:"since"`
	Until     time.Time           `json:"until"`
	Hours     int                 `json:"hours"`
	Fleet     saasmon.Result      `json:"fleet"`
	Endpoints []saasEndpointScore `json:"endpoints"`
}

func (s *Server) handleSaaSAppEndpoints(w http.ResponseWriter, r *http.Request) {
	since, until, hours, err := s.saasPeriod(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	app, err := s.store.GetSaaSApp(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrSaaSAppNotFound) {
		http.Error(w, "no such app", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows, err := s.store.SaaSRollup(ctx, store.SaaSRollupQuery{Since: since, Until: until, AppID: app.ID, GroupBy: store.SaaSByAgent})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hosts := map[string]store.AgentRecord{}
	if agents, err := s.store.ListAgents(ctx, s.staleAfter()); err == nil {
		for _, a := range agents {
			hosts[a.AgentID] = a
		}
	}
	exts := map[string]store.SaaSEndpoint{}
	if eps, err := s.store.ListSaaSEndpoints(ctx); err == nil {
		for _, e := range eps {
			exts[e.AgentID] = e
		}
	}
	out := saasAppEndpointsResponse{App: app, Since: since, Until: until, Hours: hours, Endpoints: []saasEndpointScore{}}
	var fleet saasmon.Totals
	for _, row := range rows {
		addTotals(&fleet, row.Totals)
		h := hosts[row.Key]
		e := saasEndpointScore{AgentID: row.Key, Hostname: h.Hostname, OS: h.OS, Result: saasmon.Compute(row.Totals)}
		if x, ok := exts[row.Key]; ok {
			e.ExtensionVersion = x.ExtensionVersion
			at := x.LastReportAt
			e.LastReportAt = &at
		}
		out.Endpoints = append(out.Endpoints, e)
	}
	out.Fleet = saasmon.Compute(fleet)
	sortSaaSScores(out.Endpoints, func(i int) (*int, string) {
		return out.Endpoints[i].Score, out.Endpoints[i].Hostname + out.Endpoints[i].AgentID
	})
	writeJSONResponse(w, out)
}

// saasTrendPoint is one bucket of an app's trend.
type saasTrendPoint struct {
	At        time.Time `json:"at"`
	Endpoints int       `json:"endpoints"`
	saasmon.Result
}

// saasTrendResponse is what GET /api/saas/apps/{id}/trend answers.
type saasTrendResponse struct {
	AppID         string           `json:"app_id"`
	Since         time.Time        `json:"since"`
	Until         time.Time        `json:"until"`
	Hours         int              `json:"hours"`
	BucketSeconds int              `json:"bucket_seconds"`
	Points        []saasTrendPoint `json:"points"`
}

// saasBucketFor keeps a trend to roughly 50-170 points.
func saasBucketFor(hours int) int {
	switch {
	case hours <= 6:
		return 300
	case hours <= 48:
		return 3600
	case hours <= 24*14:
		return 6 * 3600
	}
	return 24 * 3600
}

func (s *Server) handleSaaSAppTrend(w http.ResponseWriter, r *http.Request) {
	since, until, hours, err := s.saasPeriod(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	app, err := s.store.GetSaaSApp(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrSaaSAppNotFound) {
		http.Error(w, "no such app", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bucket := saasBucketFor(hours)
	rows, err := s.store.SaaSRollup(ctx, store.SaaSRollupQuery{Since: since, Until: until, AppID: app.ID, AgentID: r.URL.Query().Get("agent_id"),
		GroupBy: store.SaaSByBucket, BucketSeconds: bucket})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := saasTrendResponse{AppID: app.ID, Since: since, Until: until, Hours: hours, BucketSeconds: bucket, Points: []saasTrendPoint{}}
	for _, row := range rows {
		out.Points = append(out.Points, saasTrendPoint{At: row.Bucket, Endpoints: row.Endpoints, Result: saasmon.Compute(row.Totals)})
	}
	writeJSONResponse(w, out)
}
