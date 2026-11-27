package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

func replInv(t *testing.T, apps []proto.InstalledApp) replacementInventory {
	t.Helper()
	raw, _ := json.Marshal(apps)
	parsed, idx, err := parseAgentApps(raw)
	if err != nil {
		t.Fatal(err)
	}
	return replacementInventory{apps: parsed, index: idx}
}

func names(list []store.DeviceReplacementProduct) []string {
	out := []string{}
	for _, p := range list {
		out = append(out, p.Name)
	}
	return out
}

func findProduct(list []store.DeviceReplacementProduct, name string) *store.DeviceReplacementProduct {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

// The comparison: what the new laptop lacks is matched to catalog
// packages by the packages' own detection, components never appear, and
// every product lands in exactly one of the three lists with its reason.
func TestPlanReplacement(t *testing.T) {
	oldA := store.AgentRecord{AgentID: "agt-old", Hostname: "FIN-LT-0087", OS: "windows", Arch: "amd64", Managed: true}
	newA := store.AgentRecord{AgentID: "agt-new", Hostname: "FIN-LT-0142", OS: "windows", Arch: "amd64", Managed: true}
	oldInv := replInv(t, []proto.InstalledApp{
		{Name: "7-Zip 23.01 (x64)", Version: "23.01", Publisher: "Igor Pavlov"},
		{Name: "Mozilla Firefox (x64 en-US)", Version: "127.0", Publisher: "Mozilla"},
		{Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130", Version: "14.38.33130"},
		{Name: "Microsoft Teams", Version: "24295.605"},
		{Name: "SAP GUI for Windows 8.00", Version: "8.00", Publisher: "SAP SE"},
		{Name: "Notepad++ (64-bit x64)", Version: "8.6.9"},
		{Name: "Slack", Version: "4.40"},
		{Name: "Zoom Workplace", Version: "6.2"},
		{Name: "Paint.NET", Version: "5.0"},
	})
	newInv := replInv(t, []proto.InstalledApp{
		{Name: "Microsoft Teams", Version: "25031.805"},
		{Name: "Slack Deployment Tool", Version: "4.41"},
	})
	legacy := func(id, name, detect string, mods ...func(*store.SoftwarePackage)) replacementCandidate {
		p := store.SoftwarePackage{ID: id, Kind: store.KindSoftware, Name: name, Enabled: true,
			Commands: map[string]store.SoftwareOps{"windows": {Install: "winget install " + id}},
			Detect:   store.SoftwareDetect{AppName: detect, Match: "contains"}}
		for _, m := range mods {
			m(&p)
		}
		return replacementCandidate{pkg: p}
	}
	firefox := store.SoftwarePackage{ID: "sw-firefox", Kind: store.KindSoftware, Name: "Mozilla Firefox", Enabled: true,
		DeployRevision: "rev-1", DeployDefinition: &proto.DeployDefinition{Version: 1, Variants: []proto.DeployVariant{{
			ID: "win", OS: "windows", Version: "128.0",
			Detection: &proto.DeployCheck{Kind: "app", Name: "Mozilla Firefox (x64 en-US)"},
			Actions:   map[string]proto.DeployAction{"install": {Steps: []proto.DeployStep{{ID: "s1", Name: "install"}}}},
		}}}}
	sapScoped := legacy("sw-sap", "SAP GUI", "sap gui")
	sapScoped.pkg.GroupIDs = []string{"grp-finance"}
	sapScoped.scope = map[string]bool{"agt-other": true}
	notepad := legacy("sw-npp", "Notepad++", "notepad++")
	notepad.denied = "Notepad++ is not in a content set your roles grant"
	cands := []replacementCandidate{
		legacy("sw-7zip", "7-Zip", "7-zip"),
		// A second package detecting 7-Zip that cannot install it: the one
		// that can is chosen whatever the order.
		legacy("sw-7zip-old", "7-Zip (legacy)", "7-zip", func(p *store.SoftwarePackage) { p.Commands = map[string]store.SoftwareOps{"linux": {Install: "x"}} }),
		{pkg: firefox},
		legacy("sw-vcredist", "VC++ runtime", "visual c++"),
		sapScoped,
		notepad,
		legacy("sw-slack", "Slack", "slack"),
		legacy("sw-zoom", "Zoom", "zoom", func(p *store.SoftwarePackage) { p.Enabled = false }),
		legacy("sw-paint", "Paint.NET", "paint.net", func(p *store.SoftwarePackage) { p.Kind = store.KindAction }),
	}
	usable := cands[:0:0]
	for _, c := range cands {
		if replacementPackageUsable(c.pkg) {
			usable = append(usable, c)
		}
	}
	plan := planReplacement(oldA, newA, oldInv, newInv, usable)

	var install []string
	for _, it := range plan.WillInstall {
		install = append(install, it.PackageID+"="+strings.Join(it.Products, ","))
	}
	if want := []string{"sw-7zip=7-Zip", "sw-firefox=Mozilla Firefox"}; !slices.Equal(install, want) {
		t.Errorf("will install %v, want %v", install, want)
	}
	if got, want := names(plan.AlreadyPresent), []string{"Microsoft Teams", "Slack"}; !slices.Equal(got, want) {
		t.Errorf("already present %v, want %v", got, want)
	}
	if p := findProduct(plan.AlreadyPresent, "Slack"); p == nil || p.PackageID != "sw-slack" || p.NewVersion != "4.41" || p.OldVersion != "4.40" {
		t.Errorf("Slack should be present by the package's detection, at 4.41: %+v", p)
	}
	if got, want := names(plan.NoMatch), []string{"Notepad++", "Paint.NET", "SAP GUI for Windows", "Zoom Workplace"}; !slices.Equal(got, want) {
		t.Errorf("no match %v, want %v", got, want)
	}
	if p := findProduct(plan.NoMatch, "SAP GUI for Windows"); p == nil || p.PackageID != "sw-sap" || !strings.Contains(p.Reason, "computer groups") {
		t.Errorf("SAP GUI should name its out-of-scope package: %+v", p)
	}
	if p := findProduct(plan.NoMatch, "Notepad++"); p == nil || !strings.Contains(p.Reason, "content set") {
		t.Errorf("Notepad++ should say the caller may not deploy it: %+v", p)
	}
	for _, n := range []string{"Zoom Workplace", "Paint.NET"} {
		if p := findProduct(plan.NoMatch, n); p == nil || p.PackageID != "" || p.Reason != "No catalog package detects it" {
			t.Errorf("%s: a disabled package or an action package is not a match: %+v", n, p)
		}
	}
	for _, list := range [][]store.DeviceReplacementProduct{plan.AlreadyPresent, plan.NoMatch} {
		for _, p := range list {
			if strings.Contains(p.Name, "Visual C++") {
				t.Errorf("a runtime was listed: %+v", p)
			}
		}
	}
}

// A device named by hostname or serial must be exactly one endpoint.
func TestResolveReplacementDevice(t *testing.T) {
	agents := []store.AgentRecord{
		{AgentID: "agt-1", Hostname: "FIN-LT-0087", OS: "windows", Managed: false},
		{AgentID: "agt-2", Hostname: "fin-lt-0087", OS: "windows", Managed: true},
		{AgentID: "agt-3", Hostname: "web-01.corp.example.com", OS: "linux", Managed: true},
		{AgentID: "agt-4", Hostname: "MAC-0001", OS: "darwin", Managed: true},
		{AgentID: "agt-5", Hostname: "MAC-0002", OS: "darwin", Managed: true},
	}
	serials := map[string]string{"agt-4": "C02XYZ", "agt-5": "c02xyz", "agt-3": "VMW-1"}
	code := func(err error) int {
		var he httpError
		if asHTTPError(err, &he) {
			return he.code
		}
		return 0
	}
	cases := []struct {
		name        string
		ref         replacementRef
		managedOnly bool
		want        string
		wantCode    int
	}{
		{"agent id", replacementRef{agentID: "agt-3"}, false, "agt-3", 0},
		{"two names given", replacementRef{agentID: "agt-3", hostname: "web-01"}, false, "", http.StatusBadRequest},
		{"none given", replacementRef{}, false, "", http.StatusBadRequest},
		{"hostname differing in case is two endpoints", replacementRef{hostname: "FIN-LT-0087"}, false, "", http.StatusConflict},
		{"a retired record is not the new endpoint", replacementRef{hostname: "FIN-LT-0087"}, true, "agt-2", 0},
		{"short name for a fully qualified host", replacementRef{hostname: "WEB-01"}, false, "agt-3", 0},
		{"unknown hostname", replacementRef{hostname: "nope"}, false, "", http.StatusNotFound},
		{"serial shared by two", replacementRef{serial: "C02XYZ"}, false, "", http.StatusConflict},
		{"unique serial", replacementRef{serial: "vmw-1"}, false, "agt-3", 0},
		{"retired endpoint by id as new", replacementRef{agentID: "agt-1"}, true, "", http.StatusConflict},
	}
	for _, c := range cases {
		got, err := resolveReplacementDevice(agents, serials, "new", c.ref, c.managedOnly)
		if c.wantCode != 0 {
			if code(err) != c.wantCode {
				t.Errorf("%s: got %v (%v), want status %d", c.name, got.AgentID, err, c.wantCode)
			}
			continue
		}
		if err != nil || got.AgentID != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got.AgentID, err, c.want)
		}
	}
	_, err := resolveReplacementDevice(agents, serials, "old", replacementRef{hostname: "fin-lt-0087"}, false)
	if err == nil || !strings.Contains(err.Error(), "agt-1") || !strings.Contains(err.Error(), "agt-2") || !strings.Contains(err.Error(), "agent ID") {
		t.Errorf("an ambiguous name should list what it matched and ask for the agent ID: %v", err)
	}

	win := store.AgentRecord{AgentID: "a", Hostname: "a", OS: "windows"}
	mac := store.AgentRecord{AgentID: "b", Hostname: "b", OS: "darwin"}
	if err := checkReplacementPair(win, win, true); code(err) != http.StatusBadRequest {
		t.Errorf("the same endpoint twice: %v", err)
	}
	if err := checkReplacementPair(win, mac, false); code(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "allow_cross_os") {
		t.Errorf("different OS families without allow_cross_os: %v", err)
	}
	if err := checkReplacementPair(win, mac, true); err != nil {
		t.Errorf("different OS families with allow_cross_os: %v", err)
	}
}

// Each package goes to the ordinary deployment with the new endpoint as
// its one explicit target, and never with an empty target list, which
// that handler reads as "every eligible endpoint".
func TestDispatchReplacementItemTargetsOnlyTheNewEndpoint(t *testing.T) {
	var got []softwareDeployRequest
	reply := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var req softwareDeployRequest
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &req); err != nil {
				t.Fatal(err)
			}
			if r.URL.Path != "/api/software/deploy" || r.Method != http.MethodPost {
				t.Errorf("dispatched as %s %s", r.Method, r.URL.Path)
			}
			got = append(got, req)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	r := httptest.NewRequest("POST", "/api/device-replacements", strings.NewReader(`{"agent_ids":["agt-x","agt-y"]}`))
	item := store.DeviceReplacementItem{PackageID: "sw-7zip", PackageName: "7-Zip", Status: replPending}

	it := dispatchReplacementItem(reply(200, `{"run_id":"run-1","targets":1}`), r, "agt-new", item)
	if it.RunID != "run-1" || it.Status != replPending {
		t.Errorf("dispatched item: %+v", it)
	}
	if len(got) != 1 || !slices.Equal(got[0].AgentIDs, []string{"agt-new"}) || got[0].Operation != "install" || got[0].PackageID != "sw-7zip" {
		t.Fatalf("deploy was asked for %+v", got)
	}

	got = nil
	it = dispatchReplacementItem(reply(200, `{}`), r, "  ", item)
	if len(got) != 0 || it.Status != replRefused {
		t.Errorf("no target must dispatch nothing: asked %+v, item %+v", got, it)
	}

	it = dispatchReplacementItem(reply(202, `{"approval_required":true,"request_id":"apr-1"}`), r, "agt-new", item)
	if it.Status != replAwaitingApproval || it.ApprovalID != "apr-1" || it.RunID != "" {
		t.Errorf("a parked deployment: %+v", it)
	}
	it = dispatchReplacementItem(reply(403, "7-Zip is not in a content set your roles grant\n"), r, "agt-new", item)
	if it.Status != replRefused || !strings.Contains(it.Detail, "content set") {
		t.Errorf("a refused deployment: %+v", it)
	}
}

// The four outcomes stay apart, an open action ages into the right one,
// and a queued catalog job with an expiry is left to expire.
func TestReplacementItemStatus(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	recent, old := now.Add(-time.Minute), now.Add(-4*time.Hour)
	act := func(status string, started time.Time) *store.AgentAction {
		return &store.AgentAction{ID: "act-1", Status: status, Detail: "detail " + status, StartedAt: started}
	}
	queued := &store.DeployJobRecord{Status: "queued", Detail: "Outside the maintenance window", Job: proto.DeployJob{ExpiresAt: now.Add(time.Hour)}}
	cases := []struct {
		name       string
		act        *store.AgentAction
		job        *store.DeployJobRecord
		dispatched time.Time
		want       string
	}{
		{"nothing yet", nil, nil, recent, replPending},
		{"nothing for hours", nil, nil, old, replNoResponse},
		{"succeeded", act("succeeded", recent), nil, recent, replInstalled},
		{"pending restart", act("pending_restart", recent), nil, recent, replInstalled},
		{"failed", act("failed", recent), nil, recent, replFailed},
		{"cancelled", act("cancelled", recent), nil, recent, replFailed},
		{"unsupported agent", act("unsupported", recent), nil, recent, replFailed},
		{"timed out", act("timed_out", recent), nil, recent, replTimedOut},
		{"agent offline", act("no_response", recent), nil, recent, replNoResponse},
		{"expired in the queue", act("expired", recent), nil, recent, replNoResponse},
		{"skipped for a window", act("skipped", recent), nil, recent, replSkipped},
		{"sent", act("started", recent), nil, recent, replPending},
		{"installing", act("installing", recent), nil, recent, replRunning},
		{"never accepted", act("started", old), nil, old, replNoResponse},
		{"stuck installing", act("installing", old), nil, old, replTimedOut},
		{"queued for a window, with an expiry", act("started", old), queued, old, replPending},
		{"queued without an expiry", act("started", old), &store.DeployJobRecord{Status: "queued"}, old, replNoResponse},
	}
	for _, c := range cases {
		if got, _ := replacementItemStatus(c.act, c.job, c.dispatched, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if _, detail := replacementItemStatus(act("started", old), queued, old, now); detail != queued.Detail {
		t.Errorf("a queued job should say what it waits for: %q", detail)
	}
}

func TestSelectReplacementItems(t *testing.T) {
	planned := []store.DeviceReplacementItem{{PackageID: "a", PackageName: "A", Detail: "why"}, {PackageID: "b", PackageName: "B"}, {PackageID: "c", PackageName: "C"}}
	ids := func(items []store.DeviceReplacementItem) []string {
		var out []string
		for _, it := range items {
			out = append(out, it.PackageID)
			if it.Status != replPending || it.Detail != "" {
				t.Errorf("selected item not reset to pending: %+v", it)
			}
		}
		return out
	}
	if got, err := selectReplacementItems(planned, nil, nil); err != nil || !slices.Equal(ids(got), []string{"a", "b", "c"}) {
		t.Errorf("default: %v %v", got, err)
	}
	if got, err := selectReplacementItems(planned, []string{"c", "a"}, []string{"a"}); err != nil || !slices.Equal(ids(got), []string{"c"}) {
		t.Errorf("include and exclude: %v %v", got, err)
	}
	if _, err := selectReplacementItems(planned, []string{"zzz"}, nil); err == nil {
		t.Error("a package the comparison did not choose was accepted")
	}
}

func TestReplacementJobStatusAndReport(t *testing.T) {
	done := time.Now()
	job := store.DeviceReplacement{ID: "drp-1", OldHostname: "OLD", NewHostname: "NEW", RequestedBy: "jsmith", FinishedAt: &done,
		Items: []store.DeviceReplacementItem{
			{PackageName: "7-Zip", Status: replInstalled},
			{PackageName: "Firefox", Status: replFailed, Detail: "exit code 1603\ninstaller log"},
			{PackageName: "Zoom", Status: replTimedOut},
			{PackageName: "Slack", Status: replNoResponse, Detail: "offline"},
		},
		NoMatch:        []store.DeviceReplacementProduct{{Name: "SAP GUI", OldVersion: "8.00"}},
		AlreadyPresent: []store.DeviceReplacementProduct{{Name: "Teams"}},
	}
	if s := replacementJobStatus(job); s != "partial" {
		t.Errorf("status %s, want partial", s)
	}
	text := replacementReportText(job, "https://mustra.example.com/device-replacement#drp-1")
	for _, want := range []string{"OLD", "NEW", "jsmith", "Installed (1):\n- 7-Zip", "Failed (1):\n- Firefox — exit code 1603 installer log",
		"Timed out (1):\n- Zoom", "No response (1):\n- Slack — offline", "No matching package, to install by hand (1):\n- SAP GUI 8.00",
		"Already on the new endpoint: 1.", "https://mustra.example.com/device-replacement#drp-1"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	job.Items = []store.DeviceReplacementItem{{Status: replNoResponse}, {Status: replNoResponse}}
	if s := replacementJobStatus(job); s != "no_response" {
		t.Errorf("the endpoint never answered: %s", s)
	}
	job.Items[1].Status = replFailed
	if s := replacementJobStatus(job); s != "failed" {
		t.Errorf("nothing installed: %s", s)
	}
	job.Items = nil
	if s := replacementJobStatus(job); s != "completed" {
		t.Errorf("nothing to install: %s", s)
	}
	job.FinishedAt = nil
	if s := replacementJobStatus(job); s != "running" {
		t.Errorf("unfinished: %s", s)
	}
}

func TestNormalizeTicket(t *testing.T) {
	for in, want := range map[string]string{
		"":                                 "",
		" inc0012345 ":                     "INC0012345",
		"RITM0012345":                      "RITM0012345",
		"6816F79CC0A8016401C5A33BE04BE441": "6816f79cc0a8016401c5a33be04be441",
		"OPS-1234":                         "OPS-1234",
	} {
		got, err := normalizeTicket(in)
		if err != nil || got != want {
			t.Errorf("normalizeTicket(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"INC001 OR 1=1", "number=INC1^ORactive=true", strings.Repeat("A", 65), "<script>"} {
		if _, err := normalizeTicket(bad); err == nil {
			t.Errorf("normalizeTicket(%q) accepted", bad)
		}
	}
	if _, _, _, err := snowTicketTarget("OPS-1234"); err == nil {
		t.Error("a non-ServiceNow reference was given a table")
	}
	if _, _, _, err := snowTicketTarget("PRB0001234"); err == nil {
		t.Error("an unsupported ServiceNow prefix was given a table")
	}
}

// The work note against a stand-in ServiceNow: a number is looked up in
// its table first, a sys_id goes straight to an incident, and anything
// but exactly one record is an error rather than a note on the wrong
// ticket.
func TestServiceNowWorkNote(t *testing.T) {
	const sysID = "6816f79cc0a8016401c5a33be04be441"
	var patched []string
	var noteText string
	results := map[string]string{
		"RITM0012345": `{"result":[{"sys_id":"` + sysID + `","number":"RITM0012345"}]}`,
		"INC0000001":  `{"result":[]}`,
		"INC0000002":  `{"result":[{"sys_id":"` + sysID + `"},{"sys_id":"` + sysID + `"}]}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "mustra.svc" || p != "s3cret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/now/table/"):
			num := strings.TrimPrefix(r.URL.Query().Get("sysparm_query"), "number=")
			body, ok := results[num]
			if !ok {
				t.Errorf("unexpected lookup %s", r.URL.RawQuery)
				body = `{"result":[]}`
			}
			_, _ = io.WriteString(w, body)
		case r.Method == http.MethodPatch:
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			noteText = b["work_notes"]
			patched = append(patched, r.URL.Path)
			_, _ = io.WriteString(w, `{"result":{}}`)
		default:
			http.Error(w, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	c := snowClient{base: srv.URL + "/", user: "mustra.svc", pass: "s3cret"}
	ctx := context.Background()

	if err := c.addWorkNote(ctx, "RITM0012345", "report text"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(patched, []string{"/api/now/table/sc_req_item/" + sysID}) || noteText != "report text" {
		t.Errorf("patched %v with %q", patched, noteText)
	}
	patched = nil
	if err := c.addWorkNote(ctx, sysID, "by sys_id"); err != nil || !slices.Equal(patched, []string{"/api/now/table/incident/" + sysID}) {
		t.Errorf("sys_id note: %v %v", err, patched)
	}
	patched = nil
	for _, ticket := range []string{"INC0000001", "INC0000002"} {
		if err := c.addWorkNote(ctx, ticket, "x"); err == nil {
			t.Errorf("%s: no error for zero or several records", ticket)
		}
	}
	if len(patched) != 0 {
		t.Errorf("a note was written although the ticket was not exactly one record: %v", patched)
	}
	bad := snowClient{base: srv.URL, user: "mustra.svc", pass: "wrong"}
	if err := bad.addWorkNote(ctx, sysID, "x"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("rejected credentials: %v", err)
	}
	if err := (snowClient{base: "ftp://x"}).addWorkNote(ctx, sysID, "x"); err == nil {
		t.Error("an invalid instance URL was used")
	}
}

// Every device replacement route needs deploy.manage, and starting one
// goes through the endpoint-action gate.
func TestDeviceReplacementRoutesNeedDeployManage(t *testing.T) {
	s := &Server{logger: slog.Default(), syslog: &syslogSink{}}
	s.routes()
	routes := map[string]bool{
		"GET /device-replacement": false, "GET /api/device-replacements": false, "GET /api/device-replacements/{id}": false,
		"POST /api/device-replacements/preview": false, "POST /api/device-replacements": true,
	}
	for _, e := range s.routeLog.entries {
		gated, ok := routes[e.Pattern]
		if !ok {
			continue
		}
		delete(routes, e.Pattern)
		pg, isGuard := e.Handler.(*permGuard)
		if !isGuard || !slices.Equal(pg.perms, []string{auth.PermDeployManage}) {
			t.Errorf("%s: not behind deploy.manage", e.Pattern)
			continue
		}
		if _, isGate := pg.next.(*actionGate); isGate != gated {
			t.Errorf("%s: gated %v, want %v", e.Pattern, isGate, gated)
		}
		// A token without deploy.manage is refused before anything runs
		// (on this bare server, anything running would panic on the
		// missing store).
		method, path, _ := strings.Cut(e.Pattern, " ")
		path = strings.ReplaceAll(path, "{id}", "drp-1")
		req := httptest.NewRequest(method, path, strings.NewReader(`{"old_agent_id":"a","new_agent_id":"b"}`))
		ctx := auth.WithUser(req.Context(), &store.User{ID: auth.APITokenUserID, Username: "token:servicenow", Active: true})
		req = req.WithContext(auth.WithToken(ctx, []string{auth.PermFleetRead}, &auth.TokenInfo{ID: "tok-1"}))
		rec := httptest.NewRecorder()
		e.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), auth.PermDeployManage) {
			t.Errorf("%s without deploy.manage: %d %q", e.Pattern, rec.Code, rec.Body.String())
		}
	}
	for p := range routes {
		t.Errorf("%s is not registered", p)
	}
}
