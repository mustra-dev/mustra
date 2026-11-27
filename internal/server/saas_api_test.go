package server

import (
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Reading SaaS scores is fleet telemetry; changing what every endpoint's
// browser measures, or what extension they install, is a server setting.
func TestSaaSRoutePermissions(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	want := map[string]string{
		"GET /saas":                         auth.PermFleetRead,
		"GET /api/saas/settings":            auth.PermFleetRead,
		"GET /api/saas/apps":                auth.PermFleetRead,
		"GET /api/saas/overview":            auth.PermFleetRead,
		"GET /api/saas/apps/{id}/endpoints": auth.PermFleetRead,
		"GET /api/saas/apps/{id}/trend":     auth.PermFleetRead,
		"PUT /api/saas/settings":            auth.PermSettingsManage,
		"POST /api/saas/extension":          auth.PermSettingsManage,
		"DELETE /api/saas/extension":        auth.PermSettingsManage,
		"POST /api/saas/apps":               auth.PermSettingsManage,
		"PUT /api/saas/apps/{id}":           auth.PermSettingsManage,
		"DELETE /api/saas/apps/{id}":        auth.PermSettingsManage,
	}
	got := map[string][]string{}
	for _, e := range s.routeLog.entries {
		if g, ok := e.Handler.(*permGuard); ok {
			got[e.Pattern] = g.perms
		}
	}
	for pattern, perm := range want {
		perms, ok := got[pattern]
		if !ok {
			t.Errorf("%s is not registered behind a permission", pattern)
			continue
		}
		if len(perms) != 1 || perms[0] != perm {
			t.Errorf("%s needs %v, want %s", pattern, perms, perm)
		}
	}
	// The browser-facing update manifest and package are outside the
	// session table: a browser has no session.
	for _, e := range s.routeLog.entries {
		if strings.HasPrefix(routePath(e.Pattern), "/saas-extension/") {
			t.Errorf("%s must be public, not behind a session", e.Pattern)
		}
	}
}

func routePath(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		return pattern[i+1:]
	}
	return pattern
}

func TestCleanSaaSApp(t *testing.T) {
	existing := []store.SaaSApp{{ID: "slack", Name: "Slack", Domains: []string{"slack.com"}}}
	a, err := cleanSaaSApp(saasAppRequest{Name: " Example CRM ", Domains: []string{"https://CRM.example.com/", "crm.example.com", "files.crm.example.com"}}, existing, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "example-crm" || a.Name != "Example CRM" || strings.Join(a.Domains, ",") != "crm.example.com,files.crm.example.com" {
		t.Fatalf("cleaned %+v", a)
	}
	for name, req := range map[string]saasAppRequest{
		"no name":            {Domains: []string{"a.example"}},
		"no domains":         {Name: "x"},
		"domain of another":  {Name: "x", Domains: []string{"slack.com"}},
		"a URL with a path":  {Name: "x", Domains: []string{"https://x.example/path"}},
		"a wildcard":         {Name: "x", Domains: []string{"*.example.com"}},
		"an invalid id":      {ID: "Bad ID", Name: "x", Domains: []string{"x.example"}},
		"a name of symbols":  {Name: "!!!", Domains: []string{"x.example"}},
		"a very long name":   {Name: strings.Repeat("n", 101), Domains: []string{"x.example"}},
		"a single-label one": {Name: "x", Domains: []string{"intranet"}},
	} {
		if _, err := cleanSaaSApp(req, existing, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Editing an app may keep its own domains.
	if _, err := cleanSaaSApp(saasAppRequest{Name: "Slack", Domains: []string{"slack.com", "slack-edge.com"}}, existing, "slack"); err != nil {
		t.Fatalf("editing slack: %v", err)
	}
}

func TestSaaSForcelistPolicies(t *testing.T) {
	id := strings.Repeat("k", 32)
	url := "https://console.example.com/saas-extension/update.xml"
	p := saasForcelistPolicies(id, url)
	entry := id + ";" + url
	if !strings.Contains(p.WindowsReg, `"100"="`+entry+`"`) || !strings.Contains(p.WindowsReg, `Policies\Microsoft\Edge\ExtensionInstallForcelist`) ||
		!strings.Contains(p.WindowsReg, `Policies\Google\Chrome\ExtensionInstallForcelist`) {
		t.Fatalf("reg:\n%s", p.WindowsReg)
	}
	var linux map[string][]string
	if err := json.Unmarshal([]byte(p.LinuxJSON), &linux); err != nil || len(linux["ExtensionInstallForcelist"]) != 1 || linux["ExtensionInstallForcelist"][0] != entry {
		t.Fatalf("linux %q: %v", p.LinuxJSON, err)
	}
	dec := xml.NewDecoder(strings.NewReader(p.MacOSMobileconfig))
	dec.Strict = true
	for {
		if _, err := dec.Token(); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("mobileconfig is not well-formed XML: %v", err)
		}
	}
	for _, want := range []string{"com.google.Chrome", "com.microsoft.Edge", entry} {
		if !strings.Contains(p.MacOSMobileconfig, want) {
			t.Fatalf("mobileconfig lacks %q", want)
		}
	}
	// Stable across calls: a re-downloaded profile replaces the installed
	// one instead of adding a second.
	if saasForcelistPolicies(id, url).MacOSMobileconfig != p.MacOSMobileconfig {
		t.Fatal("profile UUIDs are not stable")
	}
}

// What the agent publishes is decoded through the protocol type, so a
// field outside it (a URL a broken extension added) never reaches storage.
func TestSaaSSnapshotNormalizationDropsUnknownFields(t *testing.T) {
	raw := json.RawMessage(`{"batch_id":"abcdefgh","aggregates":[{"app":"slack","url":"https://slack.com/archives/secret","navigations":1}]}`)
	out, err := normalizeSnapshotData(proto.SensorSaaS, raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "secret") || strings.Contains(string(out), `"url"`) {
		t.Fatalf("normalized data kept an unknown field: %s", out)
	}
	if _, err := normalizeSnapshotData(proto.SensorSaaS, json.RawMessage(`{"aggregates":"nope"}`)); err == nil {
		t.Fatal("a mistyped report was accepted")
	}
}

func TestSaaSSlugAndOrdering(t *testing.T) {
	if got := saasSlug("Jira & Confluence (Cloud)"); got != "jira-confluence-cloud" {
		t.Fatalf("slug %q", got)
	}
	ten, fifty := 10, 50
	rows := []saasAppScore{{Name: "b"}, {Name: "good"}, {Name: "bad"}, {Name: "a"}}
	rows[1].Score, rows[2].Score = &fifty, &ten
	sortSaaSScores(rows, func(i int) (*int, string) { return rows[i].Score, rows[i].Name })
	var names []string
	for _, r := range rows {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "bad,good,a,b" {
		t.Fatalf("order %v: worst first, unscored last", names)
	}
}

func TestSaaSBucketFor(t *testing.T) {
	for hours, want := range map[int]int{1: 300, 24: 3600, 168: 21600, 720: 86400} {
		if got := saasBucketFor(hours); got != want {
			t.Errorf("%dh: %d, want %d", hours, got, want)
		}
	}
}
