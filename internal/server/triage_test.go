package server

import (
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

var triageFleet = []store.EndpointIdentity{
	{AgentID: "agt-web01", Hostname: "web-01.corp.example", Serial: "SN-WEB-01"},
	{AgentID: "agt-web02", Hostname: "web-02", Serial: "SN-WEB-02"},
	// Two machines that report the same hostname: a reimage that kept its
	// name, or a lab copy.
	{AgentID: "agt-dup-a", Hostname: "FIN-LT-0142", Serial: "SN-A"},
	{AgentID: "agt-dup-b", Hostname: "fin-lt-0142", Serial: "SN-B"},
	// Firmware with no serial set.
	{AgentID: "agt-oem1", Hostname: "kiosk-1", Serial: "To Be Filled By O.E.M."},
	{AgentID: "agt-oem2", Hostname: "kiosk-2", Serial: "To Be Filled By O.E.M."},
}

// An endpoint is attached only when the source's identifiers agree on
// exactly one. Anything else leaves the item unattached, with the
// candidates named and the reason given: never a guess.
func TestResolveTriageEndpoint(t *testing.T) {
	cases := []struct {
		name       string
		ref        triageEndpointRef
		want       string
		candidates []string
		note       string
	}{
		{name: "agent id", ref: triageEndpointRef{AgentID: "agt-web02"}, want: "agt-web02", note: "matched by agent ID"},
		{name: "hostname ignores case", ref: triageEndpointRef{Hostname: "WEB-02"}, want: "agt-web02"},
		{name: "short hostname finds the FQDN", ref: triageEndpointRef{Hostname: "web-01"}, want: "agt-web01"},
		{name: "FQDN finds the short name", ref: triageEndpointRef{Hostname: "web-02.corp.example"}, want: "agt-web02"},
		{name: "serial", ref: triageEndpointRef{Serial: "sn-web-01"}, want: "agt-web01", note: "matched by serial number"},
		{name: "hostname and serial agree", ref: triageEndpointRef{Hostname: "web-01", Serial: "SN-WEB-01"}, want: "agt-web01",
			note: "matched by serial number and hostname"},
		{name: "ambiguous hostname", ref: triageEndpointRef{Hostname: "fin-lt-0142"},
			candidates: []string{"agt-dup-a", "agt-dup-b"}, note: `hostname "fin-lt-0142" matches 2 endpoints; choose one`},
		{name: "serial settles an ambiguous hostname", ref: triageEndpointRef{Hostname: "FIN-LT-0142", Serial: "SN-B"}, want: "agt-dup-b"},
		{name: "identifiers disagree", ref: triageEndpointRef{Hostname: "web-02", Serial: "SN-WEB-01"},
			candidates: []string{"agt-web01", "agt-web02"}, note: "the identifiers name different endpoints"},
		{name: "agent id and hostname disagree", ref: triageEndpointRef{AgentID: "agt-web01", Hostname: "web-02"},
			candidates: []string{"agt-web01", "agt-web02"}},
		{name: "nothing matches", ref: triageEndpointRef{Hostname: "db-09"}, note: `no endpoint matched: no endpoint has hostname "db-09"`},
		{name: "a stale identifier is reported, not trusted", ref: triageEndpointRef{AgentID: "agt-gone", Hostname: "web-02"},
			want: "agt-web02", note: `no endpoint has agent ID "agt-gone"`},
		{name: "placeholder serial is ignored", ref: triageEndpointRef{Serial: "To be filled by O.E.M."},
			note: "firmware placeholder"},
		{name: "placeholder serial does not join kiosks", ref: triageEndpointRef{Serial: "To be filled by O.E.M.", Hostname: "kiosk-2"},
			want: "agt-oem2"},
		{name: "no identifiers", ref: triageEndpointRef{}, note: "did not name an endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, note, cands := resolveTriageEndpoint(triageFleet, tc.ref)
			if got != tc.want {
				t.Fatalf("endpoint = %q (%s), want %q", got, note, tc.want)
			}
			if tc.note != "" && !strings.Contains(note, tc.note) {
				t.Errorf("note = %q, want it to contain %q", note, tc.note)
			}
			var ids []string
			for _, c := range cands {
				ids = append(ids, c.AgentID)
			}
			if strings.Join(ids, ",") != strings.Join(tc.candidates, ",") {
				t.Errorf("candidates = %v, want %v", ids, tc.candidates)
			}
		})
	}
}

func TestTriageTransitions(t *testing.T) {
	allowed := [][2]string{
		{"new", "in_progress"}, {"new", "waiting"}, {"new", "resolved"},
		{"in_progress", "waiting"}, {"in_progress", "resolved"}, {"in_progress", "new"},
		{"waiting", "in_progress"}, {"waiting", "resolved"},
		{"resolved", "in_progress"},
	}
	refused := [][2]string{
		{"resolved", "new"}, {"resolved", "waiting"}, {"waiting", "new"},
		{"new", "new"}, {"new", "closed"}, {"", "new"},
	}
	for _, p := range allowed {
		if !triageTransitionAllowed(p[0], p[1]) {
			t.Errorf("%s → %s refused", p[0], p[1])
		}
	}
	for _, p := range refused {
		if triageTransitionAllowed(p[0], p[1]) {
			t.Errorf("%s → %s allowed", p[0], p[1])
		}
	}
	for from, tos := range triageTransitions {
		if triageStatuses[from] == "" {
			t.Errorf("transition from unknown status %q", from)
		}
		for _, to := range tos {
			if triageStatuses[to] == "" {
				t.Errorf("transition to unknown status %q", to)
			}
		}
	}
}

func TestTriageAlertAgent(t *testing.T) {
	for link, want := range map[string]string{
		"/endpoint/agt-1":            "agt-1",
		"/endpoint/agt-1#privileges": "agt-1",
		"/endpoint/agt-1?tab=x":      "agt-1",
		"/agents#overview":           "",
		"/deploy?job=x#jobs":         "",
		"":                           "",
	} {
		if got := triageAlertAgent(link); got != want {
			t.Errorf("triageAlertAgent(%q) = %q, want %q", link, got, want)
		}
	}
}

// A ServiceNow reference becomes part of a URL on the instance, so only a
// sys_id and a plain table name are accepted.
func TestCheckServiceNowRef(t *testing.T) {
	ok := "9d385017c611228701d22104cc95c371"
	if err := checkServiceNowRef(ok, ""); err != nil {
		t.Fatal(err)
	}
	if err := checkServiceNowRef(ok, "sc_req_item"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{"INC0010023", ""}, {ok + "/../x", ""}, {ok, "incident/../sys_user"}, {ok, "Incident"}, {"", ""}} {
		if err := checkServiceNowRef(bad[0], bad[1]); err == nil {
			t.Errorf("accepted %q in %q", bad[0], bad[1])
		}
	}
}

// Every source the queue accepts has a label, and the alert source has its
// own way in (the Guide), not the inbound API.
func TestTriageSources(t *testing.T) {
	for _, src := range []string{"servicenow", "self_service", "alert", "api", "manual"} {
		if triageSources[src].Label == "" {
			t.Errorf("source %q has no label", src)
		}
	}
	if triageSources["alert"].Inbound {
		t.Error("alerts must come from the Guide, not the inbound API")
	}
}

// Reading the queue is fleet.read; every change to it, filing through the
// API included, is alerts.triage. (A fix also passes the permission check
// of the route it runs: TestTriageFixThenSimilar.)
func TestTriageRoutePermissions(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	seen := 0
	for _, e := range s.routeLog.entries {
		if !strings.Contains(e.Pattern, "/api/triage/") && e.Pattern != "POST /api/guide/{id}/triage" {
			continue
		}
		seen++
		pg, ok := e.Handler.(*permGuard)
		if !ok {
			t.Errorf("%s has no permission check", e.Pattern)
			continue
		}
		want := auth.PermAlertsTriage
		if strings.HasPrefix(e.Pattern, "GET ") {
			want = auth.PermFleetRead
		}
		if !slices.Equal(pg.perms, []string{want}) {
			t.Errorf("%s needs %v, want %s", e.Pattern, pg.perms, want)
		}
	}
	if seen != 11 {
		t.Errorf("found %d triage routes, want 11", seen)
	}
}
