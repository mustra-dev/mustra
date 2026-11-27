package server

import (
	"log/slog"
	"slices"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Reading anomalies is reading the fleet; acknowledging and suppressing
// hide them from everyone's ranked list, so they take triage rights (or
// settings.manage, as dismissing a Guide item does), never fleet.read
// alone.
func TestAnomalyRoutePermissions(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	want := map[string][]string{
		"GET /api/anomalies":                      {auth.PermFleetRead},
		"GET /api/anomalies/{id}":                 {auth.PermFleetRead},
		"GET /api/anomalies/suppressions":         {auth.PermFleetRead},
		"GET /anomalies":                          {auth.PermFleetRead},
		"POST /api/anomalies/ack":                 {auth.PermAlertsTriage, auth.PermSettingsManage},
		"POST /api/anomalies/suppressions":        {auth.PermAlertsTriage, auth.PermSettingsManage},
		"DELETE /api/anomalies/suppressions/{id}": {auth.PermAlertsTriage, auth.PermSettingsManage},
	}
	seen := map[string]bool{}
	for _, e := range s.routeLog.entries {
		perms, ok := want[e.Pattern]
		if !ok {
			continue
		}
		seen[e.Pattern] = true
		g, guarded := e.Handler.(*permGuard)
		if !guarded || !slices.Equal(g.perms, perms) {
			t.Errorf("%s guarded by %v, want %v", e.Pattern, g, perms)
		}
	}
	for p := range want {
		if !seen[p] {
			t.Errorf("%s is not registered", p)
		}
	}
}
