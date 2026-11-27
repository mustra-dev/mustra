package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Who may do what with Apple MDM, as registered: reading is fleet.read,
// setup is settings.manage, commands are deploy.manage behind the
// endpoint-action gate (module "mdm"), a lock or erase PIN is
// enforce.recovery_keys like a recovery key.
func TestMDMRoutePermissions(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	want := map[string]string{
		"GET /api/mdm/settings":                                auth.PermSettingsManage,
		"PUT /api/mdm/settings":                                auth.PermSettingsManage,
		"POST /api/mdm/push-csr":                               auth.PermSettingsManage,
		"POST /api/mdm/push-certificate":                       auth.PermSettingsManage,
		"POST /api/mdm/ca":                                     auth.PermSettingsManage,
		"PUT /api/mdm/signing-identity":                        auth.PermSettingsManage,
		"DELETE /api/mdm/signing-identity":                     auth.PermSettingsManage,
		"GET /api/mdm/enroll-tokens":                           auth.PermDeployManage,
		"POST /api/mdm/enroll-tokens":                          auth.PermDeployManage,
		"DELETE /api/mdm/enroll-tokens/{id}":                   auth.PermDeployManage,
		"GET /api/mdm/devices":                                 auth.PermFleetRead,
		"GET /api/mdm/devices/{id}":                            auth.PermFleetRead,
		"POST /api/mdm/devices/{id}/commands":                  auth.PermDeployManage,
		"POST /api/mdm/devices/{id}/commands/{command}/cancel": auth.PermDeployManage,
		"DELETE /api/mdm/devices/{id}":                         auth.PermDeployManage,
		"POST /api/mdm/commands/{id}/reveal-pin":               auth.PermRecoveryKeys,
		"GET /api/mdm/profiles":                                auth.PermDeployManage,
		"POST /api/mdm/profiles":                               auth.PermDeployManage,
		"GET /api/mdm/profiles/{id}/download":                  auth.PermDeployManage,
		"DELETE /api/mdm/profiles/{id}":                        auth.PermDeployManage,
		"GET /mdm":                                             auth.PermFleetRead,
	}
	seen := map[string]bool{}
	for _, e := range s.routeLog.entries {
		perm, ok := want[e.Pattern]
		if !ok {
			continue
		}
		seen[e.Pattern] = true
		pg, guarded := e.Handler.(*permGuard)
		if !guarded || len(pg.perms) != 1 || pg.perms[0] != perm {
			t.Errorf("%s: guarded by %v, want %s", e.Pattern, pg, perm)
			continue
		}
		_, gated := pg.next.(*actionGate)
		if wantGate := e.Pattern == mdmCommandRoute || e.Pattern == "DELETE /api/mdm/devices/{id}"; gated != wantGate {
			t.Errorf("%s: behind the action gate = %v, want %v", e.Pattern, gated, wantGate)
		}
	}
	for p := range want {
		if !seen[p] {
			t.Errorf("%s is not registered", p)
		}
	}
	if spec := s.endpointActionRoutes()[mdmCommandRoute]; spec.Module != "mdm" {
		t.Errorf("MDM commands are gated under module %q, want mdm", spec.Module)
	}
	if !validModule("mdm") {
		t.Error("mdm is not a module approval policies and action groups can name")
	}
	if _, ok := s.replayable()[mdmCommandRoute]; !ok {
		t.Error("an approved lock or erase has no handler to replay through")
	}
}

// With the MDM off (here: no store at all), the device endpoints answer
// as if the feature did not exist.
func TestMDMDeviceEndpointsAbsentWhenOff(t *testing.T) {
	s := &Server{logger: slog.Default()}
	h := s.routes()
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/mdm/enroll/mdm_abc"},
		{http.MethodPut, "/mdm/checkin"},
		{http.MethodPut, "/mdm/connect"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader(authenticatePlist("0000FE00-AAAA-BBBB-CCCC-000000000001", "x"))))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s with the MDM off: %d, want 404", c.method, c.path, rec.Code)
		}
	}
}

func authenticatePlist(udid, topic string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>MessageType</key><string>Authenticate</string><key>Topic</key><string>` + topic + `</string>
<key>UDID</key><string>` + udid + `</string><key>SerialNumber</key><string>C02TESTSERIAL</string>
<key>Model</key><string>Mac14,2</string><key>ModelName</key><string>MacBook Air</string>
<key>OSVersion</key><string>15.1</string><key>BuildVersion</key><string>24B83</string><key>DeviceName</key><string>test-mac</string>
</dict></plist>`
}
