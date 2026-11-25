package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/enforcekinds"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// An Ansible playbook runs operator code on endpoints, so writing one --
// saving it, or compiling it for the preview -- needs deploy.manage, like
// every other Enforce policy. Reading results does not.
func TestAnsiblePolicyWritesNeedDeployManage(t *testing.T) {
	s := &Server{logger: slog.Default(), syslog: &syslogSink{}}
	s.routes()
	handlers := map[string]http.Handler{}
	for _, e := range s.routeLog.entries {
		handlers[e.Pattern] = e.Handler
	}
	body := `{"name":"baseline","kind":"ansible","mode":"enforce","config":{"playbook":"- hosts: localhost\n  tasks: []\n"}}`
	tokenUser := &store.User{ID: auth.APITokenUserID, Username: "token:t", Active: true}
	for _, pattern := range []string{"POST /api/enforce/policies", "PUT /api/enforce/policies/{id}", "POST /api/enforce/compile"} {
		h, ok := handlers[pattern]
		if !ok {
			t.Fatalf("%s is not registered", pattern)
		}
		pg, ok := h.(*permGuard)
		if !ok || len(pg.perms) != 1 || pg.perms[0] != auth.PermDeployManage {
			t.Errorf("%s: not gated on exactly deploy.manage", pattern)
			continue
		}
		// Every other permission an operator might hold is not enough.
		for _, perm := range []string{auth.PermSettingsManage, auth.PermRecoveryKeys} {
			req := httptest.NewRequest("POST", "/api/enforce/policies", strings.NewReader(body))
			req.SetPathValue("id", "enf-1")
			ctx := auth.WithToken(auth.WithUser(req.Context(), tokenUser), []string{perm}, &auth.TokenInfo{ID: "tok-1"})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s with %s only: %d, want 403", pattern, perm, rec.Code)
			}
		}
	}
}

// A playbook reaches endpoints only through the Ansible type, which is
// what validated it. The checks run before anything is stored.
func TestSaveEnforcePolicyRefusesUncheckedPlaybooks(t *testing.T) {
	s := &Server{logger: slog.Default()}
	for name, c := range map[string]struct{ body, want string }{
		"playbook in a custom setting": {
			`{"name":"sneaky","os":"linux","settings":[{"name":"x","rules":["p:init"],"ansible":{"playbook":"- hosts: db\n"}}]}`,
			"Ansible playbook policy"},
		"playbook that is not YAML": {
			`{"name":"broken","kind":"ansible","config":{"playbook":"- hosts: localhost\n  tasks: [\n"}}`,
			"not valid YAML"},
		"play for other hosts": {
			`{"name":"web","kind":"ansible","config":{"playbook":"- hosts: webservers\n  tasks: []\n"}}`,
			"webservers"},
	} {
		req := httptest.NewRequest("POST", "/api/enforce/policies", strings.NewReader(c.body))
		req = req.WithContext(auth.WithUser(req.Context(), &store.User{ID: "u", Username: "op", IsAdmin: true}))
		rec := httptest.NewRecorder()
		s.handleSaveEnforcePolicy(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %q, want 400 mentioning %q", name, rec.Code, rec.Body.String(), c.want)
		}
	}
}

// The playbook is the fix, so an Ansible policy may be saved in enforce
// mode although it has no remediation command.
func TestAnsibleSettingCountsAsFixableOnLinux(t *testing.T) {
	settings, err := enforcekinds.Compile(enforcekinds.KindAnsible, []byte(`{"playbook":"- hosts: localhost\n  tasks: []\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateEnforceSettings(settings, "enforce", "linux"); err != nil {
		t.Errorf("enforce on linux refused: %v", err)
	}
	if _, err := validateEnforceSettings([]proto.EnforceSetting{settings[0]}, "enforce", "windows"); err == nil {
		t.Error("a playbook cannot fix a Windows endpoint, so enforce on windows must be refused")
	}
}
