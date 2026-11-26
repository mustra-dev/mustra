package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

func remediationTestServer(t *testing.T) (*Server, *store.Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}, syslog: &syslogSink{}}
	s.auth = auth.New(ctx, st, nil, false, slog.Default())
	return s, st, auth.WithUser(ctx, &store.User{ID: "usr-gallery-test", Username: "gallery-test"})
}

// testEntry is a real gallery entry under an ID of its own, so the test
// can run repeatedly against the same database.
func testEntry(t *testing.T, id string) remediationEntry {
	t.Helper()
	e, err := findRemediation(id)
	if err != nil || e == nil {
		t.Fatalf("no %s in the gallery: %v", id, err)
	}
	c := *e
	c.ID = "test-" + idgen.New("") + "-" + id
	return c
}

func importAs(t *testing.T, s *Server, ctx context.Context, e remediationEntry, req remediationImportRequest) (remediationImportResponse, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/remediations/"+e.ID+"/import", nil).WithContext(ctx)
	return s.importRemediation(r, e, req)
}

// Importing creates one action package and one playbook; importing again
// changes nothing; a newer gallery version is published to the same
// package and the playbook runs it; a deleted playbook is re-created.
func TestRemediationImportIsIdempotent(t *testing.T) {
	s, st, ctx := remediationTestServer(t)
	e := testEntry(t, "flush-dns")

	first, err := importAs(t, s, ctx, e, remediationImportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "imported" || first.PackageID == "" || first.PlaybookID == "" || first.RevisionID == "" {
		t.Fatalf("first import: %+v", first)
	}
	pkg, err := st.GetSoftwarePackage(ctx, first.PackageID)
	if err != nil || pkg == nil {
		t.Fatal(pkg, err)
	}
	if pkg.Kind != store.KindAction || pkg.DeployRevision != first.RevisionID || !pkg.RequireExplicitTargets ||
		!strings.Contains(pkg.Description, remediationOrigin(e.ID)) {
		t.Fatalf("package: %+v", pkg)
	}
	rev, err := st.GetDeployRevision(ctx, first.RevisionID)
	if err != nil || rev == nil || !rev.Published || rev.Label != "1" || len(rev.Definition.Variants) != 3 {
		t.Fatalf("revision: %+v %v", rev, err)
	}
	pb, err := st.GetPlaybook(ctx, first.PlaybookID)
	if err != nil || pb == nil {
		t.Fatal(pb, err)
	}
	var steps []playbookStep
	if err := json.Unmarshal(pb.Steps, &steps); err != nil || len(steps) != 1 || steps[0].PackageID != pkg.ID || !steps[0].FollowLatest {
		t.Fatalf("playbook steps: %s", pb.Steps)
	}
	// The playbook is one the editor would save as it stands.
	if _, err := s.validatePlaybookSteps(httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx), steps, pb.OS); err != nil {
		t.Fatalf("imported playbook does not validate: %v", err)
	}

	again, err := importAs(t, s, ctx, e, remediationImportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != "unchanged" || again.PackageID != first.PackageID || again.PlaybookID != first.PlaybookID || again.RevisionID != first.RevisionID {
		t.Fatalf("second import was not a no-op: %+v vs %+v", again, first)
	}
	if revs, _ := st.ListDeployRevisions(ctx, pkg.ID); len(revs) != 1 {
		t.Fatalf("second import added versions: %d", len(revs))
	}
	if n := countWithOrigin(t, st, ctx, e.ID); n != 2 {
		t.Fatalf("%d packages and playbooks carry the origin, want 1 of each", n)
	}

	// A later release ships version 2.
	e.Version = 2
	upd, err := importAs(t, s, ctx, e, remediationImportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if upd.Status != "updated" || upd.PackageID != first.PackageID || upd.PlaybookID != first.PlaybookID || upd.RevisionID == first.RevisionID {
		t.Fatalf("update: %+v", upd)
	}
	rec, _ := st.GetRemediationImport(ctx, e.ID)
	if rec == nil || rec.Version != 2 {
		t.Fatalf("import record after update: %+v", rec)
	}
	if err := s.freezePlaybookRevisions(ctx, steps, pb.OS); err != nil || steps[0].RevisionID != upd.RevisionID {
		t.Fatalf("the playbook does not run the new version: %v %s", err, steps[0].RevisionID)
	}

	// The playbook was deleted: importing again re-creates it, and only it.
	if err := st.DeletePlaybook(ctx, first.PlaybookID); err != nil {
		t.Fatal(err)
	}
	back, err := importAs(t, s, ctx, e, remediationImportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if back.Status != "imported" || back.PackageID != first.PackageID || back.PlaybookID == "" || back.PlaybookID == first.PlaybookID {
		t.Fatalf("re-import after the playbook was deleted: %+v", back)
	}
	t.Cleanup(func() { _ = st.DeletePlaybook(context.Background(), back.PlaybookID) })
}

func countWithOrigin(t *testing.T, st *store.Store, ctx context.Context, id string) int {
	t.Helper()
	n := 0
	pkgs, err := st.ListSoftwarePackages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if strings.Contains(p.Description, remediationOrigin(id)) {
			n++
		}
	}
	pbs, err := st.ListPlaybooks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pbs {
		if strings.Contains(p.Description, remediationOrigin(id)) {
			n++
		}
	}
	return n
}

// A playbook runs without asking, so a required parameter has to be given
// at import, and a bad request leaves nothing behind. The Run path
// (package_only) needs no inputs: the deploy window asks for them.
func TestRemediationImportChecksInputsFirst(t *testing.T) {
	s, st, ctx := remediationTestServer(t)
	e := testEntry(t, "restart-service")

	for name, req := range map[string]remediationImportRequest{
		"missing required parameter": {},
		"unknown parameter":          {Params: map[string]string{"service": "cups", "nope": "x"}},
		"no such group":              {GroupID: "cgrp-does-not-exist", Params: map[string]string{"service": "cups"}},
	} {
		if _, err := importAs(t, s, ctx, e, req); err == nil {
			t.Errorf("%s: accepted", name)
		} else if _, ok := err.(errRemediationInput); !ok {
			t.Errorf("%s: %v is not reported as the caller's mistake", name, err)
		}
	}
	if n := countWithOrigin(t, st, ctx, e.ID); n != 0 {
		t.Fatalf("refused imports left %d objects behind", n)
	}

	run, err := importAs(t, s, ctx, e, remediationImportRequest{PackageOnly: true})
	if err != nil || run.Status != "imported" || run.PackageID == "" || run.PlaybookID != "" {
		t.Fatalf("package-only import: %+v %v", run, err)
	}
	g, err := st.UpsertComputerGroup(ctx, store.ComputerGroup{ID: idgen.New("cgrp-"), Name: "gallery test " + e.ID, Kind: "static", MatchMode: "all"})
	if err != nil {
		t.Fatal(err)
	}
	full, err := importAs(t, s, ctx, e, remediationImportRequest{GroupID: g.ID, Params: map[string]string{"service": "cups"}})
	if err != nil || full.Status != "imported" || full.PackageID != run.PackageID || full.PlaybookID == "" {
		t.Fatalf("playbook import after package-only: %+v %v", full, err)
	}
	pb, _ := st.GetPlaybook(ctx, full.PlaybookID)
	var steps []playbookStep
	if pb != nil {
		_ = json.Unmarshal(pb.Steps, &steps)
	}
	if pb == nil || pb.GroupID != g.ID || len(steps) != 1 || steps[0].Params["service"] != "cups" {
		t.Fatalf("playbook: %+v", pb)
	}
	t.Cleanup(func() { _ = st.DeletePlaybook(context.Background(), full.PlaybookID) })
}

// Through the routes as registered: without deploy.manage the gallery is
// refused before any handler runs.
func TestRemediationRoutesRefuseWithoutDeployManage(t *testing.T) {
	s, st, ctx := remediationTestServer(t)
	s.routes()
	newUser := func(perms ...string) *store.User {
		u, err := st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("gallery-"), "", "gallery test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteUser(context.Background(), u.ID) })
		role, err := st.CreateRole(ctx, idgen.New("role-"), idgen.New("gallery-role-"), "", perms, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteRole(context.Background(), role.ID) })
		if err := st.AssignUserRole(ctx, u.ID, role.ID); err != nil {
			t.Fatal(err)
		}
		return u
	}
	reader := newUser(auth.PermFleetRead)
	operator := newUser(auth.PermFleetRead, auth.PermDeployManage)
	call := func(u *store.User, method, pattern, path string) int {
		for _, e := range s.routeLog.entries {
			if e.Pattern != pattern {
				continue
			}
			req := httptest.NewRequest(method, path, nil).WithContext(auth.WithUser(context.Background(), u))
			req.SetPathValue("id", "no-such-remediation")
			rec := httptest.NewRecorder()
			e.Handler.ServeHTTP(rec, req)
			return rec.Code
		}
		t.Fatalf("%s is not registered", pattern)
		return 0
	}
	for _, c := range []struct{ method, pattern, path string }{
		{"GET", "GET /api/remediations", "/api/remediations"},
		{"POST", "POST /api/remediations/{id}/import", "/api/remediations/no-such-remediation/import"},
	} {
		if got := call(reader, c.method, c.pattern, c.path); got != http.StatusForbidden {
			t.Errorf("%s without deploy.manage: %d, want 403", c.pattern, got)
		}
	}
	if got := call(operator, "GET", "GET /api/remediations", "/api/remediations"); got != http.StatusOK {
		t.Errorf("list with deploy.manage: %d", got)
	}
	if got := call(operator, "POST", "POST /api/remediations/{id}/import", "/api/remediations/no-such-remediation/import"); got != http.StatusNotFound {
		t.Errorf("import of an unknown entry with deploy.manage: %d, want 404", got)
	}
}
