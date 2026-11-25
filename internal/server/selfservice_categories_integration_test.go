package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// What an endpoint's window is told: each offered package's categories in
// the operator's order, only the categories something offered is in, and
// the first category's name for windows that read one string.
func TestSelfServiceStateFilesItemsUnderCategories(t *testing.T) {
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

	agent := idgen.New("agt-")
	if err := st.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: "cat-state-" + agent, OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), agent) })

	cat := func(name string) string {
		t.Helper()
		c, err := st.CreateSelfServiceCategory(ctx, store.SelfServiceCategory{ID: idgen.New("sscat-test-"), Name: idgen.New(name + " "), Icon: "star"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = st.DeleteSelfServiceCategory(context.Background(), c.ID) })
		return c.ID
	}
	first, second, unused := cat("First"), cat("Second"), cat("Unused")
	pkg := func(name string, cats []string) string {
		t.Helper()
		p, err := st.UpsertSoftwarePackage(ctx, store.SoftwarePackage{
			ID: idgen.New("sw-catstate-"), Name: name, Enabled: true, SelfService: true, CategoryIDs: cats,
			Commands: map[string]store.SoftwareOps{"linux": {Install: "apt-get install -y " + name}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteSoftwarePackage(context.Background(), p.ID) })
		return p.ID
	}
	both := pkg(idgen.New("both"), []string{second, first})
	plain := pkg(idgen.New("plain"), nil)

	reply := s.selfServiceState(ctx, agent)
	if reply.Error != "" {
		t.Fatal(reply.Error)
	}
	byID := map[string]proto.SelfServiceItem{}
	for _, it := range reply.Items {
		byID[it.ID] = it
	}
	b, p := byID[both], byID[plain]
	if !slices.Equal(b.CategoryIDs, []string{first, second}) {
		t.Errorf("filed under %v, want the list's order %v", b.CategoryIDs, []string{first, second})
	}
	if names := categoryNames(reply.Categories); b.Category == "" || b.Category != names[first] {
		t.Errorf("an older window would read category %q, want the first category's name", b.Category)
	}
	if p.ID == "" || p.CategoryIDs != nil || p.Category != "" {
		t.Errorf("an unfiled package: %+v", p)
	}
	ids := map[string]bool{}
	for _, c := range reply.Categories {
		ids[c.ID] = true
	}
	if !ids[first] || !ids[second] || ids[unused] {
		t.Errorf("the reply lists %v; it should carry the used categories and not the unused one", reply.Categories)
	}
}

func categoryNames(cats []proto.SelfServiceCategory) map[string]string {
	out := map[string]string{}
	for _, c := range cats {
		out[c.ID] = c.Name
	}
	return out
}

// A package's details save files it under categories: each must exist, a
// save that leaves category_ids out (an older console, a script) keeps
// what the package had, and an empty list files it under none.
func TestDeployPackageMetadataCategories(t *testing.T) {
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
	s := &Server{logger: slog.Default(), store: st, syslog: &syslogSink{}}
	c, err := st.CreateSelfServiceCategory(ctx, store.SelfServiceCategory{ID: idgen.New("sscat-test-"), Name: idgen.New("Meta ")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.DeleteSelfServiceCategory(context.Background(), c.ID) })
	p, err := st.UpsertSoftwarePackage(ctx, store.SoftwarePackage{ID: idgen.New("sw-catmeta-"), Name: "Meta test",
		Commands: map[string]store.SoftwareOps{"linux": {Install: "true"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteSoftwarePackage(context.Background(), p.ID) })

	put := func(body string) int {
		t.Helper()
		req := httptest.NewRequest("PUT", "/api/deploy/packages/"+p.ID, strings.NewReader(body))
		req.SetPathValue("id", p.ID)
		req = req.WithContext(auth.WithUser(req.Context(), &store.User{ID: "u", Username: "u", IsAdmin: true}))
		rec := httptest.NewRecorder()
		s.handleDeployPackageMetadata(rec, req)
		return rec.Code
	}
	filed := func() []string {
		t.Helper()
		got, err := st.GetSoftwarePackage(ctx, p.ID)
		if err != nil || got == nil {
			t.Fatal(got, err)
		}
		return got.CategoryIDs
	}
	if code := put(`{"name": "Meta test", "category_ids": ["` + c.ID + `", "` + c.ID + `"]}`); code != 200 {
		t.Fatalf("status %d", code)
	}
	if got := filed(); !slices.Equal(got, []string{c.ID}) {
		t.Fatalf("filed under %v, want [%s] once", got, c.ID)
	}
	if code := put(`{"name": "Meta test"}`); code != 200 || !slices.Equal(filed(), []string{c.ID}) {
		t.Fatalf("a save without category_ids: status %d, filed under %v", code, filed())
	}
	if code := put(`{"name": "Meta test", "category_ids": ["sscat-does-not-exist"]}`); code != 400 || !slices.Equal(filed(), []string{c.ID}) {
		t.Fatalf("an unknown category: status %d, filed under %v", code, filed())
	}
	if code := put(`{"name": "Meta test", "category_ids": []}`); code != 200 || len(filed()) != 0 {
		t.Fatalf("an empty list: status %d, filed under %v", code, filed())
	}
}

// The category routes against a real store: create, a duplicate name, a
// reorder that leaves one out, and a delete.
func TestSelfServiceCategoryHandlers(t *testing.T) {
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
	s := &Server{logger: slog.Default(), store: st, syslog: &syslogSink{}}
	call := func(h func(w http.ResponseWriter, r *http.Request), method, id, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/selfservice/categories", strings.NewReader(body))
		if id != "" {
			req.SetPathValue("id", id)
		}
		req = req.WithContext(auth.WithUser(req.Context(), &store.User{ID: "u", Username: "cat-tester", IsAdmin: true}))
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	name := idgen.New("Handler ")
	rec := call(s.handleCreateSelfServiceCategory, "POST", "", `{"name": "  `+name+`  ", "icon": "rocket"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var c store.SelfServiceCategory
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || c.Name != name || c.Icon != "rocket" || c.CreatedBy != "cat-tester" {
		t.Fatalf("created %+v %v", c, err)
	}
	t.Cleanup(func() { _, _ = st.DeleteSelfServiceCategory(context.Background(), c.ID) })
	if rec := call(s.handleCreateSelfServiceCategory, "POST", "", `{"name": "`+strings.ToUpper(name)+`"}`); rec.Code != 409 {
		t.Errorf("a duplicate name: %d %s", rec.Code, rec.Body)
	}
	if rec := call(s.handleUpdateSelfServiceCategory, "PUT", "sscat-missing", `{"name": "x"}`); rec.Code != 404 {
		t.Errorf("renaming nothing: %d", rec.Code)
	}
	if rec := call(s.handleUpdateSelfServiceCategory, "PUT", c.ID, `{"name": "`+name+`", "icon": "javascript:"}`); rec.Code != 400 {
		t.Errorf("an unknown icon: %d", rec.Code)
	}
	if rec := call(s.handleReorderSelfServiceCategories, "PUT", "", `{"ids": ["`+c.ID+`"]}`); rec.Code != 409 {
		t.Errorf("an order missing categories: %d %s", rec.Code, rec.Body)
	}
	var list selfServiceCategoriesResponse
	rec = call(s.handleListSelfServiceCategories, "GET", "", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Icons) == 0 {
		t.Fatalf("list: %v %s", err, rec.Body)
	}
	ids := []string{c.ID}
	for _, x := range list.Categories {
		if x.ID != c.ID {
			ids = append(ids, x.ID)
		}
	}
	raw, _ := json.Marshal(map[string]any{"ids": ids})
	rec = call(s.handleReorderSelfServiceCategories, "PUT", "", string(raw))
	if err := json.Unmarshal(rec.Body.Bytes(), &list); rec.Code != 200 || err != nil || list.Categories[0].ID != c.ID {
		t.Fatalf("reorder: %d %s", rec.Code, rec.Body)
	}
	if rec := call(s.handleDeleteSelfServiceCategory, "DELETE", c.ID, ""); rec.Code != 204 {
		t.Errorf("delete: %d", rec.Code)
	}
	if rec := call(s.handleDeleteSelfServiceCategory, "DELETE", c.ID, ""); rec.Code != 404 {
		t.Errorf("delete again: %d", rec.Code)
	}
}
