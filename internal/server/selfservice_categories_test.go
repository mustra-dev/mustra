package server

import (
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/selfservice"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Reading categories is reading the catalog; changing them changes what
// every endpoint's window shows, so it takes deploy.manage.
func TestSelfServiceCategoryRoutePermissions(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	want := map[string]string{
		"GET /api/selfservice/categories":         auth.PermFleetRead,
		"POST /api/selfservice/categories":        auth.PermDeployManage,
		"PUT /api/selfservice/categories/order":   auth.PermDeployManage,
		"PUT /api/selfservice/categories/{id}":    auth.PermDeployManage,
		"DELETE /api/selfservice/categories/{id}": auth.PermDeployManage,
	}
	found := map[string]bool{}
	for _, e := range s.routeLog.entries {
		perm, ok := want[e.Pattern]
		if !ok {
			continue
		}
		found[e.Pattern] = true
		pg, guarded := e.Handler.(*permGuard)
		if !guarded {
			t.Errorf("%s is not behind a permission check", e.Pattern)
			continue
		}
		if !slices.Equal(pg.perms, []string{perm}) {
			t.Errorf("%s demands %v, want [%s]", e.Pattern, pg.perms, perm)
		}
	}
	for p := range want {
		if !found[p] {
			t.Errorf("%s is not registered", p)
		}
	}
}

func TestValidSelfServiceCategory(t *testing.T) {
	for _, c := range []struct {
		in   selfServiceCategoryRequest
		fail bool
	}{
		{selfServiceCategoryRequest{Name: "  Design tools ", Icon: "layers"}, false},
		{selfServiceCategoryRequest{Name: "Browsers"}, false},
		{selfServiceCategoryRequest{Name: "   "}, true},
		{selfServiceCategoryRequest{Name: "all"}, true},
		{selfServiceCategoryRequest{Name: "Other"}, true},
		{selfServiceCategoryRequest{Name: "Two\nlines"}, true},
		{selfServiceCategoryRequest{Name: strings.Repeat("x", 41)}, true},
		{selfServiceCategoryRequest{Name: strings.Repeat("é", 40)}, false},
		{selfServiceCategoryRequest{Name: "Tools", Icon: "not-an-icon"}, true},
		{selfServiceCategoryRequest{Name: "Tools", Icon: "<svg onload=x>"}, true},
	} {
		got, err := validSelfServiceCategory(c.in)
		if (err != nil) != c.fail {
			t.Errorf("%+v: error %v, want failure %v", c.in, err, c.fail)
		}
		if err == nil && got.Name != strings.TrimSpace(c.in.Name) {
			t.Errorf("%+v: name %q was not trimmed", c.in, got.Name)
		}
	}
}

// The window files items in the operator's order, ignores categories
// deleted since a package named them, and is told only about categories
// something is in.
func TestCategoryFiler(t *testing.T) {
	f := newCategoryFiler([]store.SelfServiceCategory{
		{ID: "a", Name: "Browsers", Icon: "globe"},
		{ID: "b", Name: "Productivity"},
		{ID: "c", Name: "Security", Icon: "shield"},
	})
	ids, first := f.file([]string{"c", "gone", "a", "c"})
	if !slices.Equal(ids, []string{"a", "c"}) || first != "Browsers" {
		t.Fatalf("filed under %v (%q), want [a c] (Browsers)", ids, first)
	}
	if ids, first := f.file([]string{"gone"}); ids != nil || first != "" {
		t.Fatalf("a package in only a deleted category was filed under %v (%q)", ids, first)
	}
	if ids, first := f.file(nil); ids != nil || first != "" {
		t.Fatalf("an unfiled package was filed under %v (%q)", ids, first)
	}
	used := f.used()
	if len(used) != 2 || used[0].ID != "a" || used[1].ID != "c" || used[1].Icon != "shield" {
		t.Fatalf("used %+v, want Browsers then Security", used)
	}
}

// The icons a category may carry are drawn by the console (app.js) and by
// the endpoint window, which carries its own copy of the paths because it
// cannot load the console's scripts. Each must exist in both, identically.
func TestSelfServiceCategoryIconsMatchEverywhere(t *testing.T) {
	appJS, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	window := string(selfservice.HTML())
	paths := func(src, block string) map[string]string {
		start := strings.Index(src, block)
		if start < 0 {
			t.Fatalf("no %q", block)
		}
		end := strings.Index(src[start:], "\n};")
		out := map[string]string{}
		for _, m := range regexp.MustCompile(`(?m)^\s*([a-z]+):\s*'([^']*)',`).FindAllStringSubmatch(src[start:start+end], -1) {
			out[m[1]] = m[2]
		}
		return out
	}
	console := paths(string(appJS), "const ICON_PATHS = {")
	endpoint := paths(window, "const CAT_ICONS = {")
	for _, name := range selfServiceCategoryIcons {
		switch {
		case console[name] == "":
			t.Errorf("icon %q is not in app.js ICON_PATHS", name)
		case endpoint[name] == "":
			t.Errorf("icon %q is not in window.html CAT_ICONS", name)
		case console[name] != endpoint[name]:
			t.Errorf("icon %q draws differently in the console and the window", name)
		}
	}
	// The defaults the schema creates use icons from the list.
	for _, name := range []string{"globe", "book", "chat", "terminal", "sliders", "shield"} {
		if !knownCategoryIcon(name) {
			t.Errorf("default icon %q is not offered", name)
		}
	}
}
