package store

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
)

// The defaults arrive once. Deleting one is a decision the next start
// must respect, and an upgrade files packages under the free-text
// category they already had.
func TestSelfServiceCategoriesSeedOnce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	reopen := func() {
		t.Helper()
		s2, err := Open(ctx, os.Getenv("MUSTRA_TEST_DEPLOY_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		s2.Close()
	}
	names := func() []string {
		t.Helper()
		cats, err := s.ListSelfServiceCategories(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cats {
			out = append(out, c.Name)
		}
		return out
	}
	// The migration has run on this database; run it again as an upgrade
	// would, from a clean slate.
	reset := func() {
		t.Helper()
		if _, err := s.pool.Exec(ctx, `DELETE FROM settings WHERE key = 'migration.selfservice_categories'`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx, `DELETE FROM selfservice_categories`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(ctx, `UPDATE software_packages SET category_ids = '{}'`); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("an upgrade adds the defaults and files packages by their old category", func(t *testing.T) {
		reset()
		chrome := testPackage(t, s, "Chrome cat test", "browsers") // a default, in another case
		gimp := testPackage(t, s, "GIMP cat test", " Graphics ")
		gimp2 := testPackage(t, s, "Krita cat test", "graphics")
		none := testPackage(t, s, "jq cat test", "")
		reopen()
		got := names()
		want := []string{"Browsers", "Productivity", "Communication", "Developer tools", "Utilities", "Security"}
		if len(got) < len(want)+1 || !slices.Equal(got[:len(want)], want) || !slices.Contains(got, "Graphics") {
			t.Fatalf("categories after upgrade: %v", got)
		}
		check := func(id string, want ...string) {
			t.Helper()
			p, err := s.GetSoftwarePackage(ctx, id)
			if err != nil || p == nil {
				t.Fatal(p, err)
			}
			if !slices.Equal(p.CategoryIDs, want) {
				t.Errorf("%s filed under %v, want %v", p.Name, p.CategoryIDs, want)
			}
		}
		check(chrome, "sscat-browsers")
		var graphics string
		if err := s.pool.QueryRow(ctx, `SELECT id FROM selfservice_categories WHERE name = 'Graphics'`).Scan(&graphics); err != nil {
			t.Fatal(err)
		}
		check(gimp, graphics)
		check(gimp2, graphics)
		check(none)
	})

	t.Run("a deleted default stays deleted", func(t *testing.T) {
		reset()
		reopen()
		ok, err := s.DeleteSelfServiceCategory(ctx, "sscat-security")
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		reopen()
		reopen()
		if slices.Contains(names(), "Security") {
			t.Fatal("a deleted default category came back on the next start")
		}
	})
}

func TestSelfServiceCategoryCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	mk := func(name string) *SelfServiceCategory {
		t.Helper()
		c, err := s.CreateSelfServiceCategory(ctx, SelfServiceCategory{ID: idgen.New("sscat-test-"), Name: name, Icon: "star", CreatedBy: "tester"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.DeleteSelfServiceCategory(context.Background(), c.ID) })
		return c
	}
	a := mk(idgen.New("Cat A "))
	b := mk(idgen.New("Cat B "))
	if b.Position <= a.Position {
		t.Fatalf("a new category is not added at the end: %d then %d", a.Position, b.Position)
	}

	t.Run("names are unique ignoring case", func(t *testing.T) {
		if _, err := s.CreateSelfServiceCategory(ctx, SelfServiceCategory{ID: idgen.New("sscat-test-"), Name: upper(a.Name)}); !errors.Is(err, ErrCategoryNameTaken) {
			t.Fatalf("duplicate name: %v", err)
		}
		if _, err := s.UpdateSelfServiceCategory(ctx, SelfServiceCategory{ID: b.ID, Name: upper(a.Name)}); !errors.Is(err, ErrCategoryNameTaken) {
			t.Fatalf("rename onto another's name: %v", err)
		}
	})

	t.Run("rename and change icon", func(t *testing.T) {
		c, err := s.UpdateSelfServiceCategory(ctx, SelfServiceCategory{ID: a.ID, Name: a.Name + " renamed", Icon: "", UpdatedBy: "tester2"})
		if err != nil || c == nil || c.Name != a.Name+" renamed" || c.Icon != "" || c.UpdatedBy != "tester2" || c.Position != a.Position {
			t.Fatalf("%+v %v", c, err)
		}
		if c, err := s.UpdateSelfServiceCategory(ctx, SelfServiceCategory{ID: "sscat-missing", Name: "x"}); c != nil || err != nil {
			t.Fatalf("an update of nothing: %+v %v", c, err)
		}
	})

	t.Run("reorder", func(t *testing.T) {
		all, err := s.ListSelfServiceCategories(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, c := range all {
			ids = append(ids, c.ID)
		}
		slices.Reverse(ids)
		if err := s.ReorderSelfServiceCategories(ctx, ids, "tester"); err != nil {
			t.Fatal(err)
		}
		all, _ = s.ListSelfServiceCategories(ctx)
		var got []string
		for _, c := range all {
			got = append(got, c.ID)
		}
		if !slices.Equal(got, ids) {
			t.Fatalf("order %v, want %v", got, ids)
		}
	})

	t.Run("packages keep, change and lose their categories", func(t *testing.T) {
		id := testPackage(t, s, "Category CRUD test", "")
		p, _ := s.GetSoftwarePackage(ctx, id)
		p.CategoryIDs = []string{a.ID, b.ID}
		if _, err := s.UpsertSoftwarePackage(ctx, *p); err != nil {
			t.Fatal(err)
		}
		// A save that leaves category_ids out keeps them.
		p.CategoryIDs = nil
		p.Description = "changed"
		got, err := s.UpsertSoftwarePackage(ctx, *p)
		if err != nil || !slices.Equal(got.CategoryIDs, []string{a.ID, b.ID}) {
			t.Fatalf("a save without categories dropped them: %v %v", got.CategoryIDs, err)
		}
		if c, _ := s.GetSelfServiceCategory(ctx, a.ID); c == nil || c.PackageCount != 1 {
			t.Fatalf("package count: %+v", c)
		}
		// Deleting a category takes it off the package.
		if ok, err := s.DeleteSelfServiceCategory(ctx, a.ID); !ok || err != nil {
			t.Fatal(ok, err)
		}
		got, _ = s.GetSoftwarePackage(ctx, id)
		if !slices.Equal(got.CategoryIDs, []string{b.ID}) {
			t.Fatalf("after deleting a category the package is under %v", got.CategoryIDs)
		}
		if ok, err := s.DeleteSelfServiceCategory(ctx, a.ID); ok || err != nil {
			t.Fatalf("deleting it again: %v %v", ok, err)
		}
		// An empty list clears them.
		got.CategoryIDs = []string{}
		got, err = s.UpsertSoftwarePackage(ctx, *got)
		if err != nil || got.CategoryIDs == nil || len(got.CategoryIDs) != 0 {
			t.Fatalf("an empty list did not clear: %#v %v", got.CategoryIDs, err)
		}
	})
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// testPackage adds a package with a free-text category, removed after the
// test.
func testPackage(t *testing.T, s *Store, name, category string) string {
	t.Helper()
	p, err := s.UpsertSoftwarePackage(context.Background(), SoftwarePackage{
		ID: idgen.New("sw-cattest-"), Name: name, Category: category,
		Commands: map[string]SoftwareOps{"linux": {Install: "true"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteSoftwarePackage(context.Background(), p.ID) })
	return p.ID
}
