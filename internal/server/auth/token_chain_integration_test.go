package auth

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"testing"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// A token made by a token works only while its parent does, and never
// with more permissions than its parent holds now.
func TestTokenChainBoundByParent(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := New(ctx, st, nil, false, slog.Default())
	admin, err := st.UpsertLocalAdmin(ctx, "chain-admin-"+idgen.New("u-"), "x")
	if err != nil {
		t.Fatal(err)
	}
	mint := func(parent string, perms []string) (id, secret string) {
		secret, prefix, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		hash, err := HashToken(secret)
		if err != nil {
			t.Fatal(err)
		}
		id = idgen.New("tok-")
		if err := st.CreateAPIToken(ctx, store.APIToken{ID: id, Name: id, Prefix: prefix, Permissions: perms,
			CreatedBy: admin.Username, CreatedByID: admin.ID, ParentTokenID: parent}, hash); err != nil {
			t.Fatal(err)
		}
		return id, secret
	}
	parentID, _ := mint("", []string{PermSettingsManage, PermTokensManage, PermAllowlistsManage})
	childID, child := mint(parentID, []string{PermSettingsManage, PermAllowlistsManage, PermIdentityManage})

	u, g := a.authenticateToken(ctx, child)
	if u == nil {
		t.Fatal("a child of a live token was refused")
	}
	// identity.manage is not the parent's, so the child does not get it.
	if want := []string{PermSettingsManage, PermAllowlistsManage}; !slices.Equal(g.perms, want) {
		t.Errorf("child permissions %v, want %v", g.perms, want)
	}
	if d, _ := a.TokenChainDepth(ctx, childID); d != 1 {
		t.Errorf("child depth %d, want 1", d)
	}
	// Narrowing the parent narrows the child.
	if _, err := st.UpdateAPIToken(ctx, parentID, parentID, []string{PermSettingsManage}, false, false); err != nil {
		t.Fatal(err)
	}
	if _, g = a.authenticateToken(ctx, child); !slices.Equal(g.perms, []string{PermSettingsManage}) {
		t.Errorf("after narrowing the parent, child permissions %v", g.perms)
	}
	// Revoking the parent kills the child; so does deleting it.
	if err := st.RevokeAPIToken(ctx, parentID); err != nil {
		t.Fatal(err)
	}
	if u, _ = a.authenticateToken(ctx, child); u != nil {
		t.Error("a child of a revoked token still works")
	}
	p2, _ := mint("", []string{PermSettingsManage})
	_, c2 := mint(p2, []string{PermSettingsManage})
	if err := st.DeleteAPIToken(ctx, p2); err != nil {
		t.Fatal(err)
	}
	if u, _ = a.authenticateToken(ctx, c2); u != nil {
		t.Error("a child of a deleted token still works")
	}
	// A chain longer than MaxTokenChain is refused.
	prev, _ := mint("", []string{PermSettingsManage})
	var last string
	for i := 0; i <= MaxTokenChain; i++ {
		prev, last = mint(prev, []string{PermSettingsManage})
	}
	if u, _ = a.authenticateToken(ctx, last); u != nil {
		t.Error("a chain longer than MaxTokenChain was accepted")
	}
}

// The parent's bound survives the creator's: for a creator who is not an
// administrator, the token's permissions are what the parents left and
// the creator holds, not what the token was created with and the creator
// holds.
func TestTokenChainBoundByParentForNonAdminCreator(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := New(ctx, st, nil, false, slog.Default())
	u, err := st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("chain-"), "", "chain test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.DeleteUser(context.Background(), u.ID) }()
	role, err := st.CreateRole(ctx, idgen.New("role-"), idgen.New("chain-role-"), "", []string{PermSettingsManage, PermTokensManage, PermIdentityManage}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.DeleteRole(context.Background(), role.ID) }()
	if err := st.AssignUserRole(ctx, u.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	mint := func(parent string, perms []string) string {
		secret, prefix, _ := GenerateToken()
		hash, _ := HashToken(secret)
		id := idgen.New("tok-")
		if err := st.CreateAPIToken(ctx, store.APIToken{ID: id, Name: id, Prefix: prefix, Permissions: perms,
			CreatedBy: u.Username, CreatedByID: u.ID, ParentTokenID: parent}, hash); err != nil {
			t.Fatal(err)
		}
		return secret
	}
	parentSecret := mint("", []string{PermSettingsManage, PermTokensManage})
	_, pg := a.authenticateToken(ctx, parentSecret)
	parentID := pg.info.ID
	child := mint(parentID, []string{PermSettingsManage, PermIdentityManage})
	if _, g := a.authenticateToken(ctx, child); !slices.Equal(g.perms, []string{PermSettingsManage}) {
		t.Errorf("child of a non-admin's token got %v; identity.manage is not its parent's", g.perms)
	}
}
