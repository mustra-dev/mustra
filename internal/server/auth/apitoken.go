package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// API tokens let scripts and integrations call the same HTTP API the
// console uses, without a browser session. A token authenticates as a
// synthetic user carrying only the permissions the token was granted —
// deliberately not "as the person who made it", so revoking a token is a
// complete answer and a token can be narrower than its creator.

// TokenPrefix marks a mustra API token in logs, git-secret scanners, and
// the "is this thing a token?" glance test.
const TokenPrefix = "mstr_"

// prefixLen is how much of the token is stored in the clear to narrow the
// hash comparison (and to show in the UI). Long enough to be selective,
// far too short to help an attacker.
const prefixLen = len(TokenPrefix) + 8

// APITokenUserID is the synthetic user ID an API-token request runs as.
// It never matches a real users.id, so anything writing an audit trail
// records the token rather than misattributing the action to a person.
const APITokenUserID = "api-token"

// GenerateToken returns a new token secret. Only its hash is ever stored,
// so this is the one and only moment the plaintext exists.
func GenerateToken() (token, prefix string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, token[:prefixLen], nil
}

// HashToken reuses the same bcrypt cost as account passwords — a token is
// a credential, and verification happens once per request at worst.
func HashToken(token string) (string, error) { return HashPassword(token) }

// authenticateToken resolves a bearer token to a user + permissions, or
// (nil, nil) when the token isn't valid. An unknown token is not an error:
// the caller falls through to the normal 401.
func (a *Auth) authenticateToken(ctx context.Context, token string) (*store.User, tokenGrant) {
	if !strings.HasPrefix(token, TokenPrefix) || len(token) <= prefixLen {
		return nil, tokenGrant{}
	}
	candidates, err := a.store.CandidatesForPrefix(ctx, token[:prefixLen])
	if err != nil {
		a.logger.Error("api token lookup failed", "error", err)
		return nil, tokenGrant{}
	}
	for _, c := range candidates {
		if !VerifyPassword(c.Hash, token) {
			continue
		}
		user, grant, ok := a.grantToken(ctx, c)
		if !ok {
			return nil, tokenGrant{}
		}
		// Best-effort: a failed "last used" write must not fail the request.
		if err := a.store.TouchAPIToken(ctx, c.ID); err != nil {
			a.logger.Warn("recording api token use failed", "token", c.Name, "error", err)
		}
		return user, grant
	}
	return nil, tokenGrant{}
}

// grantToken decides what a live token may do right now: within its
// creator's reach, re-read on every use (a creator who is deactivated,
// deleted or loses a permission takes the token's share of it with them),
// and within every token up the chain that made it. A token whose creator
// cannot be resolved (one minted before tokens recorded their creator, by
// an account since deleted) is refused rather than left unbounded.
func (a *Auth) grantToken(ctx context.Context, c store.APITokenCandidate) (*store.User, tokenGrant, bool) {
	if c.CreatedByID == "" {
		a.logger.Warn("api token refused: it records no creator; recreate it", "token", c.Name)
		return nil, tokenGrant{}, false
	}
	creator, err := a.store.GetUserByID(ctx, c.CreatedByID)
	if err != nil || creator == nil || !creator.Active {
		a.logger.Warn("api token refused: its creator no longer exists or is inactive", "token", c.Name)
		return nil, tokenGrant{}, false
	}
	perms := c.Permissions
	// A token made by a token lives and is bounded by its parent:
	// revoking, deleting or letting a leaked token expire takes the
	// tokens it made with it, and narrowing it narrows them.
	if c.ParentTokenID != "" {
		var ok bool
		if perms, ok = a.boundByParents(ctx, c.ParentTokenID, perms); !ok {
			a.logger.Warn("api token refused: a token that created it is revoked, expired or gone", "token", c.Name)
			return nil, tokenGrant{}, false
		}
	}
	if !creator.IsAdmin {
		held, err := a.store.EffectivePermissions(ctx, creator.ID)
		if err != nil {
			a.logger.Error("api token creator permissions lookup failed", "token", c.Name, "error", err)
			return nil, tokenGrant{}, false
		}
		// Intersected with what the parents left, not with the token's
		// own list: a parent's narrowing must survive this step.
		bounded := make([]string, 0, len(perms))
		for _, p := range perms {
			if held[p] {
				bounded = append(bounded, p)
			}
		}
		perms = bounded
	}
	info := &TokenInfo{ID: c.ID, Name: c.Name, CreatorID: creator.ID, CreatorUsername: creator.Username,
		CreatorAdmin: creator.IsAdmin, ApprovalExempt: c.ApprovalExempt && creator.IsAdmin, MCPOnly: c.MCPOnly}
	return &store.User{
		ID:          APITokenUserID,
		Username:    "token:" + c.Name,
		DisplayName: c.Name,
		Source:      "api-token",
		Active:      true,
		// Never IsAdmin: a token's reach is exactly the permission set
		// it was created with, even if its creator was an admin.
	}, withTokenInfo(perms, info), true
}

// ErrTokenNotLive is TokenContext's answer for a token that is revoked,
// expired, gone, or whose creator or parent no longer lets it act.
var ErrTokenNotLive = errors.New("the API token is revoked, expired or no longer allowed to act")

// TokenContext is ctx acting as the API token tokenID, exactly as a
// request presenting it would: the same synthetic user, the same bounded
// permissions, and only while the token is live. It is how work a token
// asked for and somebody else approved later runs as that token rather
// than as whoever approved it.
func (a *Auth) TokenContext(ctx context.Context, tokenID string) (context.Context, error) {
	t, err := a.store.GetAPIToken(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	if t == nil || t.Revoked || (t.ExpiresAt != nil && !t.ExpiresAt.After(time.Now())) {
		return nil, ErrTokenNotLive
	}
	user, grant, ok := a.grantToken(ctx, store.APITokenCandidate{ID: t.ID, Name: t.Name, Permissions: t.Permissions,
		CreatedByID: t.CreatedByID, ApprovalExempt: t.ApprovalExempt, ParentTokenID: t.ParentTokenID, MCPOnly: t.MCPOnly})
	if !ok {
		return nil, ErrTokenNotLive
	}
	return WithToken(withUser(ctx, user), grant.perms, grant.info), nil
}

// TokenInfo is what an authenticated API-token request knows about the
// token: which one, and on whose behalf it acts. Management rights and
// content sets are the creator's.
type TokenInfo struct {
	ID              string
	Name            string
	CreatorID       string
	CreatorUsername string
	CreatorAdmin    bool
	ApprovalExempt  bool
	// MCPOnly: the token may reach only the MCP endpoint (MCPPath).
	MCPOnly bool
}

// MCPPath is the one route an MCP-only token may call.
const MCPPath = "/api/mcp"

type tokenInfoKey struct{}

// tokenGrant carries both the effective permissions and the token's
// identity from authenticateToken to the middleware.
type tokenGrant struct {
	perms []string
	info  *TokenInfo
}

func withTokenInfo(perms []string, info *TokenInfo) tokenGrant {
	return tokenGrant{perms: perms, info: info}
}

// Token returns the API token authenticating this request, if any.
func Token(ctx context.Context) (*TokenInfo, bool) {
	t, ok := ctx.Value(tokenInfoKey{}).(*TokenInfo)
	return t, ok && t != nil
}

// WithToken attaches token identity to a context. Exported for tests and
// for replaying work on a token's behalf.
func WithToken(ctx context.Context, perms []string, info *TokenInfo) context.Context {
	return context.WithValue(withTokenPermissions(ctx, perms), tokenInfoKey{}, info)
}

// bearerToken pulls the credential out of an Authorization header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return h[len(prefix):]
}

type tokenPermsKey struct{}

// withTokenPermissions stores an API token's granted permissions on the
// request context, so RequirePermission can consult them instead of the
// role tables (a token has no rows there).
func withTokenPermissions(ctx context.Context, perms []string) context.Context {
	return context.WithValue(ctx, tokenPermsKey{}, perms)
}

// TokenPermissions returns the permissions of the API token authenticating
// this request, and whether the request came from a token at all.
func TokenPermissions(ctx context.Context) ([]string, bool) {
	perms, ok := ctx.Value(tokenPermsKey{}).([]string)
	return perms, ok
}

// MaxTokenChain bounds how deep tokens creating tokens may go, and so how
// many lookups one request can cost.
const MaxTokenChain = 5

// boundByParents walks a token's parents, intersecting perms with each,
// and reports false if any of them is revoked, expired or missing, or the
// chain is longer than MaxTokenChain.
func (a *Auth) boundByParents(ctx context.Context, parentID string, perms []string) ([]string, bool) {
	for depth := 0; parentID != ""; depth++ {
		if depth >= MaxTokenChain {
			return nil, false
		}
		p, err := a.store.GetAPIToken(ctx, parentID)
		if err != nil || p == nil || p.Revoked || (p.ExpiresAt != nil && !p.ExpiresAt.After(time.Now())) {
			return nil, false
		}
		perms = intersectPermissions(perms, p.Permissions)
		parentID = p.ParentTokenID
	}
	return perms, true
}

func intersectPermissions(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, p := range b {
		in[p] = true
	}
	out := make([]string, 0, len(a))
	for _, p := range a {
		if in[p] {
			out = append(out, p)
		}
	}
	return out
}

// TokenChainDepth is how many tokens up a chain a token is: 0 for one a
// person made. Creating a token from a token at MaxTokenChain-1 is
// refused, since the new one could never be used.
func (a *Auth) TokenChainDepth(ctx context.Context, tokenID string) (int, error) {
	depth := 0
	for id := tokenID; ; depth++ {
		t, err := a.store.GetAPIToken(ctx, id)
		if err != nil {
			return 0, err
		}
		if t == nil || t.ParentTokenID == "" || depth > MaxTokenChain {
			return depth, nil
		}
		id = t.ParentTokenID
	}
}
