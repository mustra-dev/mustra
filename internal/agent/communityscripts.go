package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Apps installed by the Proxmox VE community scripts (community-scripts/
// ProxmoxVE). Such an LXC runs an app (BentoPDF, BookStack, ...) installed
// from its GitHub releases, outside the package manager, so pending OS
// updates say nothing about whether the app is behind. Its /usr/bin/update
// re-runs the app's script from ct/<app>.sh, and the version that script
// installed is in /root/.<app>.
//
// The agent reports a behind app as a pending update named
// "community-script:<app>", in the same list as the OS updates, so patch
// lists, block lists, schedules and maintenance windows apply to it as to
// any other update. Applying it runs that same update command in the
// framework's own unattended mode (PHS_SILENT=1).
//
// Only the plain form of the script's check is followed:
// check_for_gh_release "<app>" "<owner>/<repo>" ["<pinned version>"]. The
// latest GitHub release is the target, or the pinned version when the script
// pins one, which is what the maintainers tested and what the script would
// install. Tag prefixes, other forges and pre-releases are not reported.

const (
	communityPatchPrefix   = "community-script:"
	communityUpdateCmd     = "/usr/bin/update"
	communityScriptEvery   = 12 * time.Hour
	communityReleaseEvery  = 6 * time.Hour
	communityRetryEvery    = time.Hour
	communityUpdateTimeout = 45 * time.Minute
)

var (
	// The update command names the app's script in one of the forms the
	// project has used: raw.githubusercontent.com/<org>/<repo>/main/ct/x.sh,
	// or the older github.com/<org>/<repo>/raw/main/ct/x.sh. The repository is
	// ProxmoxVE, or ProxmoxVED for apps installed from its development
	// repository; the script is read from whichever the LXC updates from.
	communityScriptPathRe = regexp.MustCompile(`(?:raw\.githubusercontent\.com/community-scripts/(ProxmoxVED?)/main|github\.com/community-scripts/(ProxmoxVED?)/raw/main)/ct/([a-z0-9][a-z0-9_-]{0,63})\.sh`)
	// check_for_gh_release "app" "owner/repo" optionally followed by a pin,
	// literal or a ${VAR} the script sets.
	communityCheckRe = regexp.MustCompile(`check_for_gh_release\s+"([^"]{1,64})"\s+"([A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100})"(?:\s+"([^"]*)")?(?:\s+"[^"]*")?\s*(?:[;)&|]|then|$)`)
	communityVarRe   = regexp.MustCompile(`(?m)^\s*(?:local\s+|export\s+)?([A-Z][A-Z0-9_]{0,63})="?([vV]?[0-9][A-Za-z0-9._+-]{0,63})"?\s*$`)
	communityGitHub  = "https://api.github.com"
	communityRawBase = "https://raw.githubusercontent.com/community-scripts/"
)

// communityCheck is one app the script checks, and where its version lives.
type communityCheck struct {
	App    string // as the script names it: "Immich"
	Repo   string
	Pinned string // the version the script installs, when it pins one
}

func (c communityCheck) versionFile() string {
	return filepath.Join("/root", "."+strings.ReplaceAll(strings.ToLower(c.App), " ", ""))
}

// parseCommunityScript finds the checks in an app's ct script. A pin that
// names a variable is resolved from the script's own assignments; one that
// cannot be resolved is dropped with its check rather than guessed.
func parseCommunityScript(script string) []communityCheck {
	vars := map[string]string{}
	for _, m := range communityVarRe.FindAllStringSubmatch(script, -1) {
		vars[m[1]] = m[2]
	}
	var out []communityCheck
	seen := map[string]bool{}
	for _, line := range strings.Split(script, "\n") {
		for _, m := range communityCheckRe.FindAllStringSubmatch(line, -1) {
			c := communityCheck{App: m[1], Repo: m[2]}
			if pin := m[3]; pin != "" {
				if strings.HasPrefix(pin, "${") && strings.HasSuffix(pin, "}") {
					v, ok := vars[strings.TrimSuffix(strings.TrimPrefix(pin, "${"), "}")]
					if !ok {
						continue
					}
					pin = v
				} else if strings.Contains(pin, "$") {
					continue
				}
				c.Pinned = pin
			}
			if !seen[c.App] {
				seen[c.App] = true
				out = append(out, c)
			}
		}
	}
	return out
}

func stripV(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

// communityApps checks the LXC's community-script apps, caching the script
// and the releases so the checks cost a few requests a day.
type communityApps struct {
	mu        sync.Mutex
	client    *http.Client
	logger    *slog.Logger
	script    string // the ct script name, from /usr/bin/update
	checks    []communityCheck
	scriptDue time.Time
	latest    map[string]cachedLatest // repo -> latest release
}

type cachedLatest struct {
	tag string
	err error
	due time.Time
}

var defaultCommunityApps = &communityApps{
	client: &http.Client{Timeout: 20 * time.Second},
	latest: map[string]cachedLatest{},
}

// communityScriptName reads which app script /usr/bin/update runs, or "".
func communityScriptName(updateCmd string) string {
	_, name := communityScript(updateCmd)
	return name
}

// communityScript reads the repository and app script /usr/bin/update runs.
func communityScript(updateCmd string) (repo, name string) {
	raw, err := os.ReadFile(updateCmd)
	if err != nil || len(raw) > 4096 {
		return "", ""
	}
	// The generated entrypoint the framework now writes on install and on
	// each update names the app and repository in variables.
	if m := communityGeneratedNameRe.FindStringSubmatch(string(raw)); m != nil {
		repo = "ProxmoxVE"
		if u := communityGeneratedRepoRe.FindStringSubmatch(string(raw)); u != nil {
			repo = u[1]
		}
		return repo, m[1]
	}
	m := communityScriptPathRe.FindStringSubmatch(string(raw))
	if m == nil {
		return "", ""
	}
	repo = m[1]
	if repo == "" {
		repo = m[2]
	}
	return repo, m[3]
}

var (
	communityGeneratedNameRe = regexp.MustCompile(`(?m)^export UPDATE_SCRIPT_NAME="([a-z0-9][a-z0-9_-]{0,63})"\s*$`)
	communityGeneratedRepoRe = regexp.MustCompile(`(?m)^export COMMUNITY_SCRIPTS_URL="https://raw\.githubusercontent\.com/community-scripts/(ProxmoxVED?)/main"\s*$`)
)

// pending returns the apps that are behind, as patches. A failure to look
// is logged and leaves the app out: the OS list must not fail because
// GitHub did not answer.
func (c *communityApps) pending(ctx context.Context) []proto.PatchInfo {
	repo, name := communityScript(communityUpdateCmd)
	if name == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if repo+"/"+name != c.script || now.After(c.scriptDue) {
		script, err := c.get(ctx, communityRawBase+repo+"/main/ct/"+name+".sh")
		if err != nil {
			c.logf("reading the community script failed", "script", name, "error", err)
			c.scriptDue = now.Add(communityRetryEvery)
		} else {
			c.script, c.checks, c.scriptDue = repo+"/"+name, parseCommunityScript(script), now.Add(communityScriptEvery)
		}
	}
	var out []proto.PatchInfo
	for _, chk := range c.checks {
		raw, err := os.ReadFile(chk.versionFile())
		if err != nil {
			continue // never installed this way, or the script records it elsewhere
		}
		installed := stripV(strings.SplitN(string(raw), "\n", 2)[0])
		target := stripV(chk.Pinned)
		if target == "" {
			tag, err := c.latestTag(ctx, chk.Repo, now)
			if err != nil {
				c.logf("reading a community app's latest release failed", "app", chk.App, "repo", chk.Repo, "error", err)
				continue
			}
			target = stripV(tag)
		}
		if installed == "" || target == "" || installed == target || !versionAfter(target, installed) {
			continue
		}
		out = append(out, proto.PatchInfo{
			Name:           communityPatchPrefix + strings.ToLower(strings.ReplaceAll(chk.App, " ", "")),
			CurrentVersion: installed, NewVersion: target,
		})
	}
	return out
}

func (c *communityApps) latestTag(ctx context.Context, repo string, now time.Time) (string, error) {
	if l, ok := c.latest[repo]; ok && now.Before(l.due) {
		return l.tag, l.err
	}
	body, err := c.get(ctx, communityGitHub+"/repos/"+repo+"/releases/latest")
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err == nil {
		if json.Unmarshal([]byte(body), &rel) != nil || rel.Tag == "" {
			err = errors.New("no release tag in GitHub's answer")
		}
	}
	due := now.Add(communityReleaseEvery)
	if err != nil {
		due = now.Add(communityRetryEvery)
	}
	c.latest[repo] = cachedLatest{tag: rel.Tag, err: err, due: due}
	return rel.Tag, err
}

func (c *communityApps) get(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mustra-agent")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), err
}

func (c *communityApps) logf(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Warn(msg, args...)
	}
}

// versionAfter reports whether a is a later version than b, comparing the
// numbers each starts with; versions that do not start with numbers count
// as different, and so as an update, only when they differ at all.
func versionAfter(a, b string) bool {
	pa, okA := leadingNumbers(a)
	pb, okB := leadingNumbers(b)
	if !okA || !okB {
		return a != b
	}
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	// The same numbers with different suffixes: not knowably later.
	return false
}

var leadingNumbersRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)`)

func leadingNumbers(v string) ([]int, bool) {
	m := leadingNumbersRe.FindString(v)
	if m == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(m, ".") {
		n := 0
		for _, ch := range p {
			n = n*10 + int(ch-'0')
			if n > 1<<30 {
				return nil, false
			}
		}
		out = append(out, n)
	}
	return out, true
}

// splitCommunityPatches separates community-script apps from OS updates.
func splitCommunityPatches(names []string) (os, apps []string) {
	for _, n := range names {
		if strings.HasPrefix(n, communityPatchPrefix) {
			apps = append(apps, n)
		} else {
			os = append(os, n)
		}
	}
	return os, apps
}

// runCommunityUpdate runs the LXC's own update command in the framework's
// unattended mode. It fetches and runs the app's script from GitHub as root,
// which is what someone typing "update" does; inventory-and-patching mode,
// which refuses code from elsewhere, refuses it.
func runCommunityUpdate(ctx context.Context, report patchProgress) (string, error) {
	if noRemoteCodeActive.Load() {
		return "", errors.New("this endpoint is in inventory-and-patching mode, which does not run the community script's update")
	}
	if communityScriptName(communityUpdateCmd) == "" {
		return "", errors.New("no community-scripts update command on this endpoint")
	}
	report("installing", "Updating the app with its community script", 1)
	cctx, cancel := context.WithTimeout(ctx, communityUpdateTimeout)
	defer cancel()
	// Through bash: the file is one line with no #! line, which a shell runs
	// when someone types "update" but exec(2) refuses ("exec format error").
	cmd := exec.CommandContext(cctx, "bash", communityUpdateCmd)
	cmd.Env = append(os.Environ(), "PHS_SILENT=1", "TERM=dumb", "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	text := stripANSI(string(out))
	if len(text) > 64<<10 {
		text = text[:16<<10] + "\n… (truncated) …\n" + text[len(text)-32<<10:]
	}
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return text, fmt.Errorf("the community script's update did not finish within %v", communityUpdateTimeout)
	}
	if err != nil {
		if why := communityRefusal(text); why != "" {
			return text, fmt.Errorf("the community script did not update: %s", why)
		}
		return text, fmt.Errorf("the community script's update failed: %w", err)
	}
	return text, nil
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\r`)

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// communityRefusal is the script's own reason for stopping, its last line
// marked as an error, so the console says "LXC is under-provisioned" rather
// than "exit status 113".
func communityRefusal(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.Contains(l, "✖") {
			l = strings.TrimSpace(strings.TrimLeft(l, "✖️ \t\ufe0f"))
			if len(l) > 300 {
				l = l[:300]
			}
			return l
		}
	}
	return ""
}
