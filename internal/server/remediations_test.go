package server

import (
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mustra-dev/mustra/internal/deploy"
	"github.com/mustra-dev/mustra/internal/server/auth"
)

// The starting set the gallery promises. An entry can be added without
// touching this list; one disappearing is a decision to make on purpose.
var remediationStartingSet = []string{
	"clear-print-spooler", "fix-time-sync", "flush-dns", "free-disk-space", "rebuild-search-index",
	"recover-dpkg", "renew-dhcp", "repair-wmi", "reset-windows-update", "restart-service",
}

var paramRefRe = regexp.MustCompile(`MUSTRA_PARAM_([A-Za-z][A-Za-z0-9_]*)`)

// Every gallery entry parses, says what it changes on each platform it
// supports, and is publishable as an action package exactly as embedded.
func TestRemediationGallery(t *testing.T) {
	all, err := remediationGallery()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, e := range all {
		ids[e.ID] = true
		def := e.definition()
		if err := deploy.ValidateDefinition(def, true); err != nil {
			t.Errorf("%s does not validate for publishing: %v", e.ID, err)
		}
		if !versionNumberRe.MatchString(e.revisionLabel()) {
			t.Errorf("%s: version label %q is not a package version number", e.ID, e.revisionLabel())
		}
		declared := map[string]bool{}
		for _, p := range e.Parameters {
			declared[p.Name] = true
		}
		used := map[string]bool{}
		for os, script := range e.scripts {
			for _, m := range paramRefRe.FindAllStringSubmatch(script.Source, -1) {
				used[m[1]] = true
				if !declared[m[1]] {
					t.Errorf("%s %s reads MUSTRA_PARAM_%s, which it does not declare", e.ID, os, m[1])
				}
			}
			if script.TimeoutSeconds != e.TimeoutSeconds {
				t.Errorf("%s %s: script timeout %d, entry says %d", e.ID, os, script.TimeoutSeconds, e.TimeoutSeconds)
			}
			checkRemediationScript(t, e.ID, os, script.Source)
		}
		for name := range declared {
			if !used[name] {
				t.Errorf("%s declares parameter %s that no script reads", e.ID, name)
			}
		}
		// What a playbook step would be given: the defaults, plus a value
		// for each required parameter. Required ones must be refused when
		// missing, because a playbook runs without asking.
		params := map[string]string{}
		for _, p := range e.Parameters {
			if p.Required {
				if err := validateRevisionInputs(def, "run", e.playbookOS(), nil); err == nil {
					t.Errorf("%s: missing required parameter %s was accepted", e.ID, p.Name)
				}
				params[p.Name] = "example"
			}
		}
		for _, os := range append([]string{""}, e.platforms()...) {
			if err := validateRevisionInputs(def, "run", os, params); err != nil {
				t.Errorf("%s on %q: default inputs do not validate: %v", e.ID, os, err)
			}
		}
	}
	for _, id := range remediationStartingSet {
		if !ids[id] {
			t.Errorf("the gallery has lost %s", id)
		}
	}
}

// The safety conventions every script keeps, beyond what the package
// validator can see.
func checkRemediationScript(t *testing.T, id, os, src string) {
	t.Helper()
	code := stripComments(src)
	if os == "windows" {
		for _, line := range strings.Split(code, "\n") {
			if regexp.MustCompile(`(?i)^\s*&\s*winmgmt(\.exe)?\s+/resetrepository`).MatchString(line) {
				t.Errorf("%s: runs winmgmt /resetrepository", id)
			}
			// Recursive deletes only of the copies a reset set aside.
			if regexp.MustCompile(`(?i)Remove-Item\b.*-Recurse`).MatchString(line) && id != "reset-windows-update" {
				t.Errorf("%s: recursive delete: %s", id, strings.TrimSpace(line))
			}
		}
		if regexp.MustCompile(`(?i)/ResetBase`).MatchString(code) {
			t.Errorf("%s: DISM /ResetBase makes installed updates impossible to uninstall", id)
		}
		return
	}
	// Shell: deletes go through find -delete over the named temp and cache
	// directories; no rm at all, so never a lock file either.
	if regexp.MustCompile(`(^|[\s;&|(])rm\s`).MatchString(code) {
		t.Errorf("%s %s: uses rm", id, os)
	}
	if strings.HasPrefix(strings.TrimSpace(src), "#!") {
		t.Errorf("%s %s: the agent runs scripts with /bin/sh; a shebang suggests otherwise", id, os)
	}
	for _, bashism := range []string{"[[ ", "function ", "local -a", "${!", "<<<"} {
		if strings.Contains(code, bashism) {
			t.Errorf("%s %s: %q is not POSIX sh, and /bin/sh is dash on Debian", id, os, bashism)
		}
	}
}

func stripComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// A malformed entry is an error, not a silently shorter gallery.
func TestRemediationLoaderRefusesMalformedEntries(t *testing.T) {
	good := `{"name": "N", "version": 1, "category": "C", "summary": "S", "risk": "low", "risk_note": "R",
		"timeout_seconds": 60, "changes": {"linux": ["x"]}}`
	for name, files := range map[string]map[string]string{
		"unknown field":           {"remediation.json": strings.Replace(good, `"name"`, `"nmae": "x", "name"`, 1), "linux.sh": "true"},
		"no script":               {"remediation.json": good},
		"undescribed platform":    {"remediation.json": good, "linux.sh": "true", "darwin.sh": "true"},
		"describes missing":       {"remediation.json": strings.Replace(good, `{"linux": ["x"]}`, `{"linux": ["x"], "windows": ["y"]}`, 1), "linux.sh": "true"},
		"bad risk":                {"remediation.json": strings.Replace(good, `"low"`, `"none"`, 1), "linux.sh": "true"},
		"version zero":            {"remediation.json": strings.Replace(good, `"version": 1`, `"version": 0`, 1), "linux.sh": "true"},
		"timeout out of range":    {"remediation.json": strings.Replace(good, `60`, `5`, 1), "linux.sh": "true"},
		"missing remediationjson": {"linux.sh": "true"},
	} {
		fsys := fstest.MapFS{}
		for f, body := range files {
			fsys["remediations/entry/"+f] = &fstest.MapFile{Data: []byte(body)}
		}
		if _, err := loadRemediations(fsys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	fsys := fstest.MapFS{"remediations/entry/remediation.json": {Data: []byte(good)}, "remediations/entry/linux.sh": {Data: []byte("true")}}
	if got, err := loadRemediations(fsys); err != nil || len(got) != 1 || got[0].ID != "entry" {
		t.Fatalf("a good entry: %v %+v", err, got)
	}
}

// Both gallery routes need deploy.manage: the gallery is operator-chosen
// code to run as administrator, gated like a custom package.
func TestRemediationRoutesNeedDeployManage(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	want := []string{"GET /api/remediations", "POST /api/remediations/{id}/import"}
	found := 0
	for _, e := range s.routeLog.entries {
		if !slices.Contains(want, e.Pattern) {
			continue
		}
		found++
		g, ok := e.Handler.(*permGuard)
		if !ok || !slices.Equal(g.perms, []string{auth.PermDeployManage}) {
			t.Errorf("%s is not guarded by deploy.manage alone", e.Pattern)
		}
	}
	if found != len(want) {
		t.Fatalf("found %d of %d gallery routes", found, len(want))
	}
}
