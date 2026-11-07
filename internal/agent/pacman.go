package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// Arch Linux and its derivatives, through pacman.
//
// Reading pending updates uses `pacman -Qu`, which compares installed
// packages with the sync databases as they are, without refreshing them,
// the same choice as for apt: a sensor that runs every interval should not
// download repository indexes. Refreshing the databases alone (`pacman -Sy`)
// is what Arch warns against, since it sets up a partial upgrade, so the
// agent never does that either. A full upgrade refreshes them.

const pacmanLocalDB = "/var/lib/pacman/local"

// pacmanKernels are packages whose upgrade needs a restart to take effect.
var pacmanKernels = []string{"linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt", "linux-rt-lts"}

func pacmanPresent() bool {
	if _, err := exec.LookPath("pacman"); err != nil {
		return false
	}
	_, err := os.Stat(pacmanLocalDB)
	return err == nil
}

func collectPatchesPacman(ctx context.Context) ([]proto.PatchInfo, error) {
	out, err := exec.CommandContext(ctx, "pacman", "-Qu").Output()
	// pacman -Qu exits 1 when nothing is upgradable, with no output.
	var exit *exec.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1 && len(strings.TrimSpace(string(out))) == 0) {
		return nil, fmt.Errorf("pacman -Qu: %w", err)
	}
	return parsePacmanUpgradable(string(out)), nil
}

// parsePacmanUpgradable reads `pacman -Qu`: "name old -> new", with
// " [ignored]" after a package IgnorePkg holds back, which is left out
// because a full upgrade will not install it.
func parsePacmanUpgradable(out string) []proto.PatchInfo {
	patches := []proto.PatchInfo{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != "->" || slices.Contains(f, "[ignored]") {
			continue
		}
		patches = append(patches, proto.PatchInfo{
			Name: f[0], CurrentVersion: f[1], NewVersion: f[3],
			RestartRequired: slices.Contains(pacmanKernels, f[0]),
		})
	}
	return patches
}

// collectAppsPacman reads the local package database directly: each
// package is a directory holding a desc file with %NAME%, %VERSION% and
// %INSTALLDATE% sections.
func collectAppsPacman() ([]proto.InstalledApp, error) {
	entries, err := os.ReadDir(pacmanLocalDB)
	if err != nil {
		return nil, err
	}
	apps := []proto.InstalledApp{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(pacmanLocalDB, e.Name(), "desc"))
		if err != nil {
			continue
		}
		app := parsePacmanDesc(f)
		f.Close()
		if app.Name != "" {
			apps = append(apps, app)
		}
	}
	return apps, nil
}

func parsePacmanDesc(f *os.File) proto.InstalledApp {
	var app proto.InstalledApp
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			section = ""
		case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%"):
			section = line
		case section == "%NAME%":
			app.Name = line
		case section == "%VERSION%":
			app.Version = line
		case section == "%PACKAGER%":
			app.Publisher = line
		case section == "%INSTALLDATE%":
			if secs, err := strconv.ParseInt(line, 10, 64); err == nil {
				app.InstallDate = time.Unix(secs, 0).UTC().Format("2006-01-02")
			}
		}
	}
	return app
}

// pacmanUpgradeRefusal says why a selection of updates cannot be applied on
// Arch, or "" when it can: only a full upgrade is supported, so a list must
// name every pending update.
func pacmanUpgradeRefusal(names []string, pending []proto.PatchInfo) string {
	if len(names) == 0 {
		return ""
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var left []string
	for _, p := range pending {
		if !want[p.Name] {
			left = append(left, p.Name)
		}
	}
	if len(left) == 0 {
		return ""
	}
	slices.Sort(left)
	if len(left) > 10 {
		left = append(left[:10], fmt.Sprintf("and %d more", len(left)-10))
	}
	return "Arch Linux supports only full upgrades, and this run would leave out " + strings.Join(left, ", ") +
		". Apply all pending updates on this endpoint, or update it by hand."
}
