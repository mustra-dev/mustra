package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestParsePacmanUpgradable(t *testing.T) {
	out := "linux 6.11.1.arch1-1 -> 6.11.2.arch1-1\nopenssl 3.3.2-1 -> 3.4.0-1\nnvidia 560.35-1 -> 565.57-1 [ignored]\n\n"
	got := parsePacmanUpgradable(out)
	if len(got) != 2 || got[0].Name != "linux" || !got[0].RestartRequired || got[1].NewVersion != "3.4.0-1" || got[1].RestartRequired {
		t.Fatalf("got %+v", got)
	}
	if got := parsePacmanUpgradable(""); got == nil || len(got) != 0 {
		t.Errorf("nothing pending must be an empty list, got %v", got)
	}
}

func TestPacmanRefusesAPartialUpgrade(t *testing.T) {
	pending := []proto.PatchInfo{{Name: "openssl"}, {Name: "curl"}, {Name: "linux"}}
	if why := pacmanUpgradeRefusal(nil, pending); why != "" {
		t.Errorf("everything: %q", why)
	}
	if why := pacmanUpgradeRefusal([]string{"linux", "curl", "openssl"}, pending); why != "" {
		t.Errorf("all named: %q", why)
	}
	why := pacmanUpgradeRefusal([]string{"openssl"}, pending)
	if !strings.Contains(why, "only full upgrades") || !strings.Contains(why, "curl, linux") {
		t.Errorf("partial: %q", why)
	}
}

func TestParsePacmanDesc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desc")
	os.WriteFile(path, []byte("%NAME%\nopenssl\n\n%VERSION%\n3.4.0-1\n\n%PACKAGER%\nPierre Schmitz <pierre@archlinux.org>\n\n%INSTALLDATE%\n1730000000\n\n%DEPENDS%\nglibc\n"), 0o600)
	f, _ := os.Open(path)
	defer f.Close()
	app := parsePacmanDesc(f)
	if app.Name != "openssl" || app.Version != "3.4.0-1" || app.InstallDate != "2024-10-27" || !strings.HasPrefix(app.Publisher, "Pierre") {
		t.Errorf("got %+v", app)
	}
}

// TestLivePacman runs on a real Arch system: the patch and app collectors as
// the agent calls them. Opt-in: MUSTRA_LIVE_PACMAN=1.
func TestLivePacman(t *testing.T) {
	if os.Getenv("MUSTRA_LIVE_PACMAN") == "" {
		t.Skip("set MUSTRA_LIVE_PACMAN=1 on an Arch system")
	}
	if !pacmanPresent() {
		t.Fatal("pacman not found")
	}
	patches, err := collectPatchesLinux(t.Context(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	apps, err := collectAppsLinux(t.Context())
	if err != nil || len(apps) == 0 {
		t.Fatal(apps, err)
	}
	t.Logf("%d pending, %d installed; first pending %+v; first app %+v", len(patches), len(apps), first(patches), apps[0])
	if os.Getenv("MUSTRA_LIVE_PACMAN_APPLY") == "" || len(patches) < 2 {
		return
	}
	// Applying runs pacman for real: only in a disposable container.
	noop := func(stage, detail string, attempt int) {}
	if _, err := applyPatchesLinux(t.Context(), nil, "", []string{patches[0].Name}, noop); err == nil || !strings.Contains(err.Error(), "only full upgrades") {
		t.Fatalf("a partial upgrade was not refused: %v", err)
	}
	res, err := applyPatchesLinux(t.Context(), nil, "", nil, noop)
	if err != nil {
		t.Fatalf("full upgrade: %v\n%s", err, res.Output)
	}
	after, err := collectPatchesLinux(t.Context(), nil, "")
	if err != nil || len(after) != 0 {
		t.Fatalf("still pending after a full upgrade: %v %v", after, err)
	}
	t.Logf("full upgrade applied %d updates; reboot required: %v", len(patches), res.RebootRequired)
}

func first(p []proto.PatchInfo) any {
	if len(p) == 0 {
		return nil
	}
	return p[0]
}
