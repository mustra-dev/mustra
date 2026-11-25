package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

// A search result as wuaSearchScript prints it: one quality update, one
// hotpatch, one driver and one feature update. No Windows Update is
// involved; this is the decoding and classification alone.
const wuaSample = `[
 {"Title":"2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5070001)","Severity":"Critical","Type":1,
  "Categories":[{"Id":"0fa1201d-4330-4fa8-8ae9-b877473b6441","Name":"Security Updates","Type":"UpdateClassification"},{"Id":"x","Name":"Windows 11","Type":"Product"}],"RebootBehavior":1},
 {"Title":"2026-11 Security Hotpatch Update for Windows 11 Enterprise Version 24H2 for x64-based Systems (KB5070002)","Severity":"Important","Type":1,
  "Categories":{"Id":"0fa1201d-4330-4fa8-8ae9-b877473b6441","Name":"Security Updates","Type":"UpdateClassification"},"RebootBehavior":0},
 {"Title":"Intel Corporation - Display - 32.0.101.6000","Severity":"","Type":2,
  "Categories":[{"Id":"ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0","Name":"Drivers","Type":"UpdateClassification"}],"RebootBehavior":2,
  "DriverClass":"Display","DriverManufacturer":"Intel Corporation","DriverProvider":"Intel Corporation","DriverModel":"Intel(R) Iris(R) Xe Graphics","DriverDate":"2026-09-30"},
 {"Title":"Feature update to Windows 11, version 25H2","Severity":"","Type":1,
  "Categories":[{"Id":"3689bdc8-b205-4af4-8d4a-a63924c5e9d5","Name":"Upgrades","Type":"UpdateClassification"}],"RebootBehavior":1}
]`

func TestClassifyWindowsUpdates(t *testing.T) {
	got, err := decodeWUASearch([]byte(wuaSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d updates", len(got))
	}
	cu, hp, drv, feat := got[0], got[1], got[2], got[3]
	if cu.Category != "" || cu.Hotpatch || cu.Severity != "security" {
		t.Errorf("cumulative update misread: %+v", cu)
	}
	if hp.Category != "" || !hp.Hotpatch {
		t.Errorf("hotpatch not marked: %+v", hp)
	}
	if drv.Category != proto.PatchCategoryDriver || drv.NewVersion != "32.0.101.6000" || drv.Driver == nil ||
		drv.Driver.Class != "Display" || drv.Driver.Manufacturer != "Intel Corporation" || drv.Driver.Date != "2026-09-30" {
		t.Errorf("driver misread: %+v %+v", drv, drv.Driver)
	}
	if feat.Category != proto.PatchCategoryFeature || feat.TargetVersion != "25H2" || feat.TargetProduct != "Windows 11" || !feat.RestartRequired {
		t.Errorf("feature update misread: %+v", feat)
	}
}

// What an agent before the split printed (Title and Severity only), and a
// lone object for a single update, still decode as ordinary updates.
func TestDecodeWUASearchOldShapeAndSingle(t *testing.T) {
	got, err := decodeWUASearch([]byte(`{"Title":"Intel Corporation - Display - 32.0.101.6000","Severity":""}`))
	if err != nil || len(got) != 1 || got[0].Category != "" || got[0].Name != "Intel Corporation - Display - 32.0.101.6000" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, err := decodeWUASearch([]byte("  ")); err != nil || got != nil {
		t.Fatalf("empty output: %+v, %v", got, err)
	}
}

func TestFeatureTargetFromTitles(t *testing.T) {
	for _, c := range []struct{ title, product, version string }{
		{"Feature update to Windows 11, version 24H2", "Windows 11", "24H2"},
		{"Windows 11 (business editions), version 25h2 x64 2025-10B", "Windows 11", "25H2"},
		{"Feature update to Windows 10, version 22H2", "Windows 10", "22H2"},
		{"Feature update to Windows 10, version 1909", "Windows 10", "1909"},
		{"Windows 11 upgrade", "", ""},
	} {
		p, v := featureTarget(c.title)
		if p != c.product || v != c.version {
			t.Errorf("%q: got (%q, %q)", c.title, p, v)
		}
	}
	// A title alone marks a feature update when the classification is
	// missing (an older WSUS).
	got := classifyWindowsUpdate(wuaUpdate{Title: "Feature update to Windows 11, version 24H2"})
	if got.Category != proto.PatchCategoryFeature || got.TargetVersion != "24H2" {
		t.Errorf("title-only feature update: %+v", got)
	}
	// "Hotpatch" in the title of an update Windows says always restarts
	// is not trusted to skip a restart.
	if classifyWindowsUpdate(wuaUpdate{Title: "Security Hotpatch Update (KB1)", RebootBehavior: 1}).Hotpatch {
		t.Error("an always-reboot update was marked a hotpatch")
	}
}

func TestWindowsSelectionDefaultsLeaveDriversAndFeaturesAlone(t *testing.T) {
	pending, _ := decodeWUASearch([]byte(wuaSample))
	install, eula, skipped, notes := windowsSelection(pending, nil, patchApplyOptions{})
	if len(install) != 2 || !strings.Contains(install[0], "Cumulative") || !strings.Contains(install[1], "Hotpatch") {
		t.Fatalf("install = %v", install)
	}
	if len(eula) != 0 || len(skipped) != 2 || len(notes) != 2 {
		t.Fatalf("eula=%v skipped=%v notes=%v", eula, skipped, notes)
	}
	// Named by an older server, or a list written before the split: still
	// not installed without the command's opt-in.
	install, _, skipped, _ = windowsSelection(pending, []string{pending[2].Name, pending[3].Name}, patchApplyOptions{})
	if len(install) != 0 || len(skipped) != 2 {
		t.Fatalf("named driver/feature installed without opt-in: install=%v", install)
	}
}

func TestWindowsSelectionOptIns(t *testing.T) {
	pending, _ := decodeWUASearch([]byte(wuaSample))
	install, eula, skipped, _ := windowsSelection(pending, nil, patchApplyOptions{IncludeDrivers: true, FeatureTarget: "25H2"})
	if len(install) != 4 || len(skipped) != 0 || len(eula) != 2 {
		t.Fatalf("install=%v eula=%v skipped=%v", install, eula, skipped)
	}
	// A different target leaves the feature update alone.
	install, _, skipped, notes := windowsSelection(pending, nil, patchApplyOptions{FeatureTarget: "26H1"})
	if slices.Contains(install, pending[3].Name) || !slices.Contains(skipped, pending[3].Name) || !strings.Contains(strings.Join(notes, "\n"), "26H1") {
		t.Fatalf("wrong target installed: install=%v notes=%v", install, notes)
	}
	// Non-Windows patches carry no category and are all installable.
	if got := installableByDefault([]proto.PatchInfo{{Name: "openssl"}, {Name: "curl"}}, patchApplyOptions{}); len(got) != 2 {
		t.Fatalf("linux patches filtered: %v", got)
	}
}

func TestSkipRestartForHotpatches(t *testing.T) {
	hot := "2026-11 Security Hotpatch Update for Windows 11 Enterprise Version 24H2 (KB5070002)"
	cu := "2026-11 Cumulative Update for Windows 11 Version 24H2 (KB5070001)"
	for _, c := range []struct {
		name      string
		mode      string
		required  bool
		installed []string
		blocked   string
		want      bool
	}{
		{"all hotpatches, always", "always", false, []string{hot}, "", true},
		{"all hotpatches, if required", "if_required", false, []string{hot}, "", true},
		{"no restart asked", "", false, []string{hot}, "", false},
		{"a cumulative update too", "always", false, []string{hot, cu}, "", false},
		{"windows wants a restart anyway", "always", true, []string{hot}, "", false},
		{"nothing installed", "always", false, nil, "", false},
		{"failed run", "always", false, []string{hot}, "the updates did not finish cleanly.", false},
	} {
		if got := skipRestartForHotpatches(c.mode, c.required, c.installed, c.blocked); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestPatchApplyTimeoutForFeatureUpdates(t *testing.T) {
	if patchApplyTimeoutFor(patchApplyOptions{}) != patchApplyTimeout || patchApplyTimeoutFor(patchApplyOptions{FeatureTarget: "25H2"}) != featureUpdateApplyTimeout {
		t.Fatal("feature updates need the longer budget")
	}
}
