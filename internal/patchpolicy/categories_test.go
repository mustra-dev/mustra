package patchpolicy

import (
	"testing"
	"time"
)

func windowsPending() []Patch {
	return []Patch{
		{Name: "2026-11 Cumulative Update for Windows 11 Version 24H2 (KB5070001)", OS: "windows", Severity: "security"},
		{Name: "Intel Corporation - Display - 32.0.101.6000", OS: "windows", Category: CategoryDriver},
		{Name: "Feature update to Windows 11, version 25H2", OS: "windows", Category: CategoryFeature, TargetVersion: "25H2"},
	}
}

func allowedNames(d Decision) map[string]bool {
	out := map[string]bool{}
	for _, p := range d.Allowed {
		out[p.Name] = true
	}
	return out
}

// With no lists at all, ordinary updates stay unrestricted but drivers and
// feature updates are not installed: that is the whole default.
func TestDriversAndFeatureUpdatesExcludedByDefault(t *testing.T) {
	d := Evaluate(windowsPending(), nil, time.Now())
	got := allowedNames(d)
	if len(got) != 1 || !got["2026-11 Cumulative Update for Windows 11 Version 24H2 (KB5070001)"] {
		t.Fatalf("only the cumulative update should be allowed: %+v", d.Allowed)
	}
	if !d.Restricted {
		t.Fatal("excluding drivers must narrow the run, or the agent would be told to apply everything")
	}
	if d.IncludeDrivers || d.FeatureTarget != "" {
		t.Fatalf("nothing opted in, yet the decision carries opt-ins: %+v", d)
	}
	if d.Blocked["Intel Corporation - Display - 32.0.101.6000"] == "" || d.Blocked["Feature update to Windows 11, version 25H2"] == "" {
		t.Fatalf("each excluded update needs a reason: %+v", d.Blocked)
	}
}

// An existing patch list that matches everything still does not admit
// drivers or feature updates: the opt-in is separate from the rules.
func TestExistingListDoesNotAdmitDriversOrFeatures(t *testing.T) {
	lists := []List{{Name: "everything", Kind: "allow", Enabled: true}}
	d := Evaluate(windowsPending(), lists, time.Now())
	if got := allowedNames(d); len(got) != 1 {
		t.Fatalf("an existing list must not start installing drivers or upgrades: %+v", d.Allowed)
	}
}

func TestDriverOptIn(t *testing.T) {
	lists := []List{{Name: "drivers too", Kind: "allow", Enabled: true, Rules: Rules{Drivers: true}}}
	d := Evaluate(windowsPending(), lists, time.Now())
	got := allowedNames(d)
	if !got["Intel Corporation - Display - 32.0.101.6000"] || got["Feature update to Windows 11, version 25H2"] {
		t.Fatalf("drivers opted in, feature update not: %+v", d.Allowed)
	}
	if !d.IncludeDrivers || !d.Restricted || d.FeatureTarget != "" {
		t.Fatalf("decision flags wrong: %+v", d)
	}

	// The opting list's other rules still apply to drivers.
	lists[0].Rules.NamePatterns = []string{"nvidia*"}
	d = Evaluate(windowsPending(), lists, time.Now())
	if allowedNames(d)["Intel Corporation - Display - 32.0.101.6000"] || d.IncludeDrivers {
		t.Fatalf("a driver its name pattern does not match was admitted: %+v", d.Allowed)
	}

	// A block list still subtracts an opted-in driver.
	lists = []List{
		{Name: "drivers too", Kind: "allow", Enabled: true, Rules: Rules{Drivers: true}},
		{Name: "no Intel", Kind: "block", Enabled: true, Rules: Rules{NamePatterns: []string{"intel*"}}},
	}
	d = Evaluate(windowsPending(), lists, time.Now())
	if allowedNames(d)["Intel Corporation - Display - 32.0.101.6000"] || d.IncludeDrivers {
		t.Fatalf("block list ignored for a driver: %+v", d)
	}
}

func TestFeatureUpdateNeedsMatchingTarget(t *testing.T) {
	name := "Feature update to Windows 11, version 25H2"
	for _, tc := range []struct {
		target string
		want   bool
	}{{"25H2", true}, {"25h2", true}, {"24H2", false}, {"", false}} {
		lists := []List{{Name: "upgrade", Kind: "allow", Enabled: true, Rules: Rules{FeatureTargetVersion: tc.target}}}
		d := Evaluate(windowsPending(), lists, time.Now())
		if allowedNames(d)[name] != tc.want {
			t.Errorf("target %q: allowed=%v, want %v (%+v)", tc.target, !tc.want, tc.want, d.Blocked)
		}
		if tc.want && d.FeatureTarget != "25H2" {
			t.Errorf("target %q: FeatureTarget = %q", tc.target, d.FeatureTarget)
		}
	}
	// A feature update whose version the agent could not read is never
	// admitted, even by a list that targets something.
	unknown := []Patch{{Name: "Windows upgrade", OS: "windows", Category: CategoryFeature}}
	d := Evaluate(unknown, []List{{Name: "upgrade", Kind: "allow", Enabled: true, Rules: Rules{FeatureTargetVersion: "25H2"}}}, time.Now())
	if len(d.Allowed) != 0 {
		t.Fatalf("unknown target version admitted: %+v", d.Allowed)
	}
}

func TestFeatureHold(t *testing.T) {
	name := "Feature update to Windows 11, version 25H2"
	target := List{Name: "upgrade", Kind: "allow", Enabled: true, Rules: Rules{FeatureTargetVersion: "25H2"}}
	for _, tc := range []struct {
		hold List
		want bool
	}{
		{List{Name: "hold 24H2", Kind: "block", Enabled: true, Rules: Rules{FeatureHoldVersion: "24H2"}}, false},
		{List{Name: "hold 25H2", Kind: "block", Enabled: true, Rules: Rules{FeatureHoldVersion: "25H2"}}, true},
		{List{Name: "hold on a patch list", Kind: "allow", Enabled: true, Rules: Rules{FeatureHoldVersion: "24H2"}}, false},
		{List{Name: "disabled hold", Kind: "block", Enabled: false, Rules: Rules{FeatureHoldVersion: "24H2"}}, true},
	} {
		d := Evaluate(windowsPending(), []List{target, tc.hold}, time.Now())
		if allowedNames(d)[name] != tc.want {
			t.Errorf("%s: allowed=%v, want %v (%v)", tc.hold.Name, !tc.want, tc.want, d.Blocked[name])
		}
	}
}

func TestOneFeatureUpdatePerRun(t *testing.T) {
	pending := []Patch{
		{Name: "Feature update to Windows 11, version 25H2", OS: "windows", Category: CategoryFeature, TargetVersion: "25H2"},
		{Name: "Windows 11, version 25H2 (enablement)", OS: "windows", Category: CategoryFeature, TargetVersion: "25H2"},
	}
	d := Evaluate(pending, []List{{Name: "upgrade", Kind: "allow", Enabled: true, Rules: Rules{FeatureTargetVersion: "25H2"}}}, time.Now())
	if len(d.Allowed) != 1 || len(d.Blocked) != 1 {
		t.Fatalf("want one feature update allowed, one held back: %+v", d)
	}
}

// Agents that do not classify updates (every non-Windows agent, and
// Windows agents from before the split) report no categories, and the
// decision is exactly what it was.
func TestUnclassifiedPatchesUnchanged(t *testing.T) {
	pending := []Patch{{Name: "openssl", OS: "linux"}, {Name: "Some Driver - 1.0", OS: "windows"}}
	d := Evaluate(pending, nil, time.Now())
	if len(d.Allowed) != 2 || d.Restricted || d.IncludeDrivers || d.FeatureTarget != "" {
		t.Fatalf("unclassified patches must behave as before: %+v", d)
	}
}

// A block list that only holds the version blocks feature updates, not
// every patch, as an empty block list otherwise would.
func TestHoldOnlyBlockListBlocksNothingElse(t *testing.T) {
	hold := List{Name: "stay on 24H2", Kind: "block", Enabled: true, Rules: Rules{FeatureHoldVersion: "24H2"}}
	d := Evaluate(windowsPending(), []List{hold}, time.Now())
	if !allowedNames(d)["2026-11 Cumulative Update for Windows 11 Version 24H2 (KB5070001)"] {
		t.Fatalf("a hold-only block list blocked an ordinary update: %+v", d.Blocked)
	}
}
