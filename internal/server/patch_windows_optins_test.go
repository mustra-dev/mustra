package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/patchpolicy"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func TestValidateWindowsOptIns(t *testing.T) {
	for _, c := range []struct {
		name  string
		kind  string
		rules patchpolicy.Rules
		err   string
	}{
		{"nothing", "allow", patchpolicy.Rules{}, ""},
		{"drivers on a patch list", "allow", patchpolicy.Rules{Drivers: true}, ""},
		{"target, lower case", "allow", patchpolicy.Rules{FeatureTargetVersion: " 25h2 "}, ""},
		{"old style version", "allow", patchpolicy.Rules{FeatureHoldVersion: "1909"}, ""},
		{"hold on a block list", "block", patchpolicy.Rules{FeatureHoldVersion: "24H2"}, ""},
		{"nonsense version", "allow", patchpolicy.Rules{FeatureTargetVersion: "latest"}, "release name"},
		{"drivers on a block list", "block", patchpolicy.Rules{Drivers: true}, "patch list"},
		{"target on a block list", "block", patchpolicy.Rules{FeatureTargetVersion: "25H2"}, "patch list"},
		{"target past hold", "allow", patchpolicy.Rules{FeatureTargetVersion: "25H2", FeatureHoldVersion: "24H2"}, "past the hold"},
	} {
		p := store.PatchPolicy{Name: "x", Kind: c.kind, Rules: c.rules}
		err := validatePatchPolicy(&p)
		if (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.err)
		}
		if c.name == "target, lower case" && p.Rules.FeatureTargetVersion != "25H2" {
			t.Errorf("target not normalised: %q", p.Rules.FeatureTargetVersion)
		}
	}
}

// A list saved before the opt-ins existed has rules JSON without them, and
// reads as opted in to nothing.
func TestOldPatchListRulesReadAsNoOptIns(t *testing.T) {
	var r patchpolicy.Rules
	if err := json.Unmarshal([]byte(`{"severities":["security"],"min_age_days":7}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Drivers || r.FeatureTargetVersion != "" || r.FeatureHoldVersion != "" {
		t.Fatalf("old rules gained opt-ins: %+v", r)
	}
}

// What an agent from before the split sends (no category, driver, target
// or hotpatch) survives ingestion unchanged, and the new fields survive
// for a new agent.
func TestPatchSnapshotsOldAndNewAgents(t *testing.T) {
	old := []byte(`[{"name":"Intel Corporation - Display - 32.0.101.6000","severity":""}]`)
	out, err := normalizeSnapshotData(proto.SensorPatches, old)
	if err != nil {
		t.Fatal(err)
	}
	var got []proto.PatchInfo
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 1 || got[0].Category != "" || got[0].Driver != nil {
		t.Fatalf("old agent snapshot changed: %s (%v)", out, err)
	}
	fresh := []byte(`[{"name":"Intel Corporation - Display - 32.0.101.6000","new_version":"32.0.101.6000","category":"driver",
		"driver":{"class":"Display","manufacturer":"Intel Corporation","date":"2026-09-30"}},
		{"name":"Feature update to Windows 11, version 25H2","category":"feature","target_product":"Windows 11","target_version":"25H2","restart_required":true},
		{"name":"2026-11 Security Hotpatch Update (KB5070002)","severity":"security","hotpatch":true}]`)
	out, err = normalizeSnapshotData(proto.SensorPatches, fresh)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 3 {
		t.Fatalf("%s (%v)", out, err)
	}
	if got[0].Driver == nil || got[0].Driver.Class != "Display" || got[1].TargetVersion != "25H2" || !got[2].Hotpatch {
		t.Fatalf("new fields lost: %+v", got)
	}

	hp, err := normalizeSnapshotData(proto.SensorHotpatch, []byte(`[{"vbs":"running","enrolled":true,"eligible":true,"edition":"Enterprise"}]`))
	if err != nil || !strings.Contains(string(hp), `"enrolled":true`) {
		t.Fatalf("hotpatch snapshot: %s %v", hp, err)
	}
}
