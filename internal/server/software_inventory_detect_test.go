package server

import (
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// A published software package used to show every endpoint as "install
// eligible", even ones that had it, because detection only ran on the
// agent. Where the detection reads nothing but the installed-apps rows, the
// last inventory answers it the same way the agent would.
func TestPublishedPackageApplicabilityFromInventory(t *testing.T) {
	present := func(pattern string) *proto.DeployCheck {
		return &proto.DeployCheck{Kind: "sensor", SensorID: "installed_apps", Quantifier: "any",
			Rows: []proto.DeployPredicate{{Field: "name", Operator: "matches", Value: pattern}}}
	}
	pkg := func(detect *proto.DeployCheck, version string) store.SoftwarePackage {
		return store.SoftwarePackage{Kind: store.KindSoftware, DeployDefinition: &proto.DeployDefinition{Version: 1,
			Variants: []proto.DeployVariant{{ID: "v", OS: "darwin", Version: version, Detection: detect,
				Actions: map[string]proto.DeployAction{"install": {}, "update": {}, "remove": {}}}}}}
	}
	mac := store.AgentRecord{AgentID: "a", OS: "darwin", Arch: "arm64"}
	inv := func(rows ...map[string]any) agentApps { return agentApps{rows: rows} }
	xcode := map[string]any{"name": "Xcode", "version": "27.2"}
	other := map[string]any{"name": "Safari", "version": "26.1"}

	cases := []struct {
		name      string
		pkg       store.SoftwarePackage
		apps      agentApps
		state     string
		wantFound string
	}{
		{"installed", pkg(present(`^Xcode$`), ""), inv(other, xcode), stateInstalled, "27.2"},
		{"missing", pkg(present(`^Xcode$`), ""), inv(other), stateInstallEligible, ""},
		// Matching is the agent's, case and all.
		{"case differs", pkg(present(`^xcode$`), ""), inv(xcode), stateInstallEligible, ""},
		{"behind the revision", pkg(present(`^Xcode$`), "27.3"), inv(xcode), stateUpdateEligible, "27.2"},
		{"on the revision", pkg(present(`^Xcode$`), "27.2"), inv(xcode), stateInstalled, "27.2"},
		{"app check", pkg(&proto.DeployCheck{Kind: "app", Name: "Xcode"}, ""), inv(xcode), stateInstalled, "27.2"},
		// Nothing to answer from: the agent decides, as before.
		{"no inventory yet", pkg(present(`^Xcode$`), ""), agentApps{}, stateInstallEligible, ""},
		{"script detection", pkg(&proto.DeployCheck{Kind: "script", Script: &proto.DeployScript{Language: "shell", Source: "true"}}, ""), inv(xcode), stateInstallEligible, ""},
		{"parameterised", pkg(&proto.DeployCheck{Kind: "sensor", SensorID: "installed_apps",
			Rows: []proto.DeployPredicate{{Field: "name", Operator: "eq", Parameter: "app"}}}, ""), inv(xcode), stateInstallEligible, ""},
	}
	for _, tc := range cases {
		state, found, reason := evaluateApplicability(tc.pkg, mac, tc.apps, nil)
		if state != tc.state {
			t.Errorf("%s: state %q (%s), want %q", tc.name, state, reason, tc.state)
		}
		if tc.wantFound != "" && found != tc.wantFound {
			t.Errorf("%s: found %q, want %q", tc.name, found, tc.wantFound)
		}
	}

	// Dispatch of a published revision is unchanged: installed still applies,
	// and the agent re-checks before it acts.
	if !operationApplies(pkg(present(`^Xcode$`), ""), "install", stateInstalled) {
		t.Error("an installed endpoint stopped being a valid target for a published revision")
	}
}
