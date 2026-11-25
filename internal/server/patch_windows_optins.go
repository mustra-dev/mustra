package server

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mustra-dev/mustra/internal/patchpolicy"
	"github.com/mustra-dev/mustra/internal/store"
)

// The Windows opt-ins on a patch list (patchpolicy.Rules: Drivers,
// FeatureTargetVersion, FeatureHoldVersion). Kept in the list's rules,
// which are stored as JSON, so they need no schema change, and a list
// saved before them reads as opted in to nothing.

// windowsVersion is how Windows names its releases: 24H2, or the older
// four-digit form (1909, 2004).
var windowsVersion = regexp.MustCompile(`^(\d{2}H[12]|\d{4})$`)

func validateWindowsOptIns(p *store.PatchPolicy) error {
	r := &p.Rules
	r.FeatureTargetVersion = strings.ToUpper(strings.TrimSpace(r.FeatureTargetVersion))
	r.FeatureHoldVersion = strings.ToUpper(strings.TrimSpace(r.FeatureHoldVersion))
	for _, v := range []string{r.FeatureTargetVersion, r.FeatureHoldVersion} {
		if v != "" && !windowsVersion.MatchString(v) {
			return fmt.Errorf("Windows version %q: use the release name, such as 24H2", v)
		}
	}
	if p.Kind == "block" && (r.Drivers || r.FeatureTargetVersion != "") {
		return fmt.Errorf("drivers and a feature update target belong on a patch list; a block list can only hold the Windows version")
	}
	if r.FeatureTargetVersion != "" && r.FeatureHoldVersion != "" &&
		patchpolicy.CompareVersions(r.FeatureTargetVersion, r.FeatureHoldVersion) > 0 {
		return fmt.Errorf("the feature update target %s is past the hold at %s", r.FeatureTargetVersion, r.FeatureHoldVersion)
	}
	return nil
}
