// Package patchpolicy decides which pending patches an endpoint may
// receive. It is pure: lists in, decision out, so the rule semantics can be
// tested without a database or an agent.
//
// The model: a patch list says what MAY be applied, a
// block list says what may NOT, and both are rule-based (severity, OS,
// name pattern, age) rather than hand-picked. The resolution is
//
//	allowed = pending ∩ (union of the patch lists that cover the endpoint)
//	          − (union of the block lists that cover the endpoint)
//
// with one deliberate asymmetry: an endpoint no patch list covers is
// unrestricted (everything pending is allowed), while an endpoint no block
// list covers simply has nothing blocked. A fleet with no lists at all
// therefore behaves exactly as before lists existed.
//
// Windows driver updates and feature updates (a new Windows version) are
// the exception to "unrestricted": neither is ever allowed unless a patch
// list covering the endpoint opts in, drivers with Rules.Drivers and a
// feature update with Rules.FeatureTargetVersion naming its exact target.
// A hold (Rules.FeatureHoldVersion) on any list covering the endpoint
// blocks every feature update past that version, whatever else admits it.
// Only agents that classify Windows updates report either kind, so for
// every other endpoint nothing here changes.
package patchpolicy

import (
	"path"
	"strings"
	"time"
)

// Rules is the matching part of a list. Empty slices match anything, so a
// list with no rules matches every patch; a list is the AND of its
// non-empty rules, and each rule is the OR of its values.
type Rules struct {
	Severities   []string `json:"severities,omitempty"`    // "security" | "" (unclassified)
	OS           []string `json:"os,omitempty"`            // linux | windows | darwin
	NamePatterns []string `json:"name_patterns,omitempty"` // case-insensitive globs: linux-image-*, KB50*, "2026-09 Cumulative*"
	// MinAgeDays admits a patch only once the fleet has seen it pending
	// for this many days: "nothing younger than a week" is the classic
	// ring-zero rule. Age is measured from first observation anywhere in
	// the fleet, the closest thing to a release date every OS can give.
	MinAgeDays int `json:"min_age_days,omitempty"`
	// Drivers, on a patch list, also admits the Windows driver updates its
	// other rules match. Without a list that sets it, driver updates are
	// never installed.
	Drivers bool `json:"drivers,omitempty"`
	// FeatureTargetVersion, on a patch list, admits the Windows feature
	// update to exactly this version ("24H2") when its other rules match.
	// Without it no feature update is ever installed.
	FeatureTargetVersion string `json:"feature_target_version,omitempty"`
	// FeatureHoldVersion holds Windows at this version ("23H2"): on any
	// list covering an endpoint, patch list or block list, it blocks
	// every feature update to a newer version, and one whose version is
	// unknown, even when another list names it as a target.
	FeatureHoldVersion string `json:"feature_hold_version,omitempty"`
}

// The Patch.Category values, as agents report them (proto.PatchInfo).
const (
	CategoryDriver  = "driver"
	CategoryFeature = "feature"
)

// List is a patch list (Kind "allow") or a block list (Kind "block").
type List struct {
	ID      string
	Name    string
	Kind    string // allow | block
	Enabled bool
	Rules   Rules
}

// Patch is one pending update as an endpoint reports it, plus what the
// fleet knows about it.
type Patch struct {
	Name       string
	NewVersion string
	Severity   string
	OS         string
	FirstSeen  time.Time // zero when unknown; treated as brand new
	Superseded bool
	// Category is "", CategoryDriver or CategoryFeature; TargetVersion is
	// a feature update's target ("24H2").
	Category      string
	TargetVersion string
}

// Decision is what an endpoint should be told to apply.
type Decision struct {
	Allowed []Patch
	// Blocked maps a patch name to the list that stopped it, or to
	// "not in any patch list" when no allow list admitted it.
	Blocked map[string]string
	// Restricted is whether any list changed the outcome for this
	// endpoint. A dispatcher uses it to decide whether an agent that
	// cannot apply a subset (too old to understand the list) may still be
	// told "apply everything".
	Restricted bool
	// IncludeDrivers is whether Allowed holds a driver update, and
	// FeatureTarget the version of the feature update it holds, if any:
	// the agent installs neither kind without being told.
	IncludeDrivers bool
	FeatureTarget  string
}

// Match reports whether the rules admit the patch at the given instant.
func (r Rules) Match(p Patch, now time.Time) bool {
	if len(r.OS) > 0 && !containsFold(r.OS, p.OS) {
		return false
	}
	if len(r.Severities) > 0 && !containsFold(r.Severities, p.Severity) {
		return false
	}
	if len(r.NamePatterns) > 0 && !anyGlob(r.NamePatterns, p.Name) {
		return false
	}
	if r.MinAgeDays > 0 {
		if p.FirstSeen.IsZero() {
			return false
		}
		if now.Sub(p.FirstSeen) < time.Duration(r.MinAgeDays)*24*time.Hour {
			return false
		}
	}
	return true
}

// Evaluate applies the lists that cover one endpoint to its pending
// patches. Disabled lists are ignored. Order is preserved so the agent
// applies in the order the endpoint reported.
func Evaluate(pending []Patch, lists []List, now time.Time) Decision {
	d := Decision{Blocked: map[string]string{}}
	var allows, blocks []List
	for _, l := range lists {
		if !l.Enabled {
			continue
		}
		switch l.Kind {
		case "allow":
			allows = append(allows, l)
		case "block":
			blocks = append(blocks, l)
		}
	}
	// A hold on any list covering the endpoint applies, a patch list's or
	// a block list's: the lowest one wins.
	hold, holdBy := "", ""
	for _, l := range append(append([]List{}, allows...), blocks...) {
		if h := strings.TrimSpace(l.Rules.FeatureHoldVersion); h != "" && (hold == "" || CompareVersions(h, hold) < 0) {
			hold, holdBy = h, l.Name
		}
	}
	for _, p := range pending {
		if why := optInRefusal(p, allows, hold, holdBy, now); why != "" {
			d.Blocked[p.Name] = why
			d.Restricted = true
			continue
		}
		if len(allows) > 0 {
			admitted := false
			for _, l := range allows {
				if l.Rules.Match(p, now) {
					admitted = true
					break
				}
			}
			if !admitted {
				d.Blocked[p.Name] = "not in any patch list"
				d.Restricted = true
				continue
			}
		}
		blocked := false
		for _, l := range blocks {
			if l.Rules.holdOnly() {
				continue
			}
			if l.Rules.Match(p, now) {
				d.Blocked[p.Name] = "blocked by " + l.Name
				d.Restricted = true
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		if p.Category == CategoryFeature {
			// One Windows upgrade per run: two would race each other, and
			// Windows offers only one at a time anyway.
			if d.FeatureTarget != "" {
				d.Blocked[p.Name] = "another feature update is already in this run"
				d.Restricted = true
				continue
			}
			d.FeatureTarget = p.TargetVersion
		}
		if p.Category == CategoryDriver {
			d.IncludeDrivers = true
		}
		d.Allowed = append(d.Allowed, p)
	}
	// A run carrying a driver or a feature update always names what it
	// installs, never "everything pending", so nothing the endpoint found
	// after the server last looked rides along with it.
	if d.IncludeDrivers || d.FeatureTarget != "" {
		d.Restricted = true
	}
	return d
}

// holdOnly is a block list that only holds the Windows version. With no
// other rules it would otherwise match, and block, every patch.
func (r Rules) holdOnly() bool {
	return strings.TrimSpace(r.FeatureHoldVersion) != "" && len(r.Severities) == 0 && len(r.OS) == 0 &&
		len(r.NamePatterns) == 0 && r.MinAgeDays == 0
}

// optInRefusal is why a driver or feature update may not be applied before
// the ordinary rules are even consulted, or "" when it may (or is neither).
func optInRefusal(p Patch, allows []List, hold, holdBy string, now time.Time) string {
	switch p.Category {
	case CategoryDriver:
		for _, l := range allows {
			if l.Rules.Drivers && l.Rules.Match(p, now) {
				return ""
			}
		}
		return "driver update: no patch list covering this endpoint includes drivers"
	case CategoryFeature:
		if hold != "" && (p.TargetVersion == "" || CompareVersions(p.TargetVersion, hold) > 0) {
			return "feature update: Windows is held at " + hold + " by " + holdBy
		}
		if p.TargetVersion == "" {
			return "feature update: its target version is unknown, so no patch list can name it"
		}
		for _, l := range allows {
			if t := strings.TrimSpace(l.Rules.FeatureTargetVersion); t != "" && strings.EqualFold(t, p.TargetVersion) && l.Rules.Match(p, now) {
				return ""
			}
		}
		return "feature update to " + p.TargetVersion + ": no patch list covering this endpoint targets that version"
	}
	return ""
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

// anyGlob matches case-insensitively with * and ? wildcards. A pattern
// with no wildcard is a substring test, because "cumulative" is what an
// operator types when they mean every cumulative update.
func anyGlob(patterns []string, name string) bool {
	lname := strings.ToLower(name)
	for _, pat := range patterns {
		lpat := strings.ToLower(strings.TrimSpace(pat))
		if lpat == "" {
			continue
		}
		if !strings.ContainsAny(lpat, "*?[") {
			if strings.Contains(lname, lpat) {
				return true
			}
			continue
		}
		if ok, err := path.Match(lpat, lname); err == nil && ok {
			return true
		}
	}
	return false
}

// MarkSuperseded flags, within each (OS, name) family, every version that
// is lower than the highest version any endpoint reports pending. That is
// The rule: a patch is superseded the moment one endpoint has seen
// its replacement. Patches with no version (Windows titles, macOS labels)
// are never superseded this way; their platform hides replaced updates
// itself.
func MarkSuperseded(patches []Patch) {
	type key struct{ os, name string }
	highest := map[key]string{}
	for _, p := range patches {
		if p.NewVersion == "" {
			continue
		}
		k := key{p.OS, p.Name}
		if cur, ok := highest[k]; !ok || CompareVersions(p.NewVersion, cur) > 0 {
			highest[k] = p.NewVersion
		}
	}
	for i := range patches {
		p := &patches[i]
		if p.NewVersion == "" {
			continue
		}
		if h := highest[key{p.OS, p.Name}]; h != "" && CompareVersions(p.NewVersion, h) < 0 {
			p.Superseded = true
		}
	}
}

// CompareVersions orders package-manager version strings well enough to
// tell "newer" from "older" across dpkg, rpm and plain dotted forms: the
// strings are split into digit and non-digit runs, digit runs compare
// numerically and the rest lexically, a tilde sorts before anything (dpkg
// "~rc1" < release), and an epoch "1:" is just a leading number.
func CompareVersions(a, b string) int {
	ra, rb := runs(a), runs(b)
	for i := 0; i < len(ra) || i < len(rb); i++ {
		var x, y string
		if i < len(ra) {
			x = ra[i]
		}
		if i < len(rb) {
			y = rb[i]
		}
		if x == y {
			continue
		}
		// A tilde run sorts below everything, including the end of string.
		xt, yt := strings.HasPrefix(x, "~"), strings.HasPrefix(y, "~")
		if xt != yt {
			if xt {
				return -1
			}
			return 1
		}
		xd, yd := isDigits(x), isDigits(y)
		switch {
		case xd && yd:
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
			if x < y {
				return -1
			}
			return 1
		case xd:
			return 1 // "1.2.3" > "1.2.3-rc" is not this case; digits beat letters at the same position
		case yd:
			return -1
		default:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func runs(v string) []string {
	var out []string
	cur := strings.Builder{}
	curDigit := false
	for _, c := range v {
		d := c >= '0' && c <= '9'
		if cur.Len() > 0 && d != curDigit {
			out = append(out, cur.String())
			cur.Reset()
		}
		curDigit = d
		cur.WriteRune(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
