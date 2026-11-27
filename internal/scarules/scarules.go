// Package scarules reads a rule in the SCA dialect that Comply and Enforce
// share, and says whether the endpoint engine (internal/agent's
// evaluateRule) will evaluate it at all, without running anything.
//
// It exists for turning a hardening check into an Enforce setting. The two
// use the same dialect and the same evaluator on the endpoint, so the
// translation keeps every rule verbatim; what it has to know is which rules
// the engine will answer "unknown" for whatever the machine looks like, so
// the operator is told before saving instead of finding a setting that can
// never be compliant. A rule is never dropped: one left out would make the
// setting check less than the benchmark does and pass where the benchmark
// fails.
//
// The forms mirror internal/agent/compliance.go. A test in that package
// holds the two together: every rule this package calls unsupported must
// be "not understood" by the evaluator. The reverse is weaker by nature:
// a supported rule can still be unknown at run time (commands disabled on
// the endpoint, the process list unavailable).
package scarules

import (
	"regexp"
	"strings"
)

// Unsupported returns why the endpoint engine cannot evaluate rule on
// platform ("linux", "windows", "darwin", or "" for any), or "" when it
// can.
func Unsupported(rule, platform string) string {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "the rule is empty"
	}
	if rest, negated := strings.CutPrefix(rule, "not "); negated {
		return Unsupported(rest, platform)
	}
	if strings.HasPrefix(rule, "r:") {
		return registry(rule, platform)
	}

	target, matcher, hasMatcher := strings.Cut(rule, " -> ")
	target = strings.TrimSpace(target)
	matcher = strings.TrimSpace(matcher)

	if strings.HasPrefix(target, "d:") {
		return directory(matcher, hasMatcher)
	}
	if hasMatcher && !matcherUnderstood(matcher) {
		return "the matcher " + quote(matcher) + " is not a form the engine reads (r:, !r:, n: … compare, a literal, or those joined with &&), or its regular expression does not compile"
	}
	switch {
	case strings.HasPrefix(target, "f:"), strings.HasPrefix(target, "c:"), strings.HasPrefix(target, "p:"):
		return ""
	}
	return "the rule type is not one the engine reads (f:, d:, c:, p:, r:)"
}

// registryRoots are the hive names the Windows evaluator opens.
var registryRoots = map[string]bool{
	"HKEY_LOCAL_MACHINE": true, "HKLM": true,
	"HKEY_CURRENT_USER": true, "HKCU": true,
	"HKEY_CLASSES_ROOT": true, "HKCR": true,
	"HKEY_USERS": true, "HKU": true,
	"HKEY_CURRENT_CONFIG": true, "HKCC": true,
}

func registry(rule, platform string) string {
	if platform != "" && platform != "windows" {
		return "registry rules are evaluated only on Windows"
	}
	rest := strings.TrimSpace(strings.TrimPrefix(rule, "r:"))
	parts := strings.SplitN(rest, " -> ", 3)
	root, _, ok := strings.Cut(strings.TrimSpace(parts[0]), `\`)
	if !ok || !registryRoots[strings.ToUpper(strings.TrimSpace(root))] {
		return "the registry key does not start with a hive the engine opens (HKLM, HKCU, HKCR, HKU, HKCC)"
	}
	if len(parts) == 3 && !matcherUnderstood(strings.TrimSpace(parts[2])) {
		return "the value matcher " + quote(strings.TrimSpace(parts[2])) + " is not a form the engine reads"
	}
	return ""
}

func directory(rest string, hasMatcher bool) string {
	if !hasMatcher {
		return ""
	}
	name, content, hasContent := strings.Cut(rest, " -> ")
	if !lineMatcherOK(strings.TrimSpace(name)) {
		return "the file-name matcher " + quote(strings.TrimSpace(name)) + " is not r:, !r: or n: terms joined with &&"
	}
	if hasContent && !matcherUnderstood(strings.TrimSpace(content)) {
		return "the content matcher " + quote(strings.TrimSpace(content)) + " is not a form the engine reads"
	}
	return ""
}

var (
	compareRe       = regexp.MustCompile(`^n:(.+?)\s+compare\s+(>=|<=|==|!=|>|<)\s*(-?\d+)$`)
	unknownPrefixRe = regexp.MustCompile(`^[a-z]{1,6}:`)
)

// matcherUnderstood is the agent's function of the same name.
func matcherUnderstood(matcher string) bool {
	matcher = strings.TrimSpace(matcher)
	if strings.Contains(matcher, " && ") {
		return lineMatcherOK(matcher)
	}
	if strings.HasPrefix(matcher, "n:") {
		// Shape only, as the agent checks it: a capture that does not
		// compile is found when the rule runs, and only if the file or
		// command it reads exists.
		return compareRe.MatchString(matcher)
	}
	matcher = strings.TrimPrefix(matcher, "!")
	if !strings.HasPrefix(matcher, "r:") && !strings.HasPrefix(matcher, "n:") && unknownPrefixRe.MatchString(matcher) {
		return false
	}
	pattern, ok := strings.CutPrefix(matcher, "r:")
	if !ok {
		return matcher != "" // a literal to compare against
	}
	_, err := regexp.Compile("(?im)" + pattern)
	return err == nil
}

// lineMatcherOK is the agent's parseLineMatcher, answering only whether it
// parses.
func lineMatcherOK(matcher string) bool {
	terms := strings.Split(matcher, " && ")
	for _, term := range terms {
		term = strings.TrimSpace(term)
		var pattern string
		switch {
		case strings.HasPrefix(term, "n:"):
			m := compareRe.FindStringSubmatch(term)
			if m == nil {
				return false
			}
			pattern = m[1]
		case strings.HasPrefix(term, "!r:"):
			pattern = strings.TrimPrefix(term, "!r:")
		case strings.HasPrefix(term, "r:"):
			pattern = strings.TrimPrefix(term, "r:")
		default:
			return false
		}
		if _, err := regexp.Compile("(?i)" + pattern); err != nil {
			return false
		}
	}
	return len(terms) > 0
}

func quote(s string) string {
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return "“" + s + "”"
}
