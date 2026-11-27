package scarules

import "testing"

// Corpus is shared with internal/agent's consistency test, which checks
// every rule here marked unsupported is also "not understood" by the
// evaluator itself.
func TestUnsupportedByRuleType(t *testing.T) {
	for _, c := range Corpus {
		got := Unsupported(c.Rule, c.Platform)
		if (got != "") != c.Unsupported {
			t.Errorf("%s on %q: Unsupported = %q, want unsupported=%v", c.Rule, c.Platform, got, c.Unsupported)
		}
	}
}

func TestEveryRuleTypeIsCovered(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Corpus {
		if !c.Unsupported {
			seen[c.Kind] = true
		}
	}
	for _, k := range []string{"file", "file content", "directory", "directory file", "directory content",
		"command", "process", "registry", "negation", "numeric compare", "line conjunction", "literal"} {
		if !seen[k] {
			t.Errorf("no supported %s rule in the corpus", k)
		}
	}
}
