package agent

import (
	"context"
	"runtime"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/scarules"
)

// The server tells an operator, before an Enforce setting is saved from a
// hardening check, which of its rules this evaluator cannot read. That
// warning is only worth anything if it agrees with the evaluator: a rule
// called unsupported there must be "not understood" here, and the plain
// supported forms (which name nothing that exists) must get a definite
// answer.
func TestScarulesAgreesWithTheEvaluator(t *testing.T) {
	ctx := context.Background()
	for _, c := range scarules.Corpus {
		unsupported := scarules.Unsupported(c.Rule, runtime.GOOS) != ""
		_, known := evaluateRule(ctx, c.Rule)
		if unsupported && known {
			t.Errorf("%s: scarules calls it unsupported on %s, but the evaluator answered it", c.Rule, runtime.GOOS)
		}
		if !c.Unsupported && (c.Platform == "" || c.Platform == runtime.GOOS) && !known {
			t.Errorf("%s: a supported %s rule was not understood by the evaluator", c.Rule, c.Kind)
		}
	}
}

// A setting whose only rule the engine cannot read is unknown, never
// drifted, and so is never remediated, even when the server allows it.
func TestUnsupportedRuleSettingIsUnknownAndUntouched(t *testing.T) {
	res := enforceSetting(context.Background(), proto.EnforceSetting{
		ID: "set-1", Name: "from a benchmark", Rules: []string{"x:/etc/passwd"},
		RemediateLinux: "exit 1", RemediateDarwin: "exit 1", RemediateWindows: "exit 1", Enforce: true,
	})
	if res.State != "unknown" || res.Output != "" {
		t.Fatalf("state %q output %q, want unknown with nothing run", res.State, res.Output)
	}
}
