package agent

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestNetSurveyCommandChecks(t *testing.T) {
	a := &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if res := a.handleCommand(context.Background(), commandOf(t, proto.AgentCommand{Cmd: "network_survey"}), nil); res.OK {
		t.Fatalf("a survey with no job started: %+v", res)
	}
	// One run at a time: a second is refused, not queued behind the first.
	a.netSurvey.running = "run-1"
	job := &proto.NetSurveyJob{RunID: "run-2", Subnets: []string{"192.0.2.0/24"}, Protocols: []string{proto.NetSurveyModbus}}
	res := a.handleCommand(context.Background(), commandOf(t, proto.AgentCommand{Cmd: "network_survey", NetSurvey: job}), nil)
	if res.OK || !strings.Contains(res.Error, "already running") {
		t.Fatalf("a concurrent survey: %+v", res)
	}
	cancelled := false
	a.netSurvey.cancel = func() { cancelled = true }
	if res := a.cancelNetSurvey("run-other"); !res.OK || cancelled {
		t.Fatalf("cancelled the wrong run: %+v", res)
	}
	if res := a.cancelNetSurvey("run-1"); !res.OK || !cancelled {
		t.Fatalf("cancel: %+v", res)
	}
}
