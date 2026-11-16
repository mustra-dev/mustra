package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// startPatchJob records a patch job the way a dispatch does.
func startPatchJob(t *testing.T, st *store.Store, runID, agent string) string {
	t.Helper()
	id := idgen.New("act-")
	if err := st.StartAgentAction(context.Background(), store.AgentAction{ID: id, AgentID: agent, Kind: "patch_apply", RunID: runID}); err != nil {
		t.Fatal(err)
	}
	return id
}

// finishWithRestart records a result that scheduled a restart, as the
// action result consumer does.
func finishWithRestart(t *testing.T, s *Server, res proto.AgentActionResult) {
	t.Helper()
	ctx := context.Background()
	status := "succeeded"
	if s.restartScheduled(ctx, res) {
		status = "pending_restart"
	}
	if err := s.store.FinishAgentAction(ctx, res.AgentID, res.ActionID, status, res.Detail); err != nil {
		t.Fatal(err)
	}
	if err := s.watchPatchRestart(ctx, res, status); err != nil {
		t.Fatal(err)
	}
}

// An endpoint that never comes back fails its job, tells the operator,
// and holds the rest of its run.
func TestPatchRestartNeverBackFailsAndHoldsRun(t *testing.T) {
	s, st, agent := threatRemediationFixture(t, "1.7.0")
	s.live.setAgent(time.Minute, 0, "") // the fixture's hour would read the restart as never happening
	ctx := context.Background()
	other := idgen.New("agt-")
	if err := st.UpsertOnRegister(ctx, other, proto.AgentInfo{Hostname: "tr-" + other, OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), other) })

	runID := idgen.New("run-")
	act := startPatchJob(t, st, runID, agent)
	held := idgen.New("act-")
	if err := st.StartAgentActionWithStatus(ctx, store.AgentAction{ID: held, AgentID: other, Kind: "patch_apply", RunID: runID}, "waiting", "outside window"); err != nil {
		t.Fatal(err)
	}
	finishWithRestart(t, s, proto.AgentActionResult{AgentID: agent, RunID: runID, ActionID: act, Kind: "patch_apply", OK: true,
		RebootRequired: true, Detail: "Verified: all 1 update(s) are installed.",
		Health: &proto.PatchHealth{Checked: true, RestartScheduled: true, RestartInMinutes: 1,
			KernelBefore: "6.1.0-54-amd64", KernelUpdates: []string{"linux-image-6.1.0-55-amd64 6.1.192-1"}}})
	if got := actionFor(t, st, runID, agent); got.Status != "pending_restart" {
		t.Fatalf("status after result = %q", got.Status)
	}

	// Within the deadline nothing happens; past it, with no check-in, the
	// job fails.
	s.judgePatchRestarts(ctx, time.Now().Add(5*time.Minute))
	if got := actionFor(t, st, runID, agent); got.Status != "pending_restart" {
		t.Fatalf("judged early: %q", got.Status)
	}
	s.judgePatchRestarts(ctx, time.Now().Add(time.Minute+patchCheckinDeadline+time.Minute))
	got := actionFor(t, st, runID, agent)
	if got.Status != "failed" || !strings.Contains(got.Detail, "did not report back") || !strings.Contains(got.Detail, "linux-image-6.1.0-55-amd64") {
		t.Fatalf("after deadline: %q %q", got.Status, got.Detail)
	}
	if h := actionFor(t, st, runID, other); h.Status != "cancelled" || !strings.Contains(h.Detail, "Held back") {
		t.Fatalf("rest of run not held: %q %q", h.Status, h.Detail)
	}
	if w, _ := st.OpenPatchRestartWatch(ctx, agent, act); w != nil {
		t.Fatal("watch still open")
	}
	notes, _, err := st.ListNotifications(ctx, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range notes {
		found = found || (n.Severity == "critical" && strings.Contains(n.Title, "did not come back healthy") && n.Link == "/endpoint/"+agent+"#activity")
	}
	if !found {
		t.Fatal("no notification raised")
	}
}

// One that comes back on a new boot is verifying until its stability
// report, which closes it as succeeded; a report of broken services after
// the restart closes it as degraded.
func TestPatchRestartBackAndStable(t *testing.T) {
	s, st, agent := threatRemediationFixture(t, "1.7.0")
	ctx := context.Background()
	for _, broken := range []bool{false, true} {
		runID := idgen.New("run-")
		act := startPatchJob(t, st, runID, agent)
		finishWithRestart(t, s, proto.AgentActionResult{AgentID: agent, RunID: runID, ActionID: act, Kind: "patch_apply", OK: true,
			Detail: "Verified: all 2 update(s) are installed.", Health: &proto.PatchHealth{Checked: true, RestartScheduled: true, RestartInMinutes: 1}})

		back := time.Now().Add(2 * time.Minute)
		if err := st.RecordFacts(ctx, proto.Facts{AgentID: agent, Hostname: "tr-" + agent, OS: "linux", Arch: "amd64",
			KernelVer: "6.1.0-55-amd64", Timestamp: back, UptimeSec: 30}); err != nil {
			t.Fatal(err)
		}
		if err := st.RecordHeartbeat(ctx, agent, back); err != nil {
			t.Fatal(err)
		}
		s.judgePatchRestarts(ctx, back.Add(10*time.Second))
		if got := actionFor(t, st, runID, agent); got.Status != "verifying" {
			t.Fatalf("after check-in: %q", got.Status)
		}
		w, err := st.OpenPatchRestartWatch(ctx, agent, act)
		if err != nil || w == nil || w.BootedAt == nil {
			t.Fatalf("watch: %+v %v", w, err)
		}
		res := proto.AgentActionResult{AgentID: agent, RunID: runID, ActionID: act, Kind: "patch_apply",
			Verification: true, Stability: true, OK: true, Detail: "Stayed up for 10m0s after the restart.",
			Health: &proto.PatchHealth{Checked: true}}
		want := "succeeded"
		if broken {
			res.OK, want = false, "degraded"
			res.Health.Regressed = []proto.UnitRegression{{Unit: "seerr.service", Before: "active (running)", After: "failed"}}
			res.Detail = "After the restart, 1 service(s) that ran before the updates are not running: seerr.service went active (running) -> failed"
		}
		if err := s.consumeWatchedVerification(ctx, res, *w); err != nil {
			t.Fatal(err)
		}
		if got := actionFor(t, st, runID, agent); got.Status != want || !strings.Contains(got.Detail, res.Detail) {
			t.Fatalf("broken=%v: %q %q", broken, got.Status, got.Detail)
		}
		if w, _ := st.OpenPatchRestartWatch(ctx, agent, act); w != nil {
			t.Fatal("watch still open")
		}
	}
}

// A job that did not schedule a restart is not watched.
func TestPatchWithoutRestartIsNotWatched(t *testing.T) {
	s, st, agent := threatRemediationFixture(t, "1.7.0")
	runID := idgen.New("run-")
	act := startPatchJob(t, st, runID, agent)
	finishWithRestart(t, s, proto.AgentActionResult{AgentID: agent, RunID: runID, ActionID: act, Kind: "patch_apply", OK: true,
		Health: &proto.PatchHealth{Checked: true}})
	if got := actionFor(t, st, runID, agent); got.Status != "succeeded" {
		t.Fatalf("status %q", got.Status)
	}
	if w, _ := st.OpenPatchRestartWatch(context.Background(), agent, act); w != nil {
		t.Fatal("watched without a restart")
	}
}
