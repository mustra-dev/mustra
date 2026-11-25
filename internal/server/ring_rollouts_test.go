package server

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/store"
)

// fakeRingDriver stands in for patch dispatch and Enforce passes, so the
// state machine is tested on its own.
type fakeRingDriver struct {
	target   []string
	groups   map[string]map[string]bool // a missing group has been deleted
	outcome  map[int]store.RingOutcome
	complete map[int]bool
	started  []int
	halt     string
	abort    string
	finished bool
}

func (f *fakeRingDriver) targets(context.Context, *store.RingRollout) ([]string, string, error) {
	return f.target, "", nil
}

func (f *fakeRingDriver) groupMembers(_ context.Context, id string) (map[string]bool, bool, error) {
	m, ok := f.groups[id]
	return m, ok, nil
}

func (f *fakeRingDriver) startRing(_ context.Context, _ *store.RingRollout, i int) (string, error) {
	f.started = append(f.started, i)
	return fmt.Sprintf("run-%d", i), nil
}

func (f *fakeRingDriver) ringOutcome(_ context.Context, r *store.RingRollout, i int, _ time.Time) (store.RingOutcome, bool, error) {
	return f.outcome[i], f.complete[i], nil
}

func (f *fakeRingDriver) stop(context.Context, *store.RingRollout) (string, string, error) {
	return f.halt, f.abort, nil
}

func (f *fakeRingDriver) finish(context.Context, *store.RingRollout) error {
	f.finished = true
	return nil
}

func newTestRollout(rings ...store.Ring) *store.RingRollout {
	r := &store.RingRollout{ID: "rollout-t", Kind: "patch", PlanID: "plan-t", Status: "running"}
	for _, ring := range rings {
		r.Rings = append(r.Rings, store.RolloutRing{Ring: ring, State: "pending", AgentIDs: []string{}})
	}
	return r
}

func agents(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("agt-%02d", i)
	}
	return out
}

// A percentage ring takes the same endpoints every time the same plan runs
// over the same target, whatever order the target arrives in, and only
// endpoints of the target that no earlier ring took.
func TestSelectRingMembersIsDeterministicAndStaysInTarget(t *testing.T) {
	target := agents(20)
	ring := store.Ring{Percent: 25}
	first := selectRingMembers(ring, "plan-a", target, nil, nil)
	if len(first) != 5 {
		t.Fatalf("25%% of 20 took %d endpoints, want 5", len(first))
	}
	reversed := slices.Clone(target)
	slices.Reverse(reversed)
	if again := selectRingMembers(ring, "plan-a", reversed, nil, nil); !slices.Equal(first, again) {
		t.Fatalf("same plan and target picked different endpoints: %v then %v", first, again)
	}
	if other := selectRingMembers(ring, "plan-b", target, nil, nil); slices.Equal(first, other) {
		t.Fatalf("a different plan picked exactly the same canaries %v; the rank should depend on the plan", other)
	}
	assigned := map[string]bool{}
	for _, id := range first {
		assigned[id] = true
	}
	next := selectRingMembers(store.Ring{Percent: 100}, "plan-a", target, assigned, nil)
	if len(next) != 15 {
		t.Fatalf("the rest of the target is 15 endpoints, got %d", len(next))
	}
	for _, id := range next {
		if assigned[id] {
			t.Fatalf("%s was taken by an earlier ring and again by this one", id)
		}
	}
	// A non-zero share of a small target is at least one endpoint.
	if got := selectRingMembers(store.Ring{Percent: 10}, "plan-a", agents(5), nil, nil); len(got) != 1 {
		t.Fatalf("10%% of 5 took %d endpoints, want 1", len(got))
	}
}

// A group ring is the group's members within the target, never a member
// the target does not include.
func TestGroupRingIsIntersectedWithTarget(t *testing.T) {
	group := map[string]bool{"agt-01": true, "agt-02": true, "agt-outside": true}
	got := selectRingMembers(store.Ring{GroupID: "cgrp-x"}, "plan", []string{"agt-01", "agt-02", "agt-03"}, nil, group)
	slices.Sort(got)
	if !slices.Equal(got, []string{"agt-01", "agt-02"}) {
		t.Fatalf("group ring took %v, want only the group's members in the target", got)
	}
	if got := selectRingMembers(store.Ring{GroupID: "cgrp-x"}, "plan", []string{"agt-03"}, nil, group); len(got) != 0 {
		t.Fatalf("a group with no member in the target took %v", got)
	}
}

// Rings go in order: a ring starts, completes, soaks, is checked again,
// and only then does the next one start. The last ring finishing completes
// the rollout.
func TestRolloutRunsRingsInOrderAfterSoak(t *testing.T) {
	ctx := context.Background()
	d := &fakeRingDriver{target: agents(10), outcome: map[int]store.RingOutcome{}, complete: map[int]bool{}}
	r := newTestRollout(store.Ring{Name: "canary", Percent: 20, SuccessRate: 100, WaitMinutes: 60}, store.Ring{Name: "rest", Percent: 100})
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	if _, err := advanceRollout(ctx, d, r, t0); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.started, []int{0}) || r.Rings[0].State != "running" || len(r.Rings[0].AgentIDs) != 2 {
		t.Fatalf("first step: started %v, ring %+v", d.started, r.Rings[0])
	}
	// Still working: nothing moves.
	d.outcome[0] = store.RingOutcome{Total: 2, Succeeded: 1, Open: 1}
	_, _ = advanceRollout(ctx, d, r, t0.Add(5*time.Minute))
	if r.Rings[0].State != "running" || len(d.started) != 1 {
		t.Fatalf("an incomplete ring moved on: %+v", r.Rings[0])
	}
	d.outcome[0], d.complete[0] = store.RingOutcome{Total: 2, Succeeded: 2}, true
	_, _ = advanceRollout(ctx, d, r, t0.Add(10*time.Minute))
	if r.Rings[0].State != "soaking" || len(d.started) != 1 {
		t.Fatalf("a passing ring should soak before the next starts: %+v, started %v", r.Rings[0], d.started)
	}
	_, _ = advanceRollout(ctx, d, r, t0.Add(30*time.Minute))
	if len(d.started) != 1 {
		t.Fatalf("the next ring started during the soak")
	}
	events, _ := advanceRollout(ctx, d, r, t0.Add(71*time.Minute))
	if r.Rings[0].State != "passed" || !slices.Equal(d.started, []int{0, 1}) || r.CurrentRing != 1 {
		t.Fatalf("after the soak: ring 0 %s, started %v, current %d", r.Rings[0].State, d.started, r.CurrentRing)
	}
	if len(r.Rings[1].AgentIDs) != 8 || r.Rings[1].RunID != "run-1" {
		t.Fatalf("the second ring should take the other 8 endpoints and record its run: %+v", r.Rings[1])
	}
	if len(events) == 0 || events[len(events)-1].Kind != "ring_started" {
		t.Fatalf("events %+v", events)
	}
	d.outcome[1], d.complete[1] = store.RingOutcome{Total: 8, Succeeded: 6, Failed: 2}, true
	events, _ = advanceRollout(ctx, d, r, t0.Add(90*time.Minute))
	if r.Status != "completed" || !d.finished || r.FinishedAt == nil {
		t.Fatalf("a last ring with no criteria should complete the rollout: %s, finished %v", r.Status, d.finished)
	}
	if events[len(events)-1].Kind != "completed" {
		t.Fatalf("events %+v", events)
	}
}

// A ring that misses its threshold halts the rollout; the next ring does
// not start until an operator resumes, which accepts the halted ring.
func TestRolloutHaltsBelowThresholdAndResumes(t *testing.T) {
	ctx := context.Background()
	d := &fakeRingDriver{target: agents(10), outcome: map[int]store.RingOutcome{}, complete: map[int]bool{}}
	r := newTestRollout(store.Ring{Name: "pilot", Percent: 50, SuccessRate: 80}, store.Ring{Name: "rest", Percent: 100})
	now := time.Now()
	_, _ = advanceRollout(ctx, d, r, now)
	d.outcome[0], d.complete[0] = store.RingOutcome{Total: 5, Succeeded: 3, Failed: 1, TimedOut: 1}, true
	events, _ := advanceRollout(ctx, d, r, now.Add(time.Minute))
	if r.Status != "halted" || r.Rings[0].State != "failed" || r.HaltReason == "" {
		t.Fatalf("60%% against 80%% should halt: status %s, ring %+v", r.Status, r.Rings[0])
	}
	if len(events) != 1 || events[0].Kind != "halted" {
		t.Fatalf("events %+v", events)
	}
	// A halted rollout does not move, however long it sits.
	_, _ = advanceRollout(ctx, d, r, now.Add(48*time.Hour))
	if !slices.Equal(d.started, []int{0}) {
		t.Fatalf("a halted rollout started ring(s) %v", d.started)
	}
	if err := resumeRollout(r, "jdoe"); err != nil {
		t.Fatal(err)
	}
	if r.Status != "running" || r.Rings[0].State != "passed" || r.CurrentRing != 1 || r.HaltReason != "" {
		t.Fatalf("after resume: %+v", r)
	}
	_, _ = advanceRollout(ctx, d, r, now.Add(49*time.Hour))
	if !slices.Equal(d.started, []int{0, 1}) {
		t.Fatalf("resume should start the next ring, started %v", d.started)
	}
	if err := resumeRollout(r, "jdoe"); err == nil {
		t.Fatal("resuming a running rollout should be refused")
	}
}

// Endpoints that never answered are not successes: they count against the
// threshold, and a ring nobody answered in has not passed even with no
// criteria set.
func TestRolloutNoResponseIsNotSuccess(t *testing.T) {
	if ok, _ := rolloutRingPassed(store.Ring{}, store.RingOutcome{Total: 3, NoResponse: 3}); ok {
		t.Fatal("a ring in which nobody reported passed")
	}
	if ok, _ := rolloutRingPassed(store.Ring{SuccessRate: 80}, store.RingOutcome{Total: 4, Succeeded: 2, NoResponse: 2}); ok {
		t.Fatal("no response counted as success")
	}
	if ok, _ := rolloutRingPassed(store.Ring{SuccessRate: 50}, store.RingOutcome{Total: 4, Succeeded: 2, NoResponse: 2}); !ok {
		t.Fatal("2 of 4 meets 50%")
	}
	if ok, _ := rolloutRingPassed(store.Ring{MinSuccess: 2}, store.RingOutcome{Total: 3, Succeeded: 1, Unknown: 2}); ok {
		t.Fatal("unknown counted as success")
	}
}

// The threshold is checked again when the soak ends: a ring that looked
// fine and then went bad halts there.
func TestRolloutRechecksThresholdAfterSoak(t *testing.T) {
	ctx := context.Background()
	d := &fakeRingDriver{target: agents(4), outcome: map[int]store.RingOutcome{}, complete: map[int]bool{}}
	r := newTestRollout(store.Ring{Name: "pilot", Percent: 50, SuccessRate: 100, WaitMinutes: 30}, store.Ring{Name: "rest", Percent: 100})
	now := time.Now()
	_, _ = advanceRollout(ctx, d, r, now)
	d.outcome[0], d.complete[0] = store.RingOutcome{Total: 2, Succeeded: 2}, true
	_, _ = advanceRollout(ctx, d, r, now.Add(time.Minute))
	if r.Rings[0].State != "soaking" {
		t.Fatalf("ring should soak, is %s", r.Rings[0].State)
	}
	// A restart check failed during the soak.
	d.outcome[0] = store.RingOutcome{Total: 2, Succeeded: 1, Failed: 1}
	_, _ = advanceRollout(ctx, d, r, now.Add(40*time.Minute))
	if r.Status != "halted" || len(d.started) != 1 {
		t.Fatalf("a ring that went bad during its soak should halt: %s, started %v", r.Status, d.started)
	}
}

// A ring whose computer group has been deleted halts the rollout: it is
// not read as everyone, and it is not quietly skipped so the broader next
// ring starts without its canary. Resuming skips it knowingly.
func TestRolloutDeletedRingGroupHaltsInsteadOfWidening(t *testing.T) {
	ctx := context.Background()
	d := &fakeRingDriver{
		target:   []string{"agt-01", "agt-02", "agt-03"},
		groups:   map[string]map[string]bool{"cgrp-web": {"agt-02": true, "agt-99": true}},
		outcome:  map[int]store.RingOutcome{},
		complete: map[int]bool{},
	}
	r := newTestRollout(store.Ring{Name: "pilot", GroupID: "cgrp-gone"}, store.Ring{Name: "web", GroupID: "cgrp-web"})
	_, _ = advanceRollout(ctx, d, r, time.Now())
	if r.Status != "halted" || len(d.started) != 0 || len(r.Rings[0].AgentIDs) != 0 {
		t.Fatalf("a deleted ring group should halt with nothing started: %s, started %v, ring %+v", r.Status, d.started, r.Rings[0])
	}
	if err := resumeRollout(r, "jdoe"); err != nil {
		t.Fatal(err)
	}
	if r.Rings[0].State != "skipped" {
		t.Fatalf("resume should skip the ring whose group is gone, got %s", r.Rings[0].State)
	}
	_, _ = advanceRollout(ctx, d, r, time.Now())
	if !slices.Equal(d.started, []int{1}) || !slices.Equal(r.Rings[1].AgentIDs, []string{"agt-02"}) {
		t.Fatalf("the web ring should take only its member in the target: started %v, ring %+v", d.started, r.Rings[1])
	}
}

// A ring none of whose endpoints is in the target is skipped, and the
// rollout carries on.
func TestRolloutSkipsEmptyRing(t *testing.T) {
	ctx := context.Background()
	d := &fakeRingDriver{target: []string{"agt-01"}, groups: map[string]map[string]bool{"cgrp-lab": {"agt-77": true}},
		outcome: map[int]store.RingOutcome{}, complete: map[int]bool{}}
	r := newTestRollout(store.Ring{Name: "lab", GroupID: "cgrp-lab"}, store.Ring{Name: "rest", Percent: 100})
	events, _ := advanceRollout(ctx, d, r, time.Now())
	if r.Rings[0].State != "skipped" || !slices.Equal(d.started, []int{1}) {
		t.Fatalf("empty ring: %+v, started %v", r.Rings[0], d.started)
	}
	if events[0].Kind != "ring_skipped" {
		t.Fatalf("events %+v", events)
	}
}

// Endpoints of the target that no ring took are counted when the rollout
// completes.
func TestRolloutCountsUntouchedEndpoints(t *testing.T) {
	ctx := context.Background()
	d := &fakeRingDriver{target: []string{"agt-01", "agt-02", "agt-03"}, groups: map[string]map[string]bool{"cgrp-a": {"agt-01": true}},
		outcome: map[int]store.RingOutcome{0: {Total: 1, Succeeded: 1}}, complete: map[int]bool{0: true}}
	r := newTestRollout(store.Ring{Name: "a", GroupID: "cgrp-a"})
	_, _ = advanceRollout(ctx, d, r, time.Now())
	_, _ = advanceRollout(ctx, d, r, time.Now())
	if r.Status != "completed" || r.Untouched != 2 {
		t.Fatalf("status %s, untouched %d; want completed with 2 untouched", r.Status, r.Untouched)
	}
}

// The kind's own stop conditions win over progress.
func TestRolloutStopConditions(t *testing.T) {
	ctx := context.Background()
	d := &fakeRingDriver{target: agents(2), abort: "the policy was deleted"}
	r := newTestRollout(store.Ring{Percent: 100})
	_, _ = advanceRollout(ctx, d, r, time.Now())
	if r.Status != "aborted" || len(d.started) != 0 {
		t.Fatalf("abort: %s, started %v", r.Status, d.started)
	}
	d = &fakeRingDriver{target: agents(2), halt: "the policy is disabled"}
	r = newTestRollout(store.Ring{Percent: 100})
	_, _ = advanceRollout(ctx, d, r, time.Now())
	if r.Status != "halted" || len(d.started) != 0 {
		t.Fatalf("halt: %s, started %v", r.Status, d.started)
	}
	// Resuming while the reason holds halts again on the next step,
	// without skipping the ring.
	_ = resumeRollout(r, "jdoe")
	if r.Rings[0].State != "pending" {
		t.Fatalf("resume skipped a ring that never had a problem: %s", r.Rings[0].State)
	}
	_, _ = advanceRollout(ctx, d, r, time.Now())
	if r.Status != "halted" {
		t.Fatalf("still disabled, should halt again: %s", r.Status)
	}
	if err := abortRollout(r, "jdoe", time.Now()); err != nil || r.Status != "aborted" {
		t.Fatalf("abort: %v %s", err, r.Status)
	}
	if err := abortRollout(r, "jdoe", time.Now()); err == nil {
		t.Fatal("aborting twice should be refused")
	}
}

// A patch ring's outcome comes from its jobs: failure, timeout and no
// response stay apart, open jobs and watched restarts keep it incomplete,
// and the deadline turns what is still open into no response.
func TestPatchRingOutcome(t *testing.T) {
	out, complete := patchRingOutcome(6, map[string]int{"succeeded": 2, "pending_restart": 1, "degraded": 1, "timed_out": 1, "installing": 1}, 0, false)
	if complete || out.Succeeded != 3 || out.Failed != 1 || out.TimedOut != 1 || out.Open != 1 {
		t.Fatalf("%+v complete=%v", out, complete)
	}
	out, complete = patchRingOutcome(6, map[string]int{"succeeded": 2, "pending_restart": 1, "degraded": 1, "timed_out": 1, "installing": 1}, 0, true)
	if !complete || out.NoResponse != 1 || out.Open != 0 {
		t.Fatalf("past the deadline: %+v complete=%v", out, complete)
	}
	if _, complete = patchRingOutcome(2, map[string]int{"pending_restart": 2}, 1, false); complete {
		t.Fatal("a ring with a restart still being watched is not complete")
	}
	out, complete = patchRingOutcome(3, map[string]int{"succeeded": 1}, 0, false)
	if !complete || out.NoResponse != 2 {
		t.Fatalf("endpoints with no job are no response: %+v", out)
	}
	out, _ = patchRingOutcome(2, map[string]int{"waiting": 2}, 0, false)
	if out.Open != 2 {
		t.Fatalf("a job waiting for its window is open: %+v", out)
	}
}

// An Enforce ring is judged per endpoint on results since it started.
func TestEnforceRingOutcome(t *testing.T) {
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	fresh, stale := start.Add(time.Minute), start.Add(-time.Minute)
	res := func(agent, setting, state string, at time.Time) store.EnforceResult {
		return store.EnforceResult{AgentID: agent, SettingID: setting, State: state, CheckedAt: at}
	}
	results := []store.EnforceResult{
		res("ok", "s1", "compliant", fresh), res("ok", "s2", "remediated", fresh),
		res("bad", "s1", "failed", fresh), res("bad", "s2", "compliant", fresh),
		res("drift", "s1", "drifted", fresh), res("drift", "s2", "compliant", fresh),
		res("unk", "s1", "unknown", fresh), res("unk", "s2", "compliant", fresh),
		res("half", "s1", "compliant", fresh),
		res("old", "s1", "compliant", stale), res("old", "s2", "compliant", stale),
	}
	out := enforceRingOutcome([]string{"ok", "bad", "drift", "unk", "half", "old", "silent"}, results, 2, start)
	want := store.RingOutcome{Total: 7, Succeeded: 1, Failed: 2, Unknown: 2, NoResponse: 2}
	if out != want {
		t.Fatalf("got %+v, want %+v", out, want)
	}
}
