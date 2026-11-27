package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// Ring rollouts: a patch run or an Enforce promotion that goes out ring by
// ring through a deployment plan, holding before each ring until the last
// one has proved itself, and stopping for a person when it has not.
//
// The software deployment path (rings.go) runs a plan inside one
// goroutine with sleeps between rings, which is fine for an hour and lost
// on a restart. Patch soak times are days, so this one keeps its state in
// ring_rollouts and is advanced by a loop: every step reads the row, does
// at most one ring's worth of work, and writes it back.
//
// Three rules carry the safety:
//
//  1. A ring only ever narrows the rollout's own target. A group ring is
//     the group's members that are also in the target; a percentage ring
//     is a share of the target. A ring whose group has been deleted halts
//     the rollout rather than being skipped or, worse, read as "everyone"
//     (the GroupDeleted rule Enforce policies and playbooks follow).
//  2. Success is what the devices reported. An endpoint that never
//     answered is "no response", which counts against the threshold, and
//     a ring in which nobody answered has not passed.
//  3. A ring that misses its threshold, or a patch that fails its health
//     check, halts the rollout. Only an operator resumes it.

// rolloutTick is how often running rollouts are advanced. Soak times are
// minutes to days; a minute of slop is nothing.
const rolloutTick = time.Minute

// ringDriver is what a kind of rollout (patch, enforce) supplies to the
// shared state machine. Kept as an interface so the machine is tested
// without a database or an endpoint.
type ringDriver interface {
	// targets is the rollout's own target as it stands now. A non-empty
	// halt stops the rollout with that reason (the author lost access).
	targets(ctx context.Context, r *store.RingRollout) (ids []string, halt string, err error)
	// groupMembers resolves a ring's computer group; exists is false when
	// the group has been deleted.
	groupMembers(ctx context.Context, groupID string) (members map[string]bool, exists bool, err error)
	// startRing dispatches ring i to its endpoints, returning the patch
	// run it created, if any.
	startRing(ctx context.Context, r *store.RingRollout, i int) (runID string, err error)
	// ringOutcome reads ring i's results; complete is false while
	// endpoints are still working.
	ringOutcome(ctx context.Context, r *store.RingRollout, i int, now time.Time) (out store.RingOutcome, complete bool, err error)
	// stop is checked before every step: a non-empty abort ends the
	// rollout (its policy is gone), a non-empty halt pauses it.
	stop(ctx context.Context, r *store.RingRollout) (halt, abort string, err error)
	// finish runs once every ring has passed.
	finish(ctx context.Context, r *store.RingRollout) error
}

// rolloutEvent is something a step did that is worth an audit row or a
// notification. The machine only reports them; the caller emits them after
// the step has been saved.
type rolloutEvent struct {
	Kind   string // ring_started, ring_skipped, halted, completed, aborted
	Ring   int
	Detail string
}

// ringRank orders endpoints for percentage rings: a hash of the plan and
// the agent ID, so a percentage ring takes the same endpoints every time
// the same plan runs over the same target, and a canary stays a canary.
func ringRank(seed, agentID string) string {
	sum := sha256.Sum256([]byte(seed + "\x00" + agentID))
	return string(sum[:])
}

// selectRingMembers picks ring's endpoints from what is left of the
// target. A group ring is the group's members within the target; a
// percentage ring takes Percent of the whole target (at least one endpoint
// for a non-zero share), from those no earlier ring took, in ringRank
// order. The target is the only source: nothing outside it can be chosen.
func selectRingMembers(ring store.Ring, seed string, target []string, assigned, groupMembers map[string]bool) []string {
	pool := make([]string, 0, len(target))
	seen := map[string]bool{}
	for _, id := range target {
		if !assigned[id] && !seen[id] {
			seen[id] = true
			pool = append(pool, id)
		}
	}
	sort.Slice(pool, func(i, j int) bool { return ringRank(seed, pool[i]) < ringRank(seed, pool[j]) })
	if ring.GroupID != "" {
		out := []string{}
		for _, id := range pool {
			if groupMembers[id] {
				out = append(out, id)
			}
		}
		return out
	}
	n := len(target) * ring.Percent / 100
	if n < 1 && ring.Percent > 0 {
		n = 1
	}
	if n > len(pool) {
		n = len(pool)
	}
	return append([]string{}, pool[:n]...)
}

// rolloutRingPassed decides whether the rollout may go past a ring. It is
// ringPassed (the software plans' rule: MinSuccess and SuccessRate, a ring
// with neither always passes) plus one rule that holds whatever the
// criteria: a ring in which no endpoint reported anything has not passed.
func rolloutRingPassed(ring store.Ring, out store.RingOutcome) (bool, string) {
	if out.Total > 0 && out.Succeeded+out.Failed+out.TimedOut+out.Unknown == 0 {
		return false, "no endpoint in this ring reported back"
	}
	return ringPassed(ring, out.Succeeded, out.Total)
}

// assignedBefore is every endpoint an earlier ring of r took.
func assignedBefore(r *store.RingRollout, i int) map[string]bool {
	out := map[string]bool{}
	for j := 0; j < i && j < len(r.Rings); j++ {
		for _, id := range r.Rings[j].AgentIDs {
			out[id] = true
		}
	}
	return out
}

// groupDeletedNote marks a ring halted because its group is gone, which is
// the one pending-ring halt a resume skips past: the group is not coming
// back, whereas a policy switched off can be switched on again.
const groupDeletedNote = "its computer group was deleted"

func haltRollout(r *store.RingRollout, reason string) rolloutEvent {
	r.Status = "halted"
	r.HaltReason = reason
	return rolloutEvent{Kind: "halted", Ring: r.CurrentRing, Detail: reason}
}

// advanceRollout moves a running rollout on as far as it can go now,
// changing r in place. It starts at most one ring per call, and returns
// what happened.
func advanceRollout(ctx context.Context, d ringDriver, r *store.RingRollout, now time.Time) ([]rolloutEvent, error) {
	if r.Status != "running" {
		return nil, nil
	}
	halt, abort, err := d.stop(ctx, r)
	if err != nil {
		return nil, err
	}
	if abort != "" {
		r.Status, r.HaltReason, r.FinishedAt = "aborted", abort, &now
		return []rolloutEvent{{Kind: "aborted", Ring: r.CurrentRing, Detail: abort}}, nil
	}
	if halt != "" {
		return []rolloutEvent{haltRollout(r, halt)}, nil
	}
	var events []rolloutEvent
	// Bounded: each pass either returns or moves CurrentRing on.
	for steps := 0; steps <= len(r.Rings)+1; steps++ {
		if r.CurrentRing >= len(r.Rings) {
			if ids, _, err := d.targets(ctx, r); err == nil {
				all := assignedBefore(r, len(r.Rings))
				r.Untouched = 0
				for _, id := range ids {
					if !all[id] {
						r.Untouched++
					}
				}
			}
			if err := d.finish(ctx, r); err != nil {
				return events, err
			}
			r.Status, r.FinishedAt = "completed", &now
			return append(events, rolloutEvent{Kind: "completed", Ring: len(r.Rings)}), nil
		}
		i := r.CurrentRing
		ring := &r.Rings[i]
		switch ring.State {
		case "", "pending":
			target, halt, err := d.targets(ctx, r)
			if err != nil {
				return events, err
			}
			if halt != "" {
				return append(events, haltRollout(r, halt)), nil
			}
			var members map[string]bool
			if ring.GroupID != "" {
				m, exists, err := d.groupMembers(ctx, ring.GroupID)
				if err != nil {
					return events, err
				}
				if !exists {
					ring.Note = groupDeletedNote
					return append(events, haltRollout(r, fmt.Sprintf("ring %d (%s): its computer group was deleted, so it cannot say which endpoints go next; resume to skip the ring, or abort", i+1, ring.Name))), nil
				}
				members = m
			}
			picked := selectRingMembers(ring.Ring, r.PlanID, target, assignedBefore(r, i), members)
			if len(picked) == 0 {
				ring.State, ring.AgentIDs = "skipped", []string{}
				ring.Note = "no endpoint of the target is in this ring"
				events = append(events, rolloutEvent{Kind: "ring_skipped", Ring: i, Detail: ring.Note})
				r.CurrentRing++
				continue
			}
			ring.AgentIDs = picked
			ring.State = "running"
			ring.StartedAt = &now
			ring.Outcome = store.RingOutcome{Total: len(picked), Open: len(picked)}
			runID, err := d.startRing(ctx, r, i)
			ring.RunID = runID
			if err != nil {
				ring.State = "failed"
				ring.Note = "could not start: " + err.Error()
				return append(events, haltRollout(r, fmt.Sprintf("ring %d (%s) could not start: %v", i+1, ring.Name, err))), nil
			}
			return append(events, rolloutEvent{Kind: "ring_started", Ring: i,
				Detail: fmt.Sprintf("%d endpoint(s)", len(picked))}), nil

		case "running", "soaking":
			if ring.State == "soaking" && ring.SoakUntil != nil && now.Before(*ring.SoakUntil) {
				return events, nil
			}
			out, complete, err := d.ringOutcome(ctx, r, i, now)
			if err != nil {
				return events, err
			}
			ring.Outcome = out
			if !complete {
				return events, nil
			}
			if ok, why := rolloutRingPassed(ring.Ring, out); !ok {
				ring.State = "failed"
				ring.Note = why
				if ring.CompletedAt == nil {
					ring.CompletedAt = &now
				}
				return append(events, haltRollout(r, fmt.Sprintf("ring %d (%s): %s", i+1, ring.Name, why))), nil
			}
			if ring.State == "running" {
				// Complete and passing: hold for the soak, then check again,
				// because a patch can fail its restart check, and a setting
				// can drift back, well after the ring first looked fine.
				ring.CompletedAt = &now
				until := now.Add(time.Duration(ring.WaitMinutes) * time.Minute)
				ring.SoakUntil = &until
				ring.State = "soaking"
				if ring.WaitMinutes > 0 {
					return events, nil
				}
				continue
			}
			ring.State = "passed"
			r.CurrentRing++
			continue

		case "passed", "skipped":
			r.CurrentRing++
			continue

		default: // failed: only a resume moves past it
			return events, nil
		}
	}
	return events, nil
}

// resumeRollout is an operator deciding a halted rollout may go on. A ring
// that failed (missed its threshold, or a patch failed its health check)
// is accepted as it stands and the next ring starts on the following step;
// it is not re-run, its endpoints already have the change. A ring halted
// before it started because its group was deleted is skipped. Anything
// else (a ring still running when an earlier ring's restart check failed,
// a policy that was switched off) carries on where it was, and halts again
// if the reason still holds.
func resumeRollout(r *store.RingRollout, who string) error {
	if r.Status != "halted" {
		return fmt.Errorf("only a halted rollout can be resumed; this one is %s", r.Status)
	}
	if r.CurrentRing < len(r.Rings) {
		ring := &r.Rings[r.CurrentRing]
		switch {
		case ring.State == "failed":
			ring.State = "passed"
			ring.Note = "accepted when " + who + " resumed the rollout: " + r.HaltReason
			r.CurrentRing++
		case (ring.State == "" || ring.State == "pending") && ring.Note == groupDeletedNote:
			ring.State, ring.AgentIDs = "skipped", []string{}
			ring.Note = "skipped when " + who + " resumed the rollout: " + groupDeletedNote
			r.CurrentRing++
		}
	}
	r.Status, r.HaltReason = "running", ""
	return nil
}

// abortRollout ends a rollout for good. Rings not started never start.
func abortRollout(r *store.RingRollout, who string, now time.Time) error {
	if r.Status != "running" && r.Status != "halted" {
		return fmt.Errorf("this rollout is already %s", r.Status)
	}
	r.Status, r.FinishedAt = "aborted", &now
	r.HaltReason = "aborted by " + who
	return nil
}

// --- server side -----------------------------------------------------------

func (s *Server) rolloutDriver(kind string) ringDriver {
	switch kind {
	case "patch":
		return patchRingDriver{s}
	case "enforce":
		return enforceRingDriver{s}
	}
	return nil
}

func (s *Server) rolloutLoop(ctx context.Context) {
	ticker := time.NewTicker(rolloutTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rollouts, err := s.store.RunningRingRollouts(ctx)
			if err != nil {
				s.logger.Warn("list running rollouts failed", "error", err)
				continue
			}
			for _, r := range rollouts {
				s.stepRollout(ctx, r.ID)
			}
		}
	}
}

// stepRollout advances one rollout and saves what changed. One step per
// rollout at a time: the loop and an operator's resume would otherwise
// both start the next ring.
func (s *Server) stepRollout(ctx context.Context, id string) {
	key := "rollout:" + id
	if !s.runs.claim(key) {
		return
	}
	defer s.runs.release(key)
	r, err := s.store.GetRingRollout(ctx, id)
	if err != nil || r == nil || r.Status != "running" {
		return
	}
	d := s.rolloutDriver(r.Kind)
	if d == nil {
		return
	}
	before, _ := json.Marshal(r)
	events, err := advanceRollout(ctx, d, r, time.Now().UTC())
	if err != nil {
		s.logger.Warn("advance rollout failed; retrying next tick", "rollout", id, "error", err)
	}
	after, _ := json.Marshal(r)
	if bytes.Equal(before, after) {
		return
	}
	saved, err := s.store.SaveRingRollout(ctx, r)
	if err != nil || !saved {
		s.logger.Warn("save rollout failed", "rollout", id, "saved", saved, "error", err)
		return
	}
	s.emitRolloutEvents(ctx, r, events, "system")
}

func (s *Server) emitRolloutEvents(ctx context.Context, r *store.RingRollout, events []rolloutEvent, actor string) {
	link := "/patches#rollouts"
	if r.Kind == "enforce" {
		link = "/enforce#rollouts"
	}
	what := r.SourceName
	if what == "" {
		what = r.Kind + " rollout"
	}
	for _, e := range events {
		ringName := ""
		if e.Ring < len(r.Rings) {
			ringName = r.Rings[e.Ring].Name
		}
		detail := map[string]any{"rollout": r.ID, "kind": r.Kind, "plan": r.PlanName, "ring": e.Ring + 1, "ring_name": ringName, "detail": e.Detail}
		switch e.Kind {
		case "ring_started":
			if e.Ring < len(r.Rings) {
				detail["run_id"] = r.Rings[e.Ring].RunID
				detail["endpoints"] = len(r.Rings[e.Ring].AgentIDs)
			}
			s.audit(ctx, auditEvent{Action: "rollout.ring_started", Actor: actor, Target: what, Severity: "notice", Detail: detail})
		case "ring_skipped":
			s.logger.Info("rollout ring skipped", "rollout", r.ID, "ring", e.Ring+1, "reason", e.Detail)
		case "halted":
			s.audit(ctx, auditEvent{Action: "rollout.halted", Actor: actor, Target: what, Severity: "warning", Detail: detail})
			s.notify(ctx, "warning", rolloutCategory(r.Kind), "Rollout halted: "+what,
				safeTruncate(e.Detail+" Resume or abort it from the console.", 300), link)
		case "aborted":
			s.audit(ctx, auditEvent{Action: "rollout.aborted", Actor: actor, Target: what, Severity: "warning", Detail: detail})
			s.notify(ctx, "warning", rolloutCategory(r.Kind), "Rollout ended: "+what, safeTruncate(e.Detail, 300), link)
		case "completed":
			detail["untouched"] = r.Untouched
			s.audit(ctx, auditEvent{Action: "rollout.completed", Actor: actor, Target: what, Severity: "notice", Detail: detail})
		}
		s.logger.Info("rollout event", "rollout", r.ID, "event", e.Kind, "ring", e.Ring+1, "detail", e.Detail)
	}
}

func rolloutCategory(kind string) string {
	if kind == "enforce" {
		return "Enforce"
	}
	return "Patch"
}

// haltRolloutsForRun halts every running rollout whose ring dispatched
// this patch run: the patch health-check hold, which already stops the
// run's own waiting endpoints, also stops the rings after it. A rollout
// busy starting a ring is retried briefly rather than missed.
func (s *Server) haltRolloutsForRun(ctx context.Context, runID, reason string) {
	rollouts, err := s.store.RunningRolloutsForRun(ctx, runID)
	if err != nil {
		s.logger.Warn("find rollouts for a held run failed", "run_id", runID, "error", err)
		return
	}
	for _, found := range rollouts {
		go func(id string) {
			for attempt := 0; attempt < 120; attempt++ {
				if s.haltRolloutNow(ctx, id, runID, reason) {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
			s.logger.Warn("could not halt a rollout after a failed health check", "rollout", id, "run_id", runID)
		}(found.ID)
	}
}

// haltRolloutNow reports whether it is done with the rollout (halted it,
// or found nothing to halt); false means try again.
func (s *Server) haltRolloutNow(ctx context.Context, id, runID, reason string) bool {
	key := "rollout:" + id
	if !s.runs.claim(key) {
		return false
	}
	defer s.runs.release(key)
	r, err := s.store.GetRingRollout(ctx, id)
	if err != nil {
		return false
	}
	if r == nil || r.Status != "running" {
		return true
	}
	ring := -1
	for i := range r.Rings {
		if r.Rings[i].RunID == runID {
			ring = i
		}
	}
	if ring < 0 {
		return true
	}
	why := fmt.Sprintf("ring %d (%s): an endpoint failed its check after patching. %s", ring+1, r.Rings[ring].Name, safeTruncate(reason, 400))
	if ring == r.CurrentRing {
		r.Rings[ring].State = "failed"
		r.Rings[ring].Note = "an endpoint failed its health check"
	}
	ev := haltRollout(r, why)
	ev.Ring = ring
	saved, err := s.store.SaveRingRollout(ctx, r)
	if err != nil || !saved {
		return false
	}
	s.emitRolloutEvents(ctx, r, []rolloutEvent{ev}, "system")
	return true
}

// startRollout records a new rollout of plan and takes its first step.
func (s *Server) startRollout(ctx context.Context, kind, sourceID, sourceName string, plan store.DeploymentPlan, params any, createdBy string) (*store.RingRollout, error) {
	if len(plan.Rings) == 0 {
		return nil, fmt.Errorf("plan %q has no rings", plan.Name)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	rings := make([]store.RolloutRing, len(plan.Rings))
	for i, ring := range plan.Rings {
		if ring.Name == "" {
			ring.Name = "Ring " + strconv.Itoa(i+1)
		}
		rings[i] = store.RolloutRing{Ring: ring, State: "pending", AgentIDs: []string{}}
	}
	r, err := s.store.CreateRingRollout(ctx, store.RingRollout{
		ID: idgen.New("rollout-"), Kind: kind, SourceID: sourceID, SourceName: sourceName,
		PlanID: plan.ID, PlanName: plan.Name, Status: "running", Rings: rings,
		Params: raw, CreatedBy: createdBy,
	})
	if err != nil {
		return nil, err
	}
	s.stepRollout(ctx, r.ID)
	if fresh, err := s.store.GetRingRollout(ctx, r.ID); err == nil && fresh != nil {
		return fresh, nil
	}
	return r, nil
}
