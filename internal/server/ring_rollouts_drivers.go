package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

// patchRingDeadline bounds how long a patch ring may wait for its results:
// a day for maintenance windows (patchWaitLimit) and the time after which
// the Deployments view calls a run stalled. Endpoints still open then count
// as no response, and the ring is judged on what came back.
const patchRingDeadline = patchWaitLimit + deploymentStallAfter

// patchRolloutParams is what a later ring of a patch rollout needs to
// dispatch the way the first one did.
type patchRolloutParams struct {
	TargetOS        string   `json:"target_os,omitempty"`
	TargetSite      string   `json:"target_site,omitempty"`
	TargetAgent     string   `json:"target_agent,omitempty"`
	TargetVulnID    string   `json:"target_vuln_id,omitempty"`
	TargetAgents    []string `json:"target_agents,omitempty"`
	ScheduleID      string   `json:"schedule_id,omitempty"`
	RequestedBy     string   `json:"requested_by"`
	OverrideWindows bool     `json:"override_windows,omitempty"`
	RestartMode     string   `json:"restart_mode,omitempty"`
	RestartWarn     int      `json:"restart_warn_minutes,omitempty"`
}

func (p patchRolloutParams) targetDesc() string {
	if len(p.TargetAgents) > 0 {
		return fmt.Sprintf("%d selected endpoint(s)", len(p.TargetAgents))
	}
	return describePatchTarget(p.TargetOS, p.TargetSite, p.TargetAgent, p.TargetVulnID)
}

type patchRingDriver struct{ s *Server }

func patchParams(r *store.RingRollout) patchRolloutParams {
	var p patchRolloutParams
	_ = json.Unmarshal(r.Params, &p)
	return p
}

// targets resolves the run's target exactly as a schedule firing does:
// the same filter, the explicit endpoint list, then the rollout author's
// current reach inside the patches action group.
func (d patchRingDriver) targets(ctx context.Context, r *store.RingRollout) ([]string, string, error) {
	agents, err := d.s.patchRolloutAgents(ctx, r)
	if err != nil {
		return nil, "", err
	}
	if agents == nil {
		return nil, "the rollout's author no longer exists or is inactive", nil
	}
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.AgentID)
	}
	return ids, "", nil
}

// patchRolloutAgents returns nil (not empty) when the author is gone.
func (s *Server) patchRolloutAgents(ctx context.Context, r *store.RingRollout) ([]store.AgentRecord, error) {
	p := patchParams(r)
	agents, err := s.resolvePatchTargets(ctx, p.TargetOS, p.TargetSite, p.TargetAgent, p.TargetVulnID)
	if err != nil {
		return nil, err
	}
	agents = filterToAgents(agents, p.TargetAgents)
	pctx, ok := s.endpointActionPrincipal(ctx, r.CreatedBy)
	if !ok {
		return nil, nil
	}
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.AgentID)
	}
	allowed, _, err := s.narrowTargets(pctx, "patches", ids)
	if err != nil {
		return nil, err
	}
	keep := make(map[string]bool, len(allowed))
	for _, id := range allowed {
		keep[id] = true
	}
	out := []store.AgentRecord{}
	for _, a := range agents {
		if keep[a.AgentID] {
			out = append(out, a)
		}
	}
	return out, nil
}

func (d patchRingDriver) groupMembers(ctx context.Context, groupID string) (map[string]bool, bool, error) {
	return d.s.rolloutGroupMembers(ctx, groupID)
}

// rolloutGroupMembers resolves a ring's group through the same membership
// code computer groups use everywhere else.
func (s *Server) rolloutGroupMembers(ctx context.Context, groupID string) (map[string]bool, bool, error) {
	g, err := s.store.GetComputerGroup(ctx, groupID)
	if err != nil {
		return nil, false, err
	}
	if g == nil {
		return nil, false, nil
	}
	ids, err := s.resolveGroupMembers(ctx, *g)
	if err != nil {
		return nil, true, err
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, true, nil
}

// startRing records the ring as a patch run of its own, so the Deployments
// view shows each ring's devices and status, and sends it through the one
// patch dispatch path: patch lists, maintenance windows, the one-job-per-
// endpoint rule and the health checks all apply to every ring.
func (d patchRingDriver) startRing(ctx context.Context, r *store.RingRollout, i int) (string, error) {
	s := d.s
	p := patchParams(r)
	ring := r.Rings[i]
	all, err := s.patchRolloutAgents(ctx, r)
	if err != nil {
		return "", err
	}
	want := map[string]bool{}
	for _, id := range ring.AgentIDs {
		want[id] = true
	}
	var members []store.AgentRecord
	for _, a := range all {
		if want[a.AgentID] {
			members = append(members, a)
		}
	}
	runID := idgen.New("run-")
	name := r.SourceName
	if name == "" {
		name = "Patch rollout"
	}
	if err := s.store.RecordPatchJobRun(ctx, store.PatchJobRun{
		ID: runID, ScheduleID: p.ScheduleID,
		ScheduleName: fmt.Sprintf("%s — ring %d of %d: %s", name, i+1, len(r.Rings), ring.Name),
		TargetDesc:   p.targetDesc(), AgentCount: len(members), TriggeredBy: p.RequestedBy,
	}); err != nil {
		return "", err
	}
	restart, err := patchRestart{Mode: p.RestartMode, WarnMinutes: p.RestartWarn}.clean()
	if err != nil {
		restart = patchRestart{}
	}
	s.deployPatchesToAgents(ctx, members, p.RequestedBy, runID, p.OverrideWindows, restart, nil)
	return runID, nil
}

func (d patchRingDriver) ringOutcome(ctx context.Context, r *store.RingRollout, i int, now time.Time) (store.RingOutcome, bool, error) {
	ring := r.Rings[i]
	counts, err := d.s.store.RunOutcomeCounts(ctx, []string{ring.RunID})
	if err != nil {
		return ring.Outcome, false, err
	}
	watches, err := d.s.store.OpenPatchRestartWatches(ctx)
	if err != nil {
		return ring.Outcome, false, err
	}
	watching := 0
	for _, w := range watches {
		if w.RunID == ring.RunID {
			watching++
		}
	}
	expired := ring.StartedAt != nil && now.Sub(*ring.StartedAt) > patchRingDeadline
	out, complete := patchRingOutcome(len(ring.AgentIDs), counts[ring.RunID], watching, expired)
	return out, complete, nil
}

// patchRingOutcome sorts a ring's patch jobs by status into the outcome
// buckets. Success is succeeded, skipped (the patch lists permitted
// nothing, so there was nothing to break) and pending restart (installed,
// as the Deployments view counts it). The ring is complete when nothing is
// open and no restart is still being watched; past the deadline, whatever
// is still open is no response.
func patchRingOutcome(members int, counts map[string]int, watching int, expired bool) (store.RingOutcome, bool) {
	out := store.RingOutcome{Total: members}
	for status, n := range counts {
		switch status {
		case "succeeded", "skipped", "pending_restart":
			out.Succeeded += n
		case "timed_out":
			out.TimedOut += n
		case "no_response":
			out.NoResponse += n
		case "started", "running", "pending", "downloading", "installing", "verifying", "waiting":
			out.Open += n
		default: // failed, degraded, cancelled, interrupted, expired, unsupported
			out.Failed += n
		}
	}
	// An endpoint with no job at all (the dispatch never recorded one) did
	// not respond either.
	if missing := members - (out.Succeeded + out.Failed + out.TimedOut + out.NoResponse + out.Open); missing > 0 {
		out.NoResponse += missing
	}
	complete := out.Open == 0 && watching == 0
	if expired && !complete {
		out.NoResponse += out.Open
		out.Open = 0
		complete = true
	}
	return out, complete
}

func (d patchRingDriver) stop(context.Context, *store.RingRollout) (string, string, error) {
	return "", "", nil
}

func (d patchRingDriver) finish(context.Context, *store.RingRollout) error { return nil }

// --- Enforce -----------------------------------------------------------

// An Enforce rollout promotes a report-mode policy one ring at a time.
// While it is open, the policy stays in report mode and every pass
// enforces on the endpoints of the rings that have started
// (enforcePromoted) and only reports everywhere else. When the last ring
// passes, the policy itself switches to enforce. Aborting puts every
// endpoint back to report.

type enforceRingDriver struct{ s *Server }

func (d enforceRingDriver) policy(ctx context.Context, r *store.RingRollout) (*store.EnforcePolicy, error) {
	return d.s.store.GetEnforcePolicy(ctx, r.SourceID)
}

func (d enforceRingDriver) targets(ctx context.Context, r *store.RingRollout) ([]string, string, error) {
	p, err := d.policy(ctx, r)
	if err != nil || p == nil {
		return nil, "", err
	}
	agents, err := d.s.enforceTargets(ctx, *p)
	if err != nil {
		return nil, "", err
	}
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.AgentID)
	}
	return ids, "", nil
}

func (d enforceRingDriver) groupMembers(ctx context.Context, groupID string) (map[string]bool, bool, error) {
	return d.s.rolloutGroupMembers(ctx, groupID)
}

// startRing dispatches nothing itself: the ring is promoted the moment its
// state is saved, and ringOutcome runs the first pass over it.
func (d enforceRingDriver) startRing(context.Context, *store.RingRollout, int) (string, error) {
	return "", nil
}

// ringOutcome runs one pass of the policy once the ring is promoted, then
// judges the ring on the results recorded since it started. Later passes
// on the policy's own timer refresh those results, so the threshold is
// checked again on what they say when the soak ends.
func (d enforceRingDriver) ringOutcome(ctx context.Context, r *store.RingRollout, i int, now time.Time) (store.RingOutcome, bool, error) {
	ring := r.Rings[i]
	if !d.s.enforceRingPassDone(r, i) {
		return ring.Outcome, false, nil
	}
	p, err := d.policy(ctx, r)
	if err != nil || p == nil {
		return ring.Outcome, false, err
	}
	var settings []proto.EnforceSetting
	_ = json.Unmarshal(p.Settings, &settings)
	results, err := d.s.store.ListEnforceResults(ctx, p.ID)
	if err != nil {
		return ring.Outcome, false, err
	}
	since := now
	if ring.StartedAt != nil {
		since = *ring.StartedAt
	}
	return enforceRingOutcome(ring.AgentIDs, results, len(settings), since), true, nil
}

// enforceRingOutcome judges each endpoint on its results since the ring
// started: succeeded when every setting came back compliant or
// remediated, failed when any setting failed, is failing or is still
// drifted, unknown when a rule could not be evaluated (never a pass), and
// no response when nothing came back.
func enforceRingOutcome(members []string, results []store.EnforceResult, settings int, since time.Time) store.RingOutcome {
	byAgent := map[string][]store.EnforceResult{}
	for _, res := range results {
		if !res.CheckedAt.Before(since) {
			byAgent[res.AgentID] = append(byAgent[res.AgentID], res)
		}
	}
	out := store.RingOutcome{Total: len(members)}
	for _, id := range members {
		rs := byAgent[id]
		if len(rs) == 0 {
			out.NoResponse++
			continue
		}
		failed, unknown := false, len(rs) < settings
		for _, res := range rs {
			switch res.State {
			case "compliant", "remediated":
			case "unknown":
				unknown = true
			default:
				failed = true
			}
		}
		switch {
		case failed:
			out.Failed++
		case unknown:
			out.Unknown++
		default:
			out.Succeeded++
		}
	}
	return out
}

func (d enforceRingDriver) stop(ctx context.Context, r *store.RingRollout) (string, string, error) {
	p, err := d.policy(ctx, r)
	if err != nil {
		return "", "", err
	}
	switch {
	case p == nil:
		return "", "the policy was deleted", nil
	case p.Mode == "enforce":
		return "", "the policy was switched to enforce for every endpoint it targets, outside the rollout", nil
	case p.GroupDeleted:
		return "the policy's computer group was deleted, so it targets nothing", "", nil
	case !p.Enabled:
		return "the policy is disabled", "", nil
	}
	return "", "", nil
}

// finish switches the policy to enforce for its whole target. Only from
// report: a person who set it back to report mid-rollout is not overruled.
func (d enforceRingDriver) finish(ctx context.Context, r *store.RingRollout) error {
	s := d.s
	switched, err := s.store.SetEnforcePolicyMode(ctx, r.SourceID, "report", "enforce", r.CreatedBy)
	if err != nil {
		return err
	}
	if switched {
		s.audit(ctx, auditEvent{Action: "enforce.policy.update", Actor: r.CreatedBy, Target: r.SourceName, Severity: "warning",
			Detail: map[string]any{"mode": "enforce", "via_rollout": r.ID, "plan": r.PlanName}})
	}
	return nil
}

// enforceRingPassDone reports whether the pass over ring i has run since
// the ring was promoted, starting it if not. It runs in the background:
// a pass can take up to enforceDispatchTimeout per endpoint, and the loop
// has other rollouts to advance. A pass refused because one is already
// running is tried again on the next step. A restarted server simply runs
// the pass again.
func (s *Server) enforceRingPassDone(r *store.RingRollout, i int) bool {
	key := r.ID + "#" + strconv.Itoa(i)
	if _, ok := s.rolloutPasses.Load(key); ok {
		return true
	}
	guard := "rollout-pass:" + key
	if !s.runs.claim(guard) {
		return false
	}
	policyID, who := r.SourceID, r.CreatedBy
	go func() {
		defer s.runs.release(guard)
		ctx := context.Background()
		p, err := s.store.GetEnforcePolicy(ctx, policyID)
		if err != nil || p == nil {
			return
		}
		if _, err := s.runEnforcePolicy(ctx, *p, who); err != nil && strings.Contains(err.Error(), "already running") {
			return
		}
		s.rolloutPasses.Store(key, time.Now())
	}()
	return false
}

// enforcePromoted is the set of endpoints an open rollout of p has
// promoted to enforce: every endpoint of a ring that has started. A halted
// rollout keeps its promoted rings enforcing (halting stops the spread,
// not what already passed); an aborted or finished one promotes nothing.
func (s *Server) enforcePromoted(ctx context.Context, p store.EnforcePolicy) map[string]bool {
	if p.Mode != "report" || s.store == nil {
		return nil
	}
	r, err := s.store.OpenRingRollout(ctx, "enforce", p.ID)
	if err != nil {
		s.logger.Warn("enforce: could not read the policy's rollout; reporting only", "policy", p.Name, "error", err)
		return nil
	}
	if r == nil {
		return nil
	}
	out := map[string]bool{}
	for _, ring := range r.Rings {
		switch ring.State {
		case "running", "soaking", "passed", "failed":
			for _, id := range ring.AgentIDs {
				out[id] = true
			}
		}
	}
	return out
}
