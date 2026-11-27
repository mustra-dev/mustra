package server

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Staged rollout: run a deployment ring by ring, and stop if a ring goes
// badly rather than discovering the problem on the whole fleet at once.

// planRings splits a target set into ordered rings. Returning the leftover
// separately matters: a custom plan whose groups don't cover everything
// would otherwise silently skip endpoints, and a rollout that quietly
// misses machines is worse than one that says so.
func (s *Server) planRings(ctx context.Context, plan store.DeploymentPlan,
	targets []applicabilityRow) (rings [][]applicabilityRow, leftover []applicabilityRow, err error) {

	assigned := map[string]bool{}

	for _, ring := range plan.Rings {
		var members []applicabilityRow
		switch {
		case plan.Kind == "dynamic" || ring.Percent > 0:
			// A share of everything still unassigned, drawn fresh. Shuffling
			// a copy rather than the caller's slice: the caller still needs
			// its original order for reporting.
			pool := make([]applicabilityRow, 0, len(targets))
			for _, t := range targets {
				if !assigned[t.AgentID] {
					pool = append(pool, t)
				}
			}
			rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
			n := len(targets) * ring.Percent / 100
			if n < 1 && ring.Percent > 0 && len(pool) > 0 {
				n = 1 // a non-zero percentage of a small fleet must not round to nothing
			}
			if n > len(pool) {
				n = len(pool)
			}
			members = pool[:n]

		case ring.GroupID != "":
			scoped, gerr := s.agentsInGroups(ctx, []string{ring.GroupID})
			if gerr != nil {
				return nil, nil, gerr
			}
			for _, t := range targets {
				if !assigned[t.AgentID] && scoped[t.AgentID] {
					members = append(members, t)
				}
			}
		}

		for _, m := range members {
			assigned[m.AgentID] = true
		}
		rings = append(rings, members)
	}

	for _, t := range targets {
		if !assigned[t.AgentID] {
			leftover = append(leftover, t)
		}
	}
	return rings, leftover, nil
}

// ringPassed decides whether the rollout may continue past this ring.
// A ring with no criteria always passes — that is a staged rollout with no
// brakes, which is a legitimate thing to want but should be chosen rather
// than defaulted into.
func ringPassed(ring store.Ring, succeeded, total int) (bool, string) {
	if total == 0 {
		return false, "no endpoint in this ring reported back"
	}
	if ring.MinSuccess > 0 && succeeded < ring.MinSuccess {
		return false, "only " + itoaInt(succeeded) + " of a required " + itoaInt(ring.MinSuccess) + " succeeded"
	}
	if ring.SuccessRate > 0 {
		rate := succeeded * 100 / total
		if rate < ring.SuccessRate {
			return false, "success rate " + itoaInt(rate) + "% is below the required " + itoaInt(ring.SuccessRate) + "%"
		}
	}
	return true, ""
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// runStagedDeployment executes a software deployment ring by ring. It runs
// in the background — a plan with wait windows legitimately takes hours —
// and records each ring against the same deployment ID, so the Deployments
// view shows one rollout rather than a scatter of unrelated runs.
func (s *Server) runStagedDeployment(ctx context.Context, pkg store.SoftwarePackage,
	operation string, plan store.DeploymentPlan, targets []applicabilityRow, runID, who string) {

	rings, leftover, err := s.planRings(ctx, plan, targets)
	if err != nil {
		s.logger.Warn("planning rings failed", "plan", plan.Name, "error", err)
		return
	}

	for i, members := range rings {
		ring := plan.Rings[i]
		if len(members) == 0 {
			s.logger.Info("ring is empty, skipping", "plan", plan.Name, "ring", ring.Name)
			continue
		}
		s.logger.Info("staged deployment: starting ring", "plan", plan.Name,
			"ring", ring.Name, "endpoints", len(members), "run_id", runID)

		before := s.runOutcomeSucceeded(ctx, runID)
		s.runSoftwareDeployment(ctx, pkg, operation, members, runID, who, false)
		succeeded := s.runOutcomeSucceeded(ctx, runID) - before

		ok, why := ringPassed(ring, succeeded, len(members))
		if !ok {
			s.logger.Warn("staged deployment halted", "plan", plan.Name, "ring", ring.Name,
				"reason", why, "run_id", runID, "remaining_rings", len(rings)-i-1)
			// Recorded against the run so the halt is visible in the
			// console rather than only in the server log.
			_ = s.store.StartAgentAction(ctx, store.AgentAction{
				ID: idgen.New("act-"), RunID: runID, AgentID: members[0].AgentID,
				Kind: "ring_halted", Summary: "Rollout halted after ring " + ring.Name,
				RequestedBy: who,
			})
			return
		}
		if ring.WaitMinutes > 0 && i < len(rings)-1 {
			s.logger.Info("staged deployment: holding before the next ring",
				"plan", plan.Name, "minutes", ring.WaitMinutes)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(ring.WaitMinutes) * time.Minute):
			}
		}
	}

	if len(leftover) > 0 {
		s.logger.Info("staged deployment: endpoints outside every ring were not touched",
			"plan", plan.Name, "count", len(leftover), "run_id", runID)
	}
	s.logger.Info("staged deployment complete", "plan", plan.Name, "run_id", runID)
}

func (s *Server) runOutcomeSucceeded(ctx context.Context, runID string) int {
	counts, err := s.store.RunOutcomeCounts(ctx, []string{runID})
	if err != nil {
		return 0
	}
	return counts[runID]["succeeded"]
}

// ---- HTTP ----

// listPlansResponse is what GET /api/deployment-plans answers.
type listPlansResponse struct {
	Plans []store.DeploymentPlan `json:"plans"`
}

func (s *Server) handleListPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := s.store.ListDeploymentPlans(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if plans == nil {
		plans = []store.DeploymentPlan{}
	}
	writeJSONResponse(w, listPlansResponse{Plans: plans})
}

func (s *Server) handleUpsertPlan(w http.ResponseWriter, r *http.Request) {
	var body store.DeploymentPlan
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Rings) == 0 {
		http.Error(w, "a plan needs a name and at least one ring", http.StatusBadRequest)
		return
	}
	if body.Kind != "dynamic" {
		body.Kind = "custom"
	}
	if msg, status := s.validatePlanRings(r.Context(), &body); msg != "" {
		http.Error(w, msg, status)
		return
	}
	// A POST creates under an ID minted here, whatever the body says; a
	// PUT updates the plan it names, which must exist.
	if id := r.PathValue("id"); id != "" {
		old, err := s.store.GetDeploymentPlan(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if old == nil {
			http.Error(w, "no such plan", http.StatusNotFound)
			return
		}
		body.ID = old.ID
	} else {
		body.ID = idgen.New("plan-")
		body.CreatedBy = auth.CurrentUser(r.Context()).Username
	}
	plan, err := s.store.UpsertDeploymentPlan(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, plan)
}

func (s *Server) handleDeletePlan(w http.ResponseWriter, r *http.Request) {
	// A schedule rolling out through this plan would otherwise skip every
	// firing from now on; say so now rather than at three in the morning.
	users, err := s.store.PatchSchedulesUsingPlan(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(users) > 0 {
		http.Error(w, "patch schedules roll out through this plan: "+strings.Join(users, ", ")+"; delete them first", http.StatusConflict)
		return
	}
	if err := s.store.DeleteDeploymentPlan(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// maxRingWaitMinutes caps a ring's soak at thirty days: longer is a
// rollout nobody remembers starting.
const maxRingWaitMinutes = 30 * 24 * 60

// validatePlanRings refuses rings that cannot select anything or would
// select the wrong thing: each ring is either a computer group that exists
// or a percentage, never both, and its numbers are in range. It returns
// the message and status to refuse with, or "" when the plan is sound.
func (s *Server) validatePlanRings(ctx context.Context, p *store.DeploymentPlan) (string, int) {
	for i := range p.Rings {
		ring := &p.Rings[i]
		ring.Name = strings.TrimSpace(ring.Name)
		label := "ring " + itoaInt(i+1)
		if ring.Name != "" {
			label += " (" + ring.Name + ")"
		}
		switch {
		case ring.GroupID != "" && ring.Percent > 0:
			return label + " is both a computer group and a percentage; choose one", http.StatusBadRequest
		case p.Kind == "dynamic" && ring.GroupID != "":
			return label + ": a dynamic plan's rings are percentages", http.StatusBadRequest
		case ring.GroupID == "" && ring.Percent <= 0:
			return label + " needs a computer group or a percentage", http.StatusBadRequest
		case ring.Percent > 100, ring.SuccessRate < 0, ring.SuccessRate > 100:
			return label + ": percentages are 0 to 100", http.StatusBadRequest
		case ring.MinSuccess < 0, ring.WaitMinutes < 0, ring.WaitMinutes > maxRingWaitMinutes:
			return label + ": soak time is 0 to 30 days and the minimum successes cannot be negative", http.StatusBadRequest
		}
		if ring.GroupID != "" {
			g, err := s.store.GetComputerGroup(ctx, ring.GroupID)
			if err != nil {
				return err.Error(), http.StatusInternalServerError
			}
			if g == nil {
				return label + ": no such computer group", http.StatusBadRequest
			}
		}
	}
	return "", 0
}
