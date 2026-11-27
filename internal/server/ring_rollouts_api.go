package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// HTTP surface for ring rollouts. Reading is open to any signed-in user,
// like the deployment history it summarizes. Resuming and aborting take
// the permission of what the rollout does: patches.manage for a patch
// rollout, deploy.manage for an Enforce promotion. That is why the same
// two handlers sit behind a /api/patches/… and an /api/enforce/… route, and
// refuse a rollout of the other kind.

// listRolloutsResponse is what GET /api/rollouts answers.
type listRolloutsResponse struct {
	Rollouts []store.RingRollout `json:"rollouts"`
}

func (s *Server) handleListRollouts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := q.Get("kind")
	if kind != "" && kind != "patch" && kind != "enforce" {
		http.Error(w, "kind must be patch or enforce", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rollouts, err := s.store.ListRingRollouts(r.Context(), kind, q.Get("source_id"), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, listRolloutsResponse{Rollouts: rollouts})
}

func (s *Server) handleGetRollout(w http.ResponseWriter, r *http.Request) {
	ro, err := s.store.GetRingRollout(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ro == nil {
		http.Error(w, "no such rollout", http.StatusNotFound)
		return
	}
	writeJSONResponse(w, ro)
}

// rolloutKindForPath is the kind of rollout a resume or abort route may
// act on, from the module its path is under.
func rolloutKindForPath(path string) string {
	if strings.HasPrefix(path, "/api/enforce/") {
		return "enforce"
	}
	return "patch"
}

// claimRolloutForChange loads the rollout a resume or abort names, under
// the same guard the rollout loop takes, so the two cannot both move it.
// The caller releases the returned key when it is not empty.
func (s *Server) claimRolloutForChange(w http.ResponseWriter, r *http.Request) (*store.RingRollout, string, bool) {
	id := r.PathValue("id")
	key := "rollout:" + id
	if !s.runs.claim(key) {
		http.Error(w, "the rollout is busy starting a ring; try again in a moment", http.StatusConflict)
		return nil, "", false
	}
	ro, err := s.store.GetRingRollout(r.Context(), id)
	if err != nil {
		s.runs.release(key)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, "", false
	}
	if ro == nil || ro.Kind != rolloutKindForPath(r.URL.Path) {
		s.runs.release(key)
		http.Error(w, "no such rollout", http.StatusNotFound)
		return nil, "", false
	}
	return ro, key, true
}

// handleResumeRollout lets a halted rollout go on: the ring it halted on is
// accepted as it stands and the next one starts (resumeRollout).
func (s *Server) handleResumeRollout(w http.ResponseWriter, r *http.Request) {
	ro, key, ok := s.claimRolloutForChange(w, r)
	if !ok {
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	reason := ro.HaltReason
	if err := resumeRollout(ro, who); err != nil {
		s.runs.release(key)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	saved, err := s.store.SaveRingRollout(r.Context(), ro)
	s.runs.release(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !saved {
		http.Error(w, "the rollout changed while you were looking at it; reload and try again", http.StatusConflict)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "rollout.resumed", Actor: who, Target: rolloutTarget(ro), Severity: "warning",
		Detail: map[string]any{"rollout": ro.ID, "kind": ro.Kind, "plan": ro.PlanName, "halt_reason": reason, "next_ring": ro.CurrentRing + 1}})
	// The next ring may be a fleet's worth of patch dispatch; the answer
	// does not wait for it.
	go s.stepRollout(context.WithoutCancel(r.Context()), ro.ID)
	writeJSONResponse(w, ro)
}

// handleAbortRollout ends a rollout. Rings not started never start; a
// patch ring's endpoints still waiting for their maintenance window are
// cancelled; an Enforce promotion's endpoints go back to report.
func (s *Server) handleAbortRollout(w http.ResponseWriter, r *http.Request) {
	ro, key, ok := s.claimRolloutForChange(w, r)
	if !ok {
		return
	}
	defer s.runs.release(key)
	who := auth.CurrentUser(r.Context()).Username
	if err := abortRollout(ro, who, time.Now().UTC()); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	saved, err := s.store.SaveRingRollout(r.Context(), ro)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !saved {
		http.Error(w, "the rollout changed while you were looking at it; reload and try again", http.StatusConflict)
		return
	}
	held := int64(0)
	if ro.Kind == "patch" && ro.CurrentRing < len(ro.Rings) {
		if n, err := s.store.HoldWaitingRunActions(r.Context(), ro.Rings[ro.CurrentRing].RunID,
			"Cancelled: "+who+" aborted the rollout this run belongs to."); err == nil {
			held = n
		}
	}
	s.audit(r.Context(), auditEvent{Action: "rollout.aborted", Actor: who, Target: rolloutTarget(ro), Severity: "warning",
		Detail: map[string]any{"rollout": ro.ID, "kind": ro.Kind, "plan": ro.PlanName, "ring": ro.CurrentRing + 1, "cancelled_waiting": held}})
	writeJSONResponse(w, ro)
}

func rolloutTarget(ro *store.RingRollout) string {
	if ro.SourceName != "" {
		return ro.SourceName
	}
	return ro.Kind + " rollout " + ro.ID
}

// startEnforceRolloutRequest is the body of POST
// /api/enforce/policies/{id}/rollout.
type startEnforceRolloutRequest struct {
	// PlanID is the deployment plan whose rings the policy is promoted
	// through, from report to enforce.
	PlanID string `json:"plan_id" api:"required"`
}

// handleStartEnforceRollout promotes a report-mode policy to enforce ring
// by ring. The policy keeps its report mode until the last ring passes;
// meanwhile each pass enforces on the endpoints of the rings promoted so
// far.
func (s *Server) handleStartEnforceRollout(w http.ResponseWriter, r *http.Request) {
	p, ok := s.lookupEnforcePolicy(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var req startEnforceRolloutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlanID == "" {
		http.Error(w, "plan_id is required", http.StatusBadRequest)
		return
	}
	switch {
	case p.Mode != "report":
		http.Error(w, "only a policy in report mode can be promoted ring by ring", http.StatusBadRequest)
		return
	case p.GroupDeleted:
		http.Error(w, "this policy's computer group was deleted; choose its targets again first", http.StatusBadRequest)
		return
	case !p.Enabled:
		http.Error(w, "this policy is disabled; enable it first", http.StatusBadRequest)
		return
	}
	var settings []proto.EnforceSetting
	if err := json.Unmarshal(p.Settings, &settings); err != nil {
		http.Error(w, "this policy has no usable settings", http.StatusBadRequest)
		return
	}
	// The same check a save in enforce mode makes: a policy with no fix
	// for its platform can only ever report.
	if _, err := validateEnforceSettings(settings, "enforce", p.OS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plan, err := s.store.GetDeploymentPlan(r.Context(), req.PlanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if plan == nil || len(plan.Rings) == 0 {
		http.Error(w, "no such rollout plan", http.StatusBadRequest)
		return
	}
	// Refused before the audit row, which would otherwise record a start
	// that never happened; the unique index still catches a race.
	if open, err := s.store.OpenRingRollout(r.Context(), "enforce", p.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if open != nil {
		http.Error(w, "this policy is already being rolled out; resume or abort that rollout first", http.StatusConflict)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	// Audited before it starts: the first ring enforces within the minute.
	s.audit(r.Context(), auditEvent{Action: "enforce.rollout.start", Actor: who, Target: p.Name, Severity: "warning",
		Detail: map[string]any{"policy": p.ID, "plan": plan.Name, "rings": len(plan.Rings)}})
	ro, err := s.startRollout(context.WithoutCancel(r.Context()), "enforce", p.ID, p.Name, *plan, struct{}{}, who)
	if errors.Is(err, store.ErrRolloutOpen) {
		http.Error(w, "this policy is already being rolled out; resume or abort that rollout first", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, ro)
}
