package server

// Then many: once a fix has worked on the item's endpoint, ask for the
// same fix on similar endpoints — the members of a computer group, or the
// endpoints a saved Interact question finds — as an approval request.
//
// It always goes to a second person, whether or not an approval policy
// covers it: one ticket is evidence about one machine, and a fleet step
// taken on it deserves a look. The request is an ordinary entry in
// Access → Approvals (and the /approve page): the requester cannot approve
// it, two approvers cannot both run it, it expires in eight hours, and
// approving replays the same route as the requester, through the same
// permission check and gate as anything else.
//
// The endpoints are resolved once, here, from shared targeting (the
// group's members as groups match them everywhere, the question's from
// clause as Interact evaluates it) and frozen into the request as named
// endpoints. Nothing re-resolves them later, so a group deleted or edited
// while the request waits cannot widen it; a group already deleted is
// refused rather than read as "no group", which elsewhere means everyone.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// triageSimilarRequest is the body of POST /api/triage/items/{id}/similar
// and its preview: which fix, and either a computer group or a saved
// question choosing the endpoints.
type triageSimilarRequest struct {
	FixID      string `json:"fix_id" api:"required"`
	GroupID    string `json:"group_id,omitempty"`
	QuestionID string `json:"question_id,omitempty"`
}

// triageEndpointBrief is one endpoint a rollout would reach.
type triageEndpointBrief struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Online   bool   `json:"online"`
}

// triageSimilarPreview is what POST /api/triage/items/{id}/similar/preview
// answers: the endpoints a request would name, exactly.
type triageSimilarPreview struct {
	TargetKind string                `json:"target_kind"`
	TargetID   string                `json:"target_id"`
	TargetName string                `json:"target_name"`
	Endpoints  []triageEndpointBrief `json:"endpoints"`
	// Dropped counts members left out because they are outside the
	// caller's management rights or the module's action group.
	Dropped int `json:"dropped"`
}

// triageSimilarResponse is what POST /api/triage/items/{id}/similar
// answers once the approval request exists.
type triageSimilarResponse struct {
	Rollout   store.TriageRollout `json:"rollout"`
	RequestID string              `json:"request_id"`
	Message   string              `json:"message"`
}

// triageSimilarTargets resolves a rollout's endpoints, or writes why not.
func (s *Server) triageSimilarTargets(w http.ResponseWriter, r *http.Request, it store.TriageItem, req triageSimilarRequest) (*store.TriageFix, triageSimilarPreview, bool) {
	ctx := r.Context()
	var pv triageSimilarPreview
	fix, err := s.store.GetTriageFix(ctx, strings.TrimSpace(req.FixID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, pv, false
	}
	if fix == nil || fix.ItemID != it.ID {
		http.Error(w, "no such fix on this item", http.StatusNotFound)
		return nil, pv, false
	}
	if fix.Outcome != "succeeded" {
		http.Error(w, "apply a fix to similar endpoints once it has succeeded on this one (it is "+firstNonEmpty(fix.Outcome, fix.State)+")", http.StatusConflict)
		return nil, pv, false
	}
	group, question := strings.TrimSpace(req.GroupID), strings.TrimSpace(req.QuestionID)
	if (group == "") == (question == "") {
		http.Error(w, "choose either a computer group (group_id) or a saved question (question_id)", http.StatusBadRequest)
		return nil, pv, false
	}
	var ids []string
	if group != "" {
		g, err := s.store.GetComputerGroup(ctx, group)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, pv, false
		}
		if g == nil {
			// Never "no group, so everything": that is how a deleted group
			// used to widen a policy to the fleet.
			http.Error(w, "that computer group no longer exists; choose the endpoints again", http.StatusConflict)
			return nil, pv, false
		}
		if ids, err = s.groupMembers(ctx, []string{g.ID}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, pv, false
		}
		pv.TargetKind, pv.TargetID, pv.TargetName = "group", g.ID, g.Name
	} else {
		q, err := s.store.GetSavedQuestion(ctx, question)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, pv, false
		}
		if q == nil {
			http.Error(w, "that saved question no longer exists; choose the endpoints again", http.StatusConflict)
			return nil, pv, false
		}
		if !s.requireContent(w, r, "questions", q.ID, q.Name) {
			return nil, pv, false
		}
		if ids, err = s.savedQuestionEndpoints(ctx, *q); err != nil {
			writeSensorFieldsError(w, err)
			return nil, pv, false
		}
		pv.TargetKind, pv.TargetID, pv.TargetName = "question", q.ID, q.Name
	}
	// The endpoint the fix already ran on is not "similar" to itself.
	kept := ids[:0:0]
	for _, id := range ids {
		if id != it.AgentID {
			kept = append(kept, id)
		}
	}
	if len(kept) == 0 {
		http.Error(w, "the "+pv.TargetKind+" "+pv.TargetName+" matches no other endpoint", http.StatusBadRequest)
		return nil, pv, false
	}
	module := map[string]string{"package": "deploy", "playbook": "playbooks"}[fix.Kind]
	if fix.Kind == "package" {
		if !s.requireContent(w, r, "packages", fix.RefID, fix.Name) {
			return nil, pv, false
		}
	}
	// Management rights and the module's action group narrow the choice
	// the way they narrow any operation that did not name its endpoints;
	// the request then names the ones left, and the preview shows those.
	scope, err := s.endpointScope(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, pv, false
	}
	ceiling, err := s.actionCeiling(ctx, module)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, pv, false
	}
	reach := kept[:0:0]
	for _, id := range kept {
		if (scope == nil || scope[id]) && (ceiling == nil || ceiling[id]) {
			reach = append(reach, id)
		}
	}
	if len(reach) == 0 {
		http.Error(w, "every endpoint the "+pv.TargetKind+" matches is outside your management rights or the "+module+" action group", http.StatusForbidden)
		return nil, pv, false
	}
	pv.Dropped = len(kept) - len(reach)
	kept = reach
	briefs, err := s.endpointBriefs(ctx, kept)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, pv, false
	}
	pv.Endpoints = briefs
	return fix, pv, true
}

// savedQuestionEndpoints is the endpoints a saved question's from clause
// matches, with the same sensor checks Interact applies to asking it.
func (s *Server) savedQuestionEndpoints(ctx context.Context, q store.SavedQuestion) ([]string, error) {
	var where []groups.Rule
	if len(q.Where) > 0 {
		if err := json.Unmarshal(q.Where, &where); err != nil {
			return nil, fmt.Errorf("the saved question's conditions are unreadable: %w", err)
		}
	}
	leaves, err := groups.ExpandGroups(where)
	if err != nil {
		return nil, err
	}
	bare, vf, err := parseGetFilters(q.Get)
	if err != nil {
		return nil, err
	}
	leaves = append(leaves, vf.all...)
	if err := s.checkSensorFields(ctx, bare, leaves); err != nil {
		return nil, err
	}
	if len(where) == 0 && len(vf.all) == 0 {
		// A question with no conditions asks every endpoint, which is not
		// a choice of similar ones.
		return nil, fmt.Errorf("the saved question %q has no conditions, so it would name every endpoint; choose one that narrows the fleet", q.Name)
	}
	devices, _, err := s.devicesForMatching(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, d := range questionMatches(devices, where, q.MatchAll, vf) {
		if !seen[d.AgentID] {
			seen[d.AgentID] = true
			out = append(out, d.AgentID)
		}
	}
	sort.Strings(out)
	return out, nil
}

// endpointBriefs describes endpoints for a preview, in hostname order.
func (s *Server) endpointBriefs(ctx context.Context, ids []string) ([]triageEndpointBrief, error) {
	agents, err := s.store.ListAgents(ctx, s.staleAfter())
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	out := []triageEndpointBrief{}
	for _, a := range agents {
		if want[a.AgentID] {
			out = append(out, triageEndpointBrief{AgentID: a.AgentID, Hostname: a.Hostname, OS: a.OS, Online: a.Online})
			delete(want, a.AgentID)
		}
	}
	// A member the agents list no longer has is still named, so the count
	// the requester sees is the count the request carries.
	for id := range want {
		out = append(out, triageEndpointBrief{AgentID: id, Hostname: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

// requestTriageRollout parks the fix, on the endpoints the preview showed,
// as an approval request.
func (s *Server) requestTriageRollout(ctx context.Context, it store.TriageItem, fix store.TriageFix, pv triageSimilarPreview, u *store.User) (store.TriageRollout, error) {
	ids := make([]string, 0, len(pv.Endpoints))
	for _, e := range pv.Endpoints {
		ids = append(ids, e.AgentID)
	}
	var req triageFixRequest
	switch fix.Kind {
	case "package":
		var tmpl deployRequest
		if err := json.Unmarshal(fix.Request, &tmpl); err != nil {
			return store.TriageRollout{}, fmt.Errorf("the fix's request is unreadable: %w", err)
		}
		req = triageFixRequest{Kind: "package", PackageID: fix.RefID, RevisionID: tmpl.RevisionID, Operation: tmpl.Operation, Parameters: tmpl.Parameters}
	case "playbook":
		req = triageFixRequest{Kind: "playbook", PlaybookID: fix.RefID}
	}
	rt, err := s.triageFixRoute(ctx, req, ids)
	if err != nil {
		return store.TriageRollout{}, err
	}
	parked, _ := json.Marshal(parkedRequest{Handler: rt.pattern, Body: rt.body, PathValues: rt.pathValues})
	summary := fmt.Sprintf("triage %q: %s on %d endpoint(s) of %s %s", safeTruncate(it.Title, 80), rt.name, len(ids), pv.TargetKind, pv.TargetName)
	expires := time.Now().Add(approvalWindow)
	apr := store.ApprovalRequest{
		ID: idgen.New("apr-"), PolicyName: "Triage: apply to similar endpoints", Module: rt.module,
		Summary: summary, Method: http.MethodPost, Path: rt.path, Body: parked,
		AgentIDs: ids, DeviceCount: len(ids), RequestedBy: u.Username, ExpiresAt: &expires,
	}
	if err := s.store.CreateApprovalRequest(ctx, apr); err != nil {
		return store.TriageRollout{}, err
	}
	ro := store.TriageRollout{ID: idgen.New("tro-"), ItemID: it.ID, FixID: fix.ID, TargetKind: pv.TargetKind, TargetID: pv.TargetID,
		TargetName: pv.TargetName, AgentIDs: ids, ApprovalID: apr.ID, RequestedBy: u.Username, ApprovalState: "pending"}
	if err := s.store.CreateTriageRollout(ctx, ro); err != nil {
		return store.TriageRollout{}, err
	}
	s.audit(ctx, auditEvent{Action: rt.module + ".approval_requested", Actor: u.Username, Target: summary, Severity: "notice",
		Detail: map[string]any{"request_id": apr.ID, "policy": apr.PolicyName, "devices": len(ids), "triage_item": it.ID}})
	s.notifyRequest(ctx, "notice", "Approvals", u.Username+" is asking for approval: "+summary,
		fmt.Sprintf("%s · %d endpoint(s) · from triage", rt.module, len(ids)), "/access#approvals", "approval", apr.ID, true)
	s.triageNote(ctx, it.ID, "similar", u.Username,
		fmt.Sprintf("Asked for approval to run %s on %d endpoint(s) of %s %s", rt.name, len(ids), pv.TargetKind, pv.TargetName),
		map[string]any{"request_id": apr.ID, "fix_id": fix.ID, "devices": len(ids)})
	return ro, nil
}

// triageCallerMayRequest refuses an API token (nobody could approve a
// token's request: the approval replays as the requester's account) and a
// caller without the permission the fix's route needs.
func (s *Server) triageCallerMayRequest(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	u := auth.CurrentUser(r.Context())
	if _, isToken := auth.Token(r.Context()); isToken || u == nil || u.ID == auth.APITokenUserID {
		http.Error(w, "asking for approval needs a console session: an approved request runs as the account that asked", http.StatusForbidden)
		return nil, false
	}
	ok, err := s.auth.HasPermission(r.Context(), u, auth.PermDeployManage)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	if !ok {
		http.Error(w, "forbidden: running packages and playbooks needs "+auth.PermDeployManage, http.StatusForbidden)
		return nil, false
	}
	return u, true
}
