package server

// HTTP surface of the triage queue. Reading it is fleet.read like the rest
// of the fleet; working items (filing, editing, notes, fixes, asking for a
// rollout, sending a resolution) is alerts.triage, the permission for
// deciding what an alert means. An API token holding alerts.triage is how
// a ServiceNow business rule files tickets. A fix additionally needs what
// the route it runs needs (deploy.manage, management rights, the action
// group, any approval policy), because it runs through that route.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// listTriageResponse is what GET /api/triage/items answers.
type listTriageResponse struct {
	Items    []store.TriageItem `json:"items"`
	Counts   store.TriageCounts `json:"counts"`
	Sources  map[string]string  `json:"sources"`
	Statuses map[string]string  `json:"statuses"`
}

func (s *Server) handleListTriage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.TriageFilter{Status: q.Get("status"), Source: q.Get("source"), Assignee: q.Get("assignee"),
		AgentID: q.Get("agent_id"), Open: q.Get("open") == "1"}
	if f.Status != "" && triageStatuses[f.Status] == "" {
		http.Error(w, "unknown status", http.StatusBadRequest)
		return
	}
	items, err := s.store.ListTriageItems(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts, err := s.store.TriageCounts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sources := map[string]string{}
	for k, v := range triageSources {
		sources[k] = v.Label
	}
	writeJSONResponse(w, listTriageResponse{Items: items, Counts: counts, Sources: sources, Statuses: triageStatuses})
}

// createTriageRequest is the body of POST /api/triage/items: a new item,
// or an update to the one already filed under the same source and
// external_ref. A ServiceNow business rule sends source "servicenow",
// the record's sys_id as external_ref and its number, and whichever of
// agent_id, hostname and serial it knows.
type createTriageRequest struct {
	// Source is manual (the default), api, servicenow or self_service.
	Source string `json:"source,omitempty"`
	// ExternalRef is the source's identifier; for servicenow, the sys_id.
	ExternalRef    string `json:"external_ref,omitempty"`
	ExternalNumber string `json:"external_number,omitempty"`
	ExternalURL    string `json:"external_url,omitempty"`
	// ExternalTable is the ServiceNow table (incident when empty).
	ExternalTable string `json:"external_table,omitempty"`
	// IntegrationID chooses the ServiceNow integration resolutions are
	// posted through, when more than one is enabled.
	IntegrationID string `json:"integration_id,omitempty"`
	Title         string `json:"title" api:"required"`
	Description   string `json:"description,omitempty"`
	// AgentID, Hostname and Serial identify the endpoint; any of them, or
	// none (the item then waits for an operator to choose).
	AgentID  string `json:"agent_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Assignee string `json:"assignee,omitempty"`
	// Note is added to the item's timeline (a comment from the ticket).
	Note string `json:"note,omitempty"`
}

// triageItemResponse is what creating or updating an item answers.
type triageItemResponse struct {
	Item store.TriageItem `json:"item"`
	// Created is false when the source's reference matched an existing
	// item, which was updated instead.
	Created bool `json:"created"`
}

func (s *Server) handleCreateTriage(w http.ResponseWriter, r *http.Request) {
	var body createTriageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.Title) == "" {
		http.Error(w, "a title is required", http.StatusBadRequest)
		return
	}
	src := firstNonEmpty(strings.TrimSpace(body.Source), "manual")
	if !triageSources[src].Inbound {
		http.Error(w, fmt.Sprintf("items from %q cannot be filed here", src), http.StatusBadRequest)
		return
	}
	it, created, err := s.openTriageItem(r.Context(), triageInput{
		Source: src, ExternalRef: body.ExternalRef, ExternalNumber: body.ExternalNumber, ExternalURL: body.ExternalURL,
		ExternalTable: body.ExternalTable, IntegrationID: body.IntegrationID, Title: body.Title, Description: body.Description,
		Endpoint: triageEndpointRef{AgentID: body.AgentID, Hostname: body.Hostname, Serial: body.Serial},
		Assignee: body.Assignee, Note: body.Note,
	}, auth.CurrentUser(r.Context()).Username)
	if err != nil {
		writeTriageError(w, err)
		return
	}
	if created {
		w.WriteHeader(http.StatusCreated)
	}
	writeJSONResponse(w, triageItemResponse{Item: it, Created: created})
}

// POST /api/guide/{id}/triage: an operator sends a Guide alert to the
// queue. Its endpoint is the one the alert links to, if any; sending the
// same alert again returns the item it already became.
func (s *Server) handleGuideToTriage(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.GetGuideNotification(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n == nil {
		http.Error(w, "no such Guide item", http.StatusNotFound)
		return
	}
	desc := n.Detail
	if n.Link != "" {
		desc = strings.TrimSpace(desc + "\n\nGuide link: " + n.Link)
	}
	it, created, err := s.openTriageItem(r.Context(), triageInput{
		Source: "alert", ExternalRef: n.ID, Title: n.Title, Description: desc,
		Endpoint: triageEndpointRef{AgentID: triageAlertAgent(n.Link)},
	}, auth.CurrentUser(r.Context()).Username)
	if err != nil {
		writeTriageError(w, err)
		return
	}
	if created {
		w.WriteHeader(http.StatusCreated)
	}
	writeJSONResponse(w, triageItemResponse{Item: it, Created: created})
}

// triageDetailResponse is what GET /api/triage/items/{id} answers: the
// item, its timeline, the fixes run from it and the rollouts asked for.
// Candidates are the endpoints an unattached item's references could
// mean, for an operator to choose from.
type triageDetailResponse struct {
	Item       store.TriageItem         `json:"item"`
	Notes      []store.TriageNote       `json:"notes"`
	Fixes      []store.TriageFix        `json:"fixes"`
	Rollouts   []store.TriageRollout    `json:"rollouts"`
	Candidates []store.EndpointIdentity `json:"candidates"`
	// Transitions are the statuses the item may move to now.
	Transitions []string `json:"transitions"`
}

func (s *Server) handleGetTriage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	it, err := s.store.GetTriageItem(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if it == nil {
		http.Error(w, "no such triage item", http.StatusNotFound)
		return
	}
	out := triageDetailResponse{Item: *it, Candidates: []store.EndpointIdentity{}, Transitions: triageTransitions[it.Status]}
	if out.Notes, err = s.store.ListTriageNotes(ctx, it.ID); err == nil {
		out.Fixes, err = s.triageFixesWithRuns(ctx, it.ID)
	}
	if err == nil {
		out.Rollouts, err = s.store.ListTriageRollouts(ctx, it.ID)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if it.AgentID == "" {
		ref := triageEndpointRef{AgentID: it.RefAgentID, Hostname: it.RefHostname, Serial: it.RefSerial}
		if !ref.empty() {
			if all, err := s.store.EndpointIdentities(ctx); err == nil {
				if _, _, c := resolveTriageEndpoint(all, ref); c != nil {
					out.Candidates = c
				}
			}
		}
	}
	writeJSONResponse(w, out)
}

// updateTriageRequest is the body of PUT /api/triage/items/{id}. Fields
// left out are unchanged. Note is added to the timeline with the change
// and, when the item is resolved, is the resolution sent to ServiceNow.
type updateTriageRequest struct {
	Status      *string `json:"status,omitempty"`
	Assignee    *string `json:"assignee,omitempty"`
	AgentID     *string `json:"agent_id,omitempty"`
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	Note        string  `json:"note,omitempty"`
}

func (s *Server) handleUpdateTriage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body updateTriageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	it, err := s.store.GetTriageItem(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if it == nil {
		http.Error(w, "no such triage item", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(ctx).Username
	before := *it
	next := *it
	type change struct {
		kind, body string
		detail     map[string]any
	}
	var changes []change
	if body.Title != nil {
		t := strings.TrimSpace(*body.Title)
		if t == "" {
			http.Error(w, "a title is required", http.StatusBadRequest)
			return
		}
		if t != it.Title {
			next.Title = safeTruncate(t, maxTriageTitle)
			changes = append(changes, change{"updated", "Title changed", nil})
		}
	}
	if body.Description != nil && strings.TrimSpace(*body.Description) != it.Description {
		next.Description = safeTruncate(strings.TrimSpace(*body.Description), maxTriageDescription)
		changes = append(changes, change{"updated", "Description changed", nil})
	}
	if body.Assignee != nil && strings.TrimSpace(*body.Assignee) != it.Assignee {
		a := strings.TrimSpace(*body.Assignee)
		if a != "" {
			if u, err := s.store.GetUserByUsername(ctx, a); err != nil || u == nil {
				http.Error(w, fmt.Sprintf("no user %q to assign", a), http.StatusBadRequest)
				return
			}
		}
		next.Assignee = a
		changes = append(changes, change{"assignee", map[bool]string{true: "Assigned to " + a, false: "Unassigned"}[a != ""], nil})
	}
	if body.AgentID != nil && strings.TrimSpace(*body.AgentID) != it.AgentID {
		id := strings.TrimSpace(*body.AgentID)
		if id == "" {
			next.AgentID, next.EndpointMatch = "", "detached by "+who
			changes = append(changes, change{"endpoint", "Endpoint detached", nil})
		} else {
			host, err := s.store.GetAgentHostname(ctx, id)
			if err != nil || host == "" {
				http.Error(w, "no such endpoint", http.StatusBadRequest)
				return
			}
			next.AgentID, next.EndpointMatch = id, "chosen by "+who
			changes = append(changes, change{"endpoint", "Endpoint set to " + host, map[string]any{"agent_id": id}})
		}
	}
	resolving := false
	if body.Status != nil && *body.Status != it.Status {
		to := *body.Status
		if triageStatuses[to] == "" {
			http.Error(w, "status is new, in_progress, waiting or resolved", http.StatusBadRequest)
			return
		}
		if !triageTransitionAllowed(it.Status, to) {
			http.Error(w, fmt.Sprintf("an item that is %s cannot move to %s", triageStatuses[it.Status], triageStatuses[to]), http.StatusConflict)
			return
		}
		next.Status = to
		if to == "resolved" {
			resolving = true
			next.ResolvedAt, next.ResolvedBy = triageNow(), who
		} else {
			next.ResolvedAt, next.ResolvedBy = nil, ""
		}
		changes = append(changes, change{"status", triageStatuses[it.Status] + " → " + triageStatuses[to],
			map[string]any{"from": it.Status, "to": to}})
	}
	note := safeTruncate(strings.TrimSpace(body.Note), maxTriageNote)
	if resolving && note != "" {
		// Kept with the transition, so the resolution can be sent again
		// as it was written (handleTriageSync).
		changes[len(changes)-1].detail["resolution"] = note
	}
	if len(changes) == 0 && note == "" {
		writeJSONResponse(w, triageItemResponse{Item: *it})
		return
	}
	if len(changes) > 0 {
		ok, err := s.store.UpdateTriageItem(ctx, next, before.Status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "somebody changed this item's status first; reload it", http.StatusConflict)
			return
		}
	}
	for _, c := range changes {
		s.triageNote(ctx, it.ID, c.kind, who, c.body, c.detail)
	}
	if note != "" {
		s.triageNote(ctx, it.ID, "note", who, note, nil)
	}
	s.audit(ctx, auditEvent{Action: "triage.update", Actor: who, Target: next.Title, AgentID: next.AgentID, Severity: "info",
		Detail: map[string]any{"item": it.ID, "status": next.Status, "from_status": before.Status, "assignee": next.Assignee, "agent_id": next.AgentID}})
	updated, err := s.store.GetTriageItem(ctx, it.ID)
	if err != nil || updated == nil {
		http.Error(w, "the item could not be read back", http.StatusInternalServerError)
		return
	}
	if resolving {
		s.syncTriageResolution(ctx, *updated, who, note)
		if again, err := s.store.GetTriageItem(ctx, it.ID); err == nil && again != nil {
			updated = again
		}
	}
	writeJSONResponse(w, triageItemResponse{Item: *updated})
}

// addTriageNoteRequest is the body of POST /api/triage/items/{id}/notes.
type addTriageNoteRequest struct {
	Body string `json:"body" api:"required"`
}

func (s *Server) handleAddTriageNote(w http.ResponseWriter, r *http.Request) {
	var body addTriageNoteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	text := strings.TrimSpace(body.Body)
	if text == "" {
		http.Error(w, "a note needs some text", http.StatusBadRequest)
		return
	}
	it, err := s.store.GetTriageItem(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if it == nil {
		http.Error(w, "no such triage item", http.StatusNotFound)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	n := store.TriageNote{ID: idgen.New("trn-"), ItemID: it.ID, Kind: "note", Author: who, Body: safeTruncate(text, maxTriageNote)}
	if err := s.store.AddTriageNote(r.Context(), n); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.store.TouchTriageItem(r.Context(), it.ID)
	s.audit(r.Context(), auditEvent{Action: "triage.note", Actor: who, Target: it.Title, AgentID: it.AgentID, Severity: "info",
		Detail: map[string]any{"item": it.ID}})
	notes, err := s.store.ListTriageNotes(r.Context(), it.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, triageNotesResponse{Notes: notes})
}

// triageNotesResponse is what adding a note answers: the timeline.
type triageNotesResponse struct {
	Notes []store.TriageNote `json:"notes"`
}

// POST /api/triage/items/{id}/fix runs a package or playbook on the item's
// endpoint and nowhere else (triage_fix.go).
func (s *Server) handleTriageFix(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body triageFixRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.Kind != "package" && body.Kind != "playbook" {
		http.Error(w, `kind is "package" or "playbook"`, http.StatusBadRequest)
		return
	}
	it, err := s.store.GetTriageItem(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if it == nil {
		http.Error(w, "no such triage item", http.StatusNotFound)
		return
	}
	if it.AgentID == "" {
		http.Error(w, "choose the item's endpoint before running anything on it", http.StatusConflict)
		return
	}
	if it.Status == "resolved" {
		http.Error(w, "this item is resolved; reopen it to run a fix", http.StatusConflict)
		return
	}
	rt, err := s.triageFixRoute(ctx, body, []string{it.AgentID})
	if err != nil {
		writeTriageError(w, err)
		return
	}
	who := auth.CurrentUser(ctx).Username
	rec, err := s.callRoute(r, rt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rec.status >= 400 {
		reason := strings.TrimSpace(rec.body.String())
		s.triageNote(ctx, it.ID, "fix", who, fmt.Sprintf("%s was refused: %s", rt.name, safeTruncate(reason, 500)),
			map[string]any{"kind": body.Kind, "ref_id": rt.refID, "status": rec.status})
		http.Error(w, reason, rec.status)
		return
	}
	fix := store.TriageFix{ID: idgen.New("trf-"), ItemID: it.ID, Kind: body.Kind, RefID: rt.refID, Name: rt.name,
		Request: rt.template, AgentID: it.AgentID, RequestedBy: who}
	msg := triageFixFromAnswer(&fix, body.Kind, rec)
	if err := s.store.CreateTriageFix(ctx, fix); err != nil {
		// The run has started; losing its row on the item must not read as
		// the run having failed.
		s.logger.Error("triage: fix dispatched but not recorded", "item", it.ID, "run", fix.RunID, "error", err)
	}
	s.triageNote(ctx, it.ID, "fix", who, fmt.Sprintf("Ran %s on %s: %s", rt.name, firstNonEmpty(it.Hostname, it.AgentID), msg),
		map[string]any{"fix_id": fix.ID, "run_id": fix.RunID, "approval_id": fix.ApprovalID, "state": fix.State})
	s.audit(ctx, auditEvent{Action: "triage.fix", Actor: who, Target: rt.name, AgentID: it.AgentID, Severity: "notice",
		Detail: map[string]any{"item": it.ID, "kind": body.Kind, "ref_id": rt.refID, "run_id": fix.RunID, "state": fix.State}})
	if it.Status == "new" {
		// Running something on it is working on it.
		next := *it
		next.Status = "in_progress"
		if ok, err := s.store.UpdateTriageItem(ctx, next, "new"); err == nil && ok {
			s.triageNote(ctx, it.ID, "status", who, "New → In progress", nil)
		}
	}
	if got, err := s.store.GetTriageFix(ctx, fix.ID); err == nil && got != nil {
		fix = *got
	}
	if fix.State == "parked" {
		w.WriteHeader(http.StatusAccepted)
	}
	writeJSONResponse(w, triageFixResponse{Fix: fix, Message: msg})
}

// triageFixesWithRuns lists an item's fixes, first catching up any that
// were parked for approval and have since run: the approval's recorded
// answer names the run.
func (s *Server) triageFixesWithRuns(ctx context.Context, itemID string) ([]store.TriageFix, error) {
	fixes, err := s.store.ListTriageFixes(ctx, itemID)
	if err != nil {
		return nil, err
	}
	changed := false
	for _, f := range fixes {
		if f.State != "parked" || f.RunID != "" || f.ApprovalID == "" {
			continue
		}
		req, err := s.store.GetApprovalRequest(ctx, f.ApprovalID)
		if err != nil || req == nil || req.State != "approved" {
			continue
		}
		var ran struct {
			RunID string `json:"run_id"`
		}
		if json.Unmarshal([]byte(req.Outcome), &ran) == nil && ran.RunID != "" {
			if err := s.store.SetTriageFixRun(ctx, f.ID, ran.RunID); err == nil {
				changed = true
			}
		}
	}
	if changed {
		return s.store.ListTriageFixes(ctx, itemID)
	}
	return fixes, nil
}

func (s *Server) handleTriageSimilarPreview(w http.ResponseWriter, r *http.Request) {
	it, body, ok := s.triageSimilarStart(w, r)
	if !ok {
		return
	}
	_, pv, ok := s.triageSimilarTargets(w, r, *it, body)
	if !ok {
		return
	}
	writeJSONResponse(w, pv)
}

// POST /api/triage/items/{id}/similar asks for approval to run a fix that
// worked on the endpoints a group or saved question matches
// (triage_similar.go).
func (s *Server) handleTriageSimilar(w http.ResponseWriter, r *http.Request) {
	it, body, ok := s.triageSimilarStart(w, r)
	if !ok {
		return
	}
	u, ok := s.triageCallerMayRequest(w, r)
	if !ok {
		return
	}
	fix, pv, ok := s.triageSimilarTargets(w, r, *it, body)
	if !ok {
		return
	}
	ro, err := s.requestTriageRollout(r.Context(), *it, *fix, pv, u)
	if err != nil {
		writeTriageError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSONResponse(w, triageSimilarResponse{Rollout: ro, RequestID: ro.ApprovalID,
		Message: fmt.Sprintf("Waiting for approval: %s on %d endpoint(s). Somebody else with approvals.decide approves it under Access → Approvals.", fix.Name, len(ro.AgentIDs))})
}

func (s *Server) triageSimilarStart(w http.ResponseWriter, r *http.Request) (*store.TriageItem, triageSimilarRequest, bool) {
	var body triageSimilarRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return nil, body, false
	}
	if strings.TrimSpace(body.FixID) == "" {
		http.Error(w, "fix_id names the fix to apply", http.StatusBadRequest)
		return nil, body, false
	}
	it, err := s.store.GetTriageItem(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, body, false
	}
	if it == nil {
		http.Error(w, "no such triage item", http.StatusNotFound)
		return nil, body, false
	}
	return it, body, true
}

// triageSyncResponse is what POST /api/triage/items/{id}/sync answers.
type triageSyncResponse struct {
	Item store.TriageItem `json:"item"`
}

// POST /api/triage/items/{id}/sync sends a resolved ServiceNow item's
// resolution again, after it failed to arrive.
func (s *Server) handleTriageSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	it, err := s.store.GetTriageItem(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if it == nil {
		http.Error(w, "no such triage item", http.StatusNotFound)
		return
	}
	if it.Source != "servicenow" || it.Status != "resolved" {
		http.Error(w, "only a resolved item from ServiceNow has a resolution to send", http.StatusConflict)
		return
	}
	note := ""
	if notes, err := s.store.ListTriageNotes(ctx, it.ID); err == nil {
		for i := len(notes) - 1; i >= 0; i-- {
			if notes[i].Kind == "status" && notes[i].Detail["to"] == "resolved" {
				note, _ = notes[i].Detail["resolution"].(string)
				break
			}
		}
	}
	s.syncTriageResolution(ctx, *it, auth.CurrentUser(ctx).Username, note)
	updated, err := s.store.GetTriageItem(ctx, it.ID)
	if err != nil || updated == nil {
		http.Error(w, "the item could not be read back", http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, triageSyncResponse{Item: *updated})
}

// writeTriageError answers a validation error with its status and
// anything else as a server error.
func writeTriageError(w http.ResponseWriter, err error) {
	var he httpError
	if errors.As(err, &he) {
		http.Error(w, he.msg, he.code)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
