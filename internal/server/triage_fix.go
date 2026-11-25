package server

// Fix one: from a triage item, run an existing package or playbook on the
// item's endpoint and nothing else.
//
// The run goes through the ordinary route — POST /api/deploy/run or POST
// /api/playbooks/{id}/run — as it is registered in the route table: its
// permission check (deploy.manage), then the shared action gate
// (management rights, the module's action group, content sets, approval
// policies), then its handler. The triage route only fills in the target,
// and the target is the item's endpoint alone: the body is built here, so
// no field a caller sends can add a group, the fleet or a second endpoint.
// What the run did is read from the run itself (store.TriageFix.Outcome).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mustra-dev/mustra/internal/store"
)

// triageFixRequest is the body of POST /api/triage/items/{id}/fix.
type triageFixRequest struct {
	// Kind is package (a software or action package, through Deploy) or
	// playbook.
	Kind string `json:"kind" api:"required"`
	// PackageID, RevisionID, Operation and Parameters are a package run's,
	// as POST /api/deploy/run takes them. Operation defaults to run for an
	// action package and install for software; RevisionID to the
	// package's published revision.
	PackageID  string            `json:"package_id,omitempty"`
	RevisionID string            `json:"revision_id,omitempty"`
	Operation  string            `json:"operation,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	// PlaybookID is the playbook to run.
	PlaybookID string `json:"playbook_id,omitempty"`
}

// triageFixResponse is what POST /api/triage/items/{id}/fix answers.
type triageFixResponse struct {
	Fix     store.TriageFix `json:"fix"`
	Message string          `json:"message"`
}

// triageRoute is one call of an existing route on the item's behalf.
type triageRoute struct {
	pattern    string // as registered, e.g. "POST /api/deploy/run"
	path       string
	pathValues map[string]string
	body       []byte
	module     string // the access module the route's gate applies
	name       string // the package's or playbook's name, for people
	refID      string
	// template is body without its targets, kept on the fix so the same
	// operation can be asked for on other endpoints.
	template []byte
}

// triageFixRoute builds the route call for a fix on exactly these
// endpoints.
func (s *Server) triageFixRoute(ctx context.Context, req triageFixRequest, agentIDs []string) (triageRoute, error) {
	switch req.Kind {
	case "package":
		pkg, err := s.store.GetSoftwarePackage(ctx, strings.TrimSpace(req.PackageID))
		if err != nil {
			return triageRoute{}, err
		}
		if pkg == nil {
			return triageRoute{}, httpError{http.StatusNotFound, "no such package"}
		}
		op := strings.TrimSpace(req.Operation)
		if op == "" {
			op = "install"
			if pkg.Kind == "action" {
				op = "run"
			}
		}
		tmpl := deployRequest{PackageID: pkg.ID, RevisionID: strings.TrimSpace(req.RevisionID), Operation: op, Parameters: req.Parameters}
		template, _ := json.Marshal(tmpl)
		tmpl.AgentIDs = agentIDs
		body, _ := json.Marshal(tmpl)
		return triageRoute{pattern: "POST /api/deploy/run", path: "/api/deploy/run", body: body, module: "deploy",
			name: pkg.Name, refID: pkg.ID, template: template}, nil
	case "playbook":
		pb, err := s.store.GetPlaybook(ctx, strings.TrimSpace(req.PlaybookID))
		if err != nil {
			return triageRoute{}, err
		}
		if pb == nil {
			return triageRoute{}, httpError{http.StatusNotFound, "no such playbook"}
		}
		body, _ := json.Marshal(runPlaybookRequest{AgentIDs: agentIDs})
		return triageRoute{pattern: "POST /api/playbooks/{id}/run", path: "/api/playbooks/" + url.PathEscape(pb.ID) + "/run",
			pathValues: map[string]string{"id": pb.ID}, body: body, module: "playbooks", name: pb.Name, refID: pb.ID,
			template: []byte("{}")}, nil
	}
	return triageRoute{}, httpError{http.StatusBadRequest, `kind is "package" or "playbook"`}
}

// protectedRoute is a route as registered in the route table: its
// permission check, its gate and its handler.
func (s *Server) protectedRoute(pattern string) http.Handler {
	if s.routeLog == nil {
		return nil
	}
	for _, e := range s.routeLog.entries {
		if e.Pattern == pattern {
			return e.Handler
		}
	}
	return nil
}

// callRoute runs a route call as the current request's caller and
// captures its answer.
func (s *Server) callRoute(r *http.Request, rt triageRoute) (*captureWriter, error) {
	h := s.protectedRoute(rt.pattern)
	if h == nil {
		return nil, fmt.Errorf("route %s is not registered", rt.pattern)
	}
	inner, err := http.NewRequestWithContext(r.Context(), http.MethodPost, rt.path, bytes.NewReader(rt.body))
	if err != nil {
		return nil, err
	}
	inner.Header.Set("Content-Type", "application/json")
	inner.RemoteAddr = r.RemoteAddr
	for k, v := range rt.pathValues {
		inner.SetPathValue(k, v)
	}
	rec := &captureWriter{header: http.Header{}}
	h.ServeHTTP(rec, inner)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	return rec, nil
}

// triageFixFromAnswer reads the route's answer into the fix: a run, a
// request parked for approval, or a run that had nothing to do.
func triageFixFromAnswer(f *store.TriageFix, kind string, rec *captureWriter) string {
	raw := []byte(rec.body.String())
	if rec.status == http.StatusAccepted {
		var parked struct {
			RequestID string `json:"request_id"`
			Policy    string `json:"policy"`
		}
		_ = json.Unmarshal(raw, &parked)
		f.State, f.ApprovalID = "parked", parked.RequestID
		f.Detail = "waiting for approval under the policy " + parked.Policy
		return "An approval policy covers this; it runs once somebody approves it."
	}
	if kind == "playbook" {
		var resp runPlaybookResponse
		_ = json.Unmarshal(raw, &resp)
		f.RunID, f.State = resp.RunID, "dispatched"
		return "Playbook started on the endpoint."
	}
	var resp deployRunResponse
	_ = json.Unmarshal(raw, &resp)
	f.RunID, f.State = resp.RunID, "dispatched"
	if resp.Targets == 0 {
		var why []string
		for _, sk := range resp.Skipped {
			why = append(why, firstNonEmpty(sk["reason"], sk["detail"]))
		}
		f.State, f.Detail = "skipped", strings.Join(why, "; ")
		return "Nothing was sent: " + firstNonEmpty(f.Detail, "the endpoint does not need it")
	}
	return "Sent to the endpoint."
}
