package server

// Triage queue (#89): support tickets and alerts, each tied to the endpoint
// it is about, worked to resolution in one place.
//
// An item arrives from a source — a ServiceNow business rule calling the
// API, an alert an operator sends over from the Guide, a script, or a
// person typing it in — and is matched to its endpoint by agent ID,
// hostname or serial number. A match has to be unambiguous: two endpoints
// with the same hostname leave the item unattached with both named, for an
// operator to choose, because acting on the wrong machine is worse than
// asking. From the item an operator reads the endpoint's state from what
// mustra already holds (triage_context.go), runs an existing package or
// playbook on exactly that endpoint through the ordinary routes
// (triage_fix.go), asks for the same fix on similar endpoints through the
// approvals mechanism (triage_similar.go), and resolves it, which posts
// the resolution back to a ServiceNow ticket (triage_servicenow.go).
//
// Sources are a table, not a switch: anything else that finds something a
// person should look at (anomaly detection, say) feeds the queue with
// openTriageItem and a source name of its own.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/store"
)

// triageSource describes where items come from.
type triageSource struct {
	Label string
	// Inbound sources may be named in POST /api/triage/items. The others
	// have their own way in (alert: the Guide's "Send to triage").
	Inbound bool
}

var triageSources = map[string]triageSource{
	"manual":     {Label: "Manual", Inbound: true},
	"api":        {Label: "API", Inbound: true},
	"servicenow": {Label: "ServiceNow", Inbound: true},
	// Self Service has no help request yet (ToDo.md); the source is here so
	// one can file into the queue when it does.
	"self_service": {Label: "Self Service", Inbound: true},
	"alert":        {Label: "Alert"},
}

var triageStatuses = map[string]string{
	"new": "New", "in_progress": "In progress", "waiting": "Waiting", "resolved": "Resolved",
}

// triageTransitions is which status may follow which. Resolved reopens to
// in progress only: an item somebody closed is not new again.
var triageTransitions = map[string][]string{
	"new":         {"in_progress", "waiting", "resolved"},
	"in_progress": {"new", "waiting", "resolved"},
	"waiting":     {"in_progress", "resolved"},
	"resolved":    {"in_progress"},
}

func triageTransitionAllowed(from, to string) bool {
	for _, s := range triageTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

const (
	maxTriageTitle       = 300
	maxTriageDescription = 20000
	maxTriageNote        = 10000
)

// triageEndpointRef is what a source says about the endpoint.
type triageEndpointRef struct {
	AgentID  string
	Hostname string
	Serial   string
}

func (r triageEndpointRef) empty() bool {
	return r.AgentID == "" && r.Hostname == "" && r.Serial == ""
}

// placeholderSerials are what firmware reports when nobody set a serial
// number. Matching on one would tie a ticket to every machine of that make.
var placeholderSerials = map[string]bool{
	"0": true, "none": true, "n/a": true, "na": true, "default string": true, "to be filled by o.e.m.": true,
	"system serial number": true, "chassis serial number": true, "not specified": true, "not applicable": true,
	"0123456789": true, "123456789": true, "1234567890": true, "unknown": true,
}

func shortHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

// resolveTriageEndpoint matches a source's reference to one endpoint. Each
// identifier given picks the endpoints it names: the agent ID exactly, the
// serial number ignoring case, the hostname ignoring case (or, when no
// hostname matches in full, by its first label, so "web01" finds
// "web01.corp.example"). An identifier that names nothing is reported and
// left out; the endpoint is the one every remaining identifier agrees on.
// Several endpoints, or identifiers naming different ones, leave the item
// unattached with the candidates listed: never a guess.
func resolveTriageEndpoint(all []store.EndpointIdentity, ref triageEndpointRef) (string, string, []store.EndpointIdentity) {
	ref.AgentID = strings.TrimSpace(ref.AgentID)
	ref.Hostname = strings.TrimSpace(ref.Hostname)
	ref.Serial = strings.TrimSpace(ref.Serial)
	if ref.empty() {
		return "", "the source did not name an endpoint", nil
	}
	type match struct {
		label, value string
		ids          map[string]bool
	}
	var matches []match
	var unmatched []string
	pick := func(label, value string, f func(store.EndpointIdentity) bool) {
		m := match{label: label, value: value, ids: map[string]bool{}}
		for _, e := range all {
			if f(e) {
				m.ids[e.AgentID] = true
			}
		}
		if len(m.ids) == 0 {
			unmatched = append(unmatched, fmt.Sprintf("no endpoint has %s %q", label, value))
			return
		}
		matches = append(matches, m)
	}
	if ref.AgentID != "" {
		pick("agent ID", ref.AgentID, func(e store.EndpointIdentity) bool { return e.AgentID == ref.AgentID })
	}
	if ref.Serial != "" {
		if placeholderSerials[strings.ToLower(ref.Serial)] {
			unmatched = append(unmatched, fmt.Sprintf("serial number %q is a firmware placeholder, not used", ref.Serial))
		} else {
			pick("serial number", ref.Serial, func(e store.EndpointIdentity) bool {
				return e.Serial != "" && strings.EqualFold(strings.TrimSpace(e.Serial), ref.Serial)
			})
		}
	}
	if ref.Hostname != "" {
		full := 0
		for _, e := range all {
			if strings.EqualFold(e.Hostname, ref.Hostname) {
				full++
			}
		}
		if full > 0 {
			pick("hostname", ref.Hostname, func(e store.EndpointIdentity) bool { return strings.EqualFold(e.Hostname, ref.Hostname) })
		} else {
			short := shortHostname(ref.Hostname)
			pick("hostname", ref.Hostname, func(e store.EndpointIdentity) bool { return short != "" && shortHostname(e.Hostname) == short })
		}
	}
	byID := make(map[string]store.EndpointIdentity, len(all))
	for _, e := range all {
		byID[e.AgentID] = e
	}
	list := func(ids map[string]bool) []store.EndpointIdentity {
		out := make([]store.EndpointIdentity, 0, len(ids))
		for id := range ids {
			out = append(out, byID[id])
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Hostname != out[j].Hostname {
				return out[i].Hostname < out[j].Hostname
			}
			return out[i].AgentID < out[j].AgentID
		})
		return out
	}
	tail := ""
	if len(unmatched) > 0 {
		tail = "; " + strings.Join(unmatched, "; ")
	}
	if len(matches) == 0 {
		return "", "no endpoint matched: " + strings.Join(unmatched, "; "), nil
	}
	common := map[string]bool{}
	for id := range matches[0].ids {
		common[id] = true
	}
	for _, m := range matches[1:] {
		for id := range common {
			if !m.ids[id] {
				delete(common, id)
			}
		}
	}
	labels := make([]string, 0, len(matches))
	for _, m := range matches {
		labels = append(labels, m.label)
	}
	switch {
	case len(common) == 1:
		for id := range common {
			return id, "matched by " + strings.Join(labels, " and ") + tail, nil
		}
	case len(common) == 0:
		union := map[string]bool{}
		var parts []string
		for _, m := range matches {
			var names []string
			for _, e := range list(m.ids) {
				union[e.AgentID] = true
				names = append(names, e.Hostname)
			}
			parts = append(parts, fmt.Sprintf("%s %q names %s", m.label, m.value, strings.Join(names, ", ")))
		}
		return "", "the identifiers name different endpoints (" + strings.Join(parts, "; ") + "); choose one" + tail, list(union)
	}
	var parts []string
	for _, m := range matches {
		if len(m.ids) > 1 {
			parts = append(parts, fmt.Sprintf("%s %q matches %d endpoints", m.label, m.value, len(m.ids)))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d endpoints match", len(common)))
	}
	return "", strings.Join(parts, "; ") + "; choose one" + tail, list(common)
}

// triageInput is a new or updated item, from any source.
type triageInput struct {
	Source         string
	ExternalRef    string
	ExternalNumber string
	ExternalURL    string
	ExternalTable  string
	IntegrationID  string
	Title          string
	Description    string
	Endpoint       triageEndpointRef
	Assignee       string
	// Note is added to the timeline as the source's words: the comment a
	// ServiceNow rule sends with an update, say.
	Note string
}

// openTriageItem files an item, or updates the one the source already
// filed under the same reference. It is the way in for every source; the
// caller has checked the actor may.
func (s *Server) openTriageItem(ctx context.Context, in triageInput, actor string) (store.TriageItem, bool, error) {
	in.Source = strings.TrimSpace(in.Source)
	if _, ok := triageSources[in.Source]; !ok {
		return store.TriageItem{}, false, httpError{400, fmt.Sprintf("unknown source %q", in.Source)}
	}
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" {
		return store.TriageItem{}, false, httpError{400, "a title is required"}
	}
	in.ExternalRef = strings.TrimSpace(in.ExternalRef)
	if len(in.ExternalRef) > 256 {
		return store.TriageItem{}, false, httpError{400, "external_ref is at most 256 characters"}
	}
	if in.ExternalURL = strings.TrimSpace(in.ExternalURL); in.ExternalURL != "" && safeLink(in.ExternalURL) == "" {
		return store.TriageItem{}, false, httpError{400, "external_url must be an http(s) URL"}
	}
	if in.Source == "servicenow" {
		if err := checkServiceNowRef(in.ExternalRef, in.ExternalTable); err != nil {
			return store.TriageItem{}, false, err
		}
	}
	if in.Assignee = strings.TrimSpace(in.Assignee); in.Assignee != "" {
		if u, err := s.store.GetUserByUsername(ctx, in.Assignee); err != nil || u == nil {
			return store.TriageItem{}, false, httpError{400, fmt.Sprintf("no user %q to assign", in.Assignee)}
		}
	}
	all, err := s.store.EndpointIdentities(ctx)
	if err != nil {
		return store.TriageItem{}, false, err
	}
	agentID, match, _ := resolveTriageEndpoint(all, in.Endpoint)
	it, created, err := s.store.UpsertTriageItem(ctx, store.TriageItem{
		ID: idgen.New("tri-"), Source: in.Source, ExternalRef: in.ExternalRef,
		ExternalNumber: safeTruncate(strings.TrimSpace(in.ExternalNumber), 100), ExternalURL: in.ExternalURL,
		ExternalTable: strings.TrimSpace(in.ExternalTable), IntegrationID: strings.TrimSpace(in.IntegrationID),
		Title: safeTruncate(in.Title, maxTriageTitle), Description: safeTruncate(strings.TrimSpace(in.Description), maxTriageDescription),
		Assignee: in.Assignee, AgentID: agentID,
		RefAgentID: safeTruncate(strings.TrimSpace(in.Endpoint.AgentID), 200), RefHostname: safeTruncate(strings.TrimSpace(in.Endpoint.Hostname), 255),
		RefSerial: safeTruncate(strings.TrimSpace(in.Endpoint.Serial), 200), EndpointMatch: match, CreatedBy: actor,
	})
	if err != nil {
		return store.TriageItem{}, false, err
	}
	label := triageSources[in.Source].Label
	if created {
		s.triageNote(ctx, it.ID, "created", actor, "Opened from "+label, map[string]any{"endpoint_match": it.EndpointMatch, "agent_id": it.AgentID})
	} else {
		s.triageNote(ctx, it.ID, "updated", actor, "Updated by "+label, nil)
	}
	if note := strings.TrimSpace(in.Note); note != "" {
		s.triageNote(ctx, it.ID, "note", actor, safeTruncate(note, maxTriageNote), map[string]any{"from": in.Source})
	}
	action := "triage.update"
	if created {
		action = "triage.create"
	}
	s.audit(ctx, auditEvent{Action: action, Actor: actor, Target: it.Title, AgentID: it.AgentID, Severity: "info",
		Detail: map[string]any{"item": it.ID, "source": it.Source, "external_ref": it.ExternalRef, "endpoint_match": it.EndpointMatch}})
	return it, created, nil
}

// triageNote adds a timeline entry. A failure is logged, not returned: the
// change it describes has happened and is in the audit log either way.
func (s *Server) triageNote(ctx context.Context, itemID, kind, author, body string, detail map[string]any) {
	if err := s.store.AddTriageNote(ctx, store.TriageNote{ID: idgen.New("trn-"), ItemID: itemID, Kind: kind, Author: author,
		Body: body, Detail: detail}); err != nil {
		s.logger.Warn("triage: could not add to the timeline", "item", itemID, "kind", kind, "error", err)
	}
	if err := s.store.TouchTriageItem(ctx, itemID); err != nil {
		s.logger.Warn("triage: could not touch item", "item", itemID, "error", err)
	}
}

// triageAlertAgent reads the endpoint a Guide item is about from its link
// (/endpoint/<id>, optionally with a section).
func triageAlertAgent(link string) string {
	rest, ok := strings.CutPrefix(link, "/endpoint/")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "#?/"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func triageNow() *time.Time {
	t := time.Now().UTC()
	return &t
}
