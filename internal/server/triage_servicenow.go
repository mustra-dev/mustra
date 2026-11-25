package server

// Closing the loop with ServiceNow: when an item that came from a ticket is
// resolved, the resolution is written to the ticket as a work note, through
// the ServiceNow integration's own URL and credentials (Administration →
// Integrations; the secret is sealed like every integration secret).
// Whether it got there is recorded on the item and in its timeline, so a
// resolution that never reached the ticket is visible and can be sent again.
//
// Nothing polls ServiceNow. Tickets arrive because a business rule or flow
// in ServiceNow calls POST /api/triage/items with an API token; see
// docs/guides/triage.md for that side.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mustra-dev/mustra/internal/store"
)

var (
	serviceNowSysID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	serviceNowTable = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
)

// checkServiceNowRef insists on a sys_id, which is what the resolution is
// later written back to, and a plain table name: both become part of a
// URL on the ServiceNow instance.
func checkServiceNowRef(ref, table string) error {
	if !serviceNowSysID.MatchString(ref) {
		return httpError{http.StatusBadRequest, "a ServiceNow item's external_ref is the record's sys_id (32 hex characters)"}
	}
	if table != "" && !serviceNowTable.MatchString(table) {
		return httpError{http.StatusBadRequest, "external_table must be a ServiceNow table name such as incident"}
	}
	return nil
}

// safeLink returns u when it is an absolute http(s) URL, or "".
func safeLink(u string) string {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return ""
	}
	return u
}

// triageServiceNowIntegration finds the integration an item's resolution
// goes through: the one it names, or the only enabled ServiceNow one.
func (s *Server) triageServiceNowIntegration(ctx context.Context, it store.TriageItem) (store.Integration, error) {
	list, err := s.store.ListIntegrations(ctx)
	if err != nil {
		return store.Integration{}, err
	}
	var found []store.Integration
	for _, in := range list {
		if in.Kind != "servicenow" {
			continue
		}
		if it.IntegrationID != "" {
			if in.ID == it.IntegrationID {
				return in, nil
			}
			continue
		}
		if in.Enabled {
			found = append(found, in)
		}
	}
	switch {
	case it.IntegrationID != "":
		return store.Integration{}, fmt.Errorf("the ServiceNow integration %q no longer exists", it.IntegrationID)
	case len(found) == 0:
		return store.Integration{}, fmt.Errorf("no ServiceNow integration is enabled (Administration → Integrations)")
	case len(found) > 1:
		return store.Integration{}, fmt.Errorf("%d ServiceNow integrations are enabled; the item has to name one (integration_id)", len(found))
	}
	return found[0], nil
}

// triageResolutionText is the work note: who resolved it, what they said,
// which endpoint and what was run on it, and where the item is.
func (s *Server) triageResolutionText(ctx context.Context, it store.TriageItem, who, note string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Resolved in Mustra by %s.", firstNonEmpty(who, "mustra"))
	if note = strings.TrimSpace(note); note != "" {
		b.WriteString("\n\n" + note)
	}
	if it.AgentID != "" {
		fmt.Fprintf(&b, "\n\nEndpoint: %s", firstNonEmpty(it.Hostname, it.AgentID))
	}
	if fixes, err := s.store.ListTriageFixes(ctx, it.ID); err == nil && len(fixes) > 0 {
		b.WriteString("\nRun on it:")
		for _, f := range fixes {
			fmt.Fprintf(&b, "\n- %s (%s): %s", f.Name, f.Kind, firstNonEmpty(f.Outcome, f.State))
		}
	}
	if link := s.eventLink(ctx, integrationEvent{Link: "/triage?id=" + url.QueryEscape(it.ID)}); link != "" {
		b.WriteString("\n\n" + link)
	}
	return safeTruncate(b.String(), 4000)
}

// postTriageResolution writes the work note to the ticket.
func (s *Server) postTriageResolution(ctx context.Context, it store.TriageItem, text string) error {
	if err := checkServiceNowRef(it.ExternalRef, it.ExternalTable); err != nil {
		return fmt.Errorf("this item has no usable ServiceNow reference")
	}
	in, err := s.triageServiceNowIntegration(ctx, it)
	if err != nil {
		return err
	}
	secret, err := s.integrationSecret(in)
	if err != nil {
		return fmt.Errorf("the integration's credentials could not be read: %w", err)
	}
	user, pass, _ := strings.Cut(secret, ":")
	table := firstNonEmpty(it.ExternalTable, "incident")
	target := strings.TrimRight(in.Config["url"], "/") + "/api/now/table/" + table + "/" + it.ExternalRef
	raw, _ := json.Marshal(map[string]string{"work_notes": text})
	err = integrationSend(ctx, http.MethodPatch, target, raw, map[string]string{
		"Authorization": "Basic " + basicAuth(user, pass), "Accept": "application/json", "Content-Type": "application/json"})
	_ = s.store.RecordIntegrationResult(ctx, in.ID, err)
	return err
}

// syncTriageResolution sends the resolution of an item that came from
// ServiceNow and records the outcome on the item, its timeline and the
// audit log. Items from other sources have nowhere to send it.
func (s *Server) syncTriageResolution(ctx context.Context, it store.TriageItem, who, note string) (string, string) {
	if it.Source != "servicenow" {
		return "", ""
	}
	err := s.postTriageResolution(ctx, it, s.triageResolutionText(ctx, it, who, note))
	state, errText, outcome := "sent", "", "ok"
	body := "Resolution posted to " + firstNonEmpty(it.ExternalNumber, "the ServiceNow ticket")
	if err != nil {
		state, errText, outcome = "failed", safeTruncate(err.Error(), 500), "failed"
		body = "Could not post the resolution to ServiceNow: " + errText
	}
	if e := s.store.SetTriageSync(ctx, it.ID, state, errText); e != nil {
		s.logger.Warn("triage: could not record the ServiceNow result", "item", it.ID, "error", e)
	}
	s.triageNote(ctx, it.ID, "sync", who, body, map[string]any{"state": state})
	s.audit(ctx, auditEvent{Action: "triage.servicenow", Actor: who, Target: it.Title, AgentID: it.AgentID, Outcome: outcome,
		Severity: map[bool]string{true: "warning", false: "info"}[err != nil],
		Detail:   map[string]any{"item": it.ID, "ticket": firstNonEmpty(it.ExternalNumber, it.ExternalRef), "error": errText}})
	return state, errText
}
