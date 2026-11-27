package server

// The ticket half of a device replacement: the finished report, added as a
// work note to the ServiceNow record the job was started for, through the
// ServiceNow integration's own instance URL and credentials
// (Administration → Integrations). The integration raises incidents; a
// work note can go on any task record, so a ticket number's prefix picks the
// table, and a bare sys_id is taken to be an incident's.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

var (
	// A ticket reference is shown, logged and possibly sent to ServiceNow;
	// it is held to what ticket numbers and sys_ids look like.
	ticketRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:#/-]{0,63}$`)
	snowNumberRe  = regexp.MustCompile(`^([A-Z]+)[0-9]{4,12}$`)
	snowSysIDRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	snowTicketTbl = map[string]string{
		"INC": "incident", "RITM": "sc_req_item", "REQ": "sc_request", "SCTASK": "sc_task", "CHG": "change_request",
	}
)

// normalizeTicket validates a ticket reference. A ServiceNow number is
// upper-cased and a sys_id lower-cased; anything else ticket-shaped is kept
// as given and reported against, but not posted to.
func normalizeTicket(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t == "" {
		return "", nil
	}
	if !ticketRe.MatchString(t) {
		return "", errors.New("ticket must be a ticket number or sys_id: letters, digits and . _ : # / - only, at most 64")
	}
	if snowSysIDRe.MatchString(strings.ToLower(t)) {
		return strings.ToLower(t), nil
	}
	if snowNumberRe.MatchString(strings.ToUpper(t)) {
		return strings.ToUpper(t), nil
	}
	return t, nil
}

// snowTicketTarget is the table and record a ticket reference names: a
// number (looked up) or a sys_id.
func snowTicketTarget(ticket string) (table, number, sysID string, err error) {
	if snowSysIDRe.MatchString(ticket) {
		return "incident", "", ticket, nil
	}
	m := snowNumberRe.FindStringSubmatch(ticket)
	if m == nil {
		return "", "", "", fmt.Errorf("%q is not a ServiceNow number or sys_id", ticket)
	}
	table = snowTicketTbl[m[1]]
	if table == "" {
		return "", "", "", fmt.Errorf("%q: ServiceNow numbers starting INC, RITM, REQ, SCTASK or CHG are supported", ticket)
	}
	return table, ticket, "", nil
}

// snowClient talks to one ServiceNow instance's Table API.
type snowClient struct {
	base, user, pass string
	client           *http.Client
}

func (c snowClient) do(ctx context.Context, method, target string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mustra/"+version.Version)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+basicAuth(c.user, c.pass))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.client
	if hc == nil {
		hc = integrationClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ServiceNow answered %d %s", resp.StatusCode, strings.TrimSpace(safeTruncate(string(data), 300)))
	}
	return data, nil
}

// addWorkNote adds text to a ticket's work notes. A number is looked up
// first and must name exactly one record.
func (c snowClient) addWorkNote(ctx context.Context, ticket, text string) error {
	u, err := url.Parse(strings.TrimRight(c.base, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the ServiceNow integration has no valid URL")
	}
	table, number, sysID, err := snowTicketTarget(ticket)
	if err != nil {
		return err
	}
	api := strings.TrimRight(c.base, "/") + "/api/now/table/" + table
	if sysID == "" {
		q := url.Values{"sysparm_query": {"number=" + number}, "sysparm_fields": {"sys_id,number"}, "sysparm_limit": {"2"}}
		data, err := c.do(ctx, http.MethodGet, api+"?"+q.Encode(), nil)
		if err != nil {
			return err
		}
		var found struct {
			Result []struct {
				SysID string `json:"sys_id"`
			} `json:"result"`
		}
		if err := json.Unmarshal(data, &found); err != nil {
			return fmt.Errorf("ServiceNow's answer for %s could not be read: %w", number, err)
		}
		switch len(found.Result) {
		case 0:
			return fmt.Errorf("ServiceNow has no %s numbered %s (or the integration's account cannot read it)", table, number)
		case 1:
		default:
			return fmt.Errorf("ServiceNow has more than one %s numbered %s", table, number)
		}
		sysID = found.Result[0].SysID
		if !snowSysIDRe.MatchString(sysID) {
			return fmt.Errorf("ServiceNow returned an unexpected sys_id for %s", number)
		}
	}
	_, err = c.do(ctx, http.MethodPatch, api+"/"+sysID, map[string]string{"work_notes": text})
	return err
}

// postReplacementNote reports a finished job to its ticket through the
// first enabled ServiceNow integration, and says what happened.
func (s *Server) postReplacementNote(ctx context.Context, job store.DeviceReplacement, text string) (status, detail string) {
	if job.Ticket == "" {
		return "", ""
	}
	if _, _, _, err := snowTicketTarget(job.Ticket); err != nil {
		return "skipped", err.Error()
	}
	list, err := s.store.ListIntegrations(ctx)
	if err != nil {
		return "failed", err.Error()
	}
	for _, in := range list {
		if in.Kind != "servicenow" || !in.Enabled {
			continue
		}
		secret, err := s.integrationSecret(in)
		if err != nil {
			return "failed", "the ServiceNow integration's credentials cannot be read: " + err.Error()
		}
		user, pass, _ := strings.Cut(secret, ":")
		err = snowClient{base: in.Config["url"], user: user, pass: pass}.addWorkNote(ctx, job.Ticket, text)
		_ = s.store.RecordIntegrationResult(ctx, in.ID, err)
		if err != nil {
			s.logger.Warn("device replacement work note failed", "id", job.ID, "ticket", job.Ticket, "error", err)
			return "failed", err.Error()
		}
		return "posted", "Added to " + job.Ticket + "'s work notes through " + in.Name
	}
	return "not_configured", "No ServiceNow integration is enabled under Administration → Integrations"
}
