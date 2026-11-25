package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// TriageItem is one support ticket or alert in the triage queue.
type TriageItem struct {
	ID     string `json:"id"`
	Source string `json:"source"` // servicenow | self_service | alert | api | manual
	// ExternalRef is the source's own identifier (a ServiceNow sys_id, a
	// Guide item's id). Together with Source it is unique: the same ticket
	// sent twice updates one item.
	ExternalRef    string `json:"external_ref,omitempty"`
	ExternalNumber string `json:"external_number,omitempty"` // what people call it: INC0010023
	ExternalURL    string `json:"external_url,omitempty"`
	// ExternalTable is the ServiceNow table the ticket lives in (incident
	// when empty).
	ExternalTable string `json:"external_table,omitempty"`
	// IntegrationID names the ServiceNow integration that resolutions are
	// posted through; empty uses the only enabled one.
	IntegrationID string `json:"integration_id,omitempty"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Status        string `json:"status"` // new | in_progress | waiting | resolved
	Assignee      string `json:"assignee"`
	// AgentID is the endpoint the item is about; empty while unattached.
	AgentID string `json:"agent_id"`
	// Hostname is the attached endpoint's current hostname, when it still
	// exists.
	Hostname string `json:"hostname,omitempty" api:"readonly"`
	// RefAgentID, RefHostname and RefSerial are what the source said the
	// endpoint was, kept so the match can be explained and redone.
	RefAgentID  string `json:"ref_agent_id,omitempty"`
	RefHostname string `json:"ref_hostname,omitempty"`
	RefSerial   string `json:"ref_serial,omitempty"`
	// EndpointMatch says how the endpoint was found, or why it was not.
	EndpointMatch string     `json:"endpoint_match"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy    string     `json:"resolved_by,omitempty"`
	// SyncState is whether the resolution reached the source's ticket:
	// "" (nothing to send), sent or failed; SyncError says why it failed.
	SyncState string     `json:"sync_state,omitempty"`
	SyncError string     `json:"sync_error,omitempty"`
	SyncAt    *time.Time `json:"sync_at,omitempty"`
}

const triageItemColumns = `t.id, t.source, t.external_ref, t.external_number, t.external_url, t.external_table, t.integration_id,
	t.title, t.description, t.status, t.assignee, t.agent_id, coalesce(a.hostname, ''), t.ref_agent_id, t.ref_hostname, t.ref_serial,
	t.endpoint_match, t.created_by, t.created_at, t.updated_at, t.resolved_at, t.resolved_by, t.sync_state, t.sync_error, t.sync_at`

const triageItemFrom = ` FROM triage_items t LEFT JOIN agents a ON a.agent_id = t.agent_id AND t.agent_id <> ''`

func scanTriageItem(row pgx.Row) (TriageItem, error) {
	var t TriageItem
	err := row.Scan(&t.ID, &t.Source, &t.ExternalRef, &t.ExternalNumber, &t.ExternalURL, &t.ExternalTable, &t.IntegrationID,
		&t.Title, &t.Description, &t.Status, &t.Assignee, &t.AgentID, &t.Hostname, &t.RefAgentID, &t.RefHostname, &t.RefSerial,
		&t.EndpointMatch, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.ResolvedBy, &t.SyncState, &t.SyncError, &t.SyncAt)
	return t, err
}

// UpsertTriageItem creates an item, or, when one with the same source and
// external reference exists, refreshes it from the source: title,
// description and the source's references change; status, assignee and
// notes are the operators' and stay. An endpoint already attached stays
// attached; one found now is attached only to an item that had none.
// created reports which happened.
func (s *Store) UpsertTriageItem(ctx context.Context, in TriageItem) (TriageItem, bool, error) {
	const q = `
INSERT INTO triage_items (id, source, external_ref, external_number, external_url, external_table, integration_id,
	title, description, status, assignee, agent_id, ref_agent_id, ref_hostname, ref_serial, endpoint_match, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'new',$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (source, external_ref) WHERE external_ref <> '' DO UPDATE SET
	title = EXCLUDED.title,
	description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE triage_items.description END,
	external_number = CASE WHEN EXCLUDED.external_number <> '' THEN EXCLUDED.external_number ELSE triage_items.external_number END,
	external_url = CASE WHEN EXCLUDED.external_url <> '' THEN EXCLUDED.external_url ELSE triage_items.external_url END,
	external_table = CASE WHEN EXCLUDED.external_table <> '' THEN EXCLUDED.external_table ELSE triage_items.external_table END,
	integration_id = CASE WHEN EXCLUDED.integration_id <> '' THEN EXCLUDED.integration_id ELSE triage_items.integration_id END,
	ref_agent_id = EXCLUDED.ref_agent_id, ref_hostname = EXCLUDED.ref_hostname, ref_serial = EXCLUDED.ref_serial,
	agent_id = CASE WHEN triage_items.agent_id = '' THEN EXCLUDED.agent_id ELSE triage_items.agent_id END,
	endpoint_match = CASE WHEN triage_items.agent_id = '' THEN EXCLUDED.endpoint_match ELSE triage_items.endpoint_match END,
	updated_at = now()
RETURNING id, (xmax = 0)`
	var id string
	var created bool
	err := s.pool.QueryRow(ctx, q, in.ID, in.Source, in.ExternalRef, in.ExternalNumber, in.ExternalURL, in.ExternalTable, in.IntegrationID,
		in.Title, in.Description, in.Assignee, in.AgentID, in.RefAgentID, in.RefHostname, in.RefSerial, in.EndpointMatch, in.CreatedBy).Scan(&id, &created)
	if err != nil {
		return TriageItem{}, false, fmt.Errorf("upsert triage item: %w", err)
	}
	it, err := s.GetTriageItem(ctx, id)
	if err != nil || it == nil {
		return TriageItem{}, false, errors.Join(err, errors.New("triage item vanished after saving"))
	}
	return *it, created, nil
}

// GetTriageItem returns one item, or nil.
func (s *Store) GetTriageItem(ctx context.Context, id string) (*TriageItem, error) {
	t, err := scanTriageItem(s.pool.QueryRow(ctx, `SELECT `+triageItemColumns+triageItemFrom+` WHERE t.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get triage item: %w", err)
	}
	return &t, nil
}

// TriageFilter narrows the queue; empty fields match everything. Open
// leaves out resolved items.
type TriageFilter struct {
	Status   string
	Source   string
	Assignee string
	AgentID  string
	Open     bool
	Limit    int
}

// ListTriageItems returns the queue, most recently changed first.
func (s *Store) ListTriageItems(ctx context.Context, f TriageFilter) ([]TriageItem, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 500
	}
	rows, err := s.pool.Query(ctx, `SELECT `+triageItemColumns+triageItemFrom+`
WHERE ($1 = '' OR t.status = $1) AND ($2 = '' OR t.source = $2) AND ($3 = '' OR t.assignee = $3)
  AND ($4 = '' OR t.agent_id = $4) AND (NOT $5 OR t.status <> 'resolved')
ORDER BY t.updated_at DESC LIMIT $6`, f.Status, f.Source, f.Assignee, f.AgentID, f.Open, f.Limit)
	if err != nil {
		return nil, fmt.Errorf("list triage items: %w", err)
	}
	defer rows.Close()
	out := []TriageItem{}
	for rows.Next() {
		t, err := scanTriageItem(rows)
		if err != nil {
			return nil, fmt.Errorf("scan triage item: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TriageCounts are the queue's tiles.
type TriageCounts struct {
	New        int `json:"new"`
	InProgress int `json:"in_progress"`
	Waiting    int `json:"waiting"`
	Resolved   int `json:"resolved"`
	Unattached int `json:"unattached"`
}

func (s *Store) TriageCounts(ctx context.Context) (TriageCounts, error) {
	var c TriageCounts
	err := s.pool.QueryRow(ctx, `SELECT
	count(*) FILTER (WHERE status = 'new'),
	count(*) FILTER (WHERE status = 'in_progress'),
	count(*) FILTER (WHERE status = 'waiting'),
	count(*) FILTER (WHERE status = 'resolved'),
	count(*) FILTER (WHERE status <> 'resolved' AND agent_id = '')
FROM triage_items`).Scan(&c.New, &c.InProgress, &c.Waiting, &c.Resolved, &c.Unattached)
	if err != nil {
		return c, fmt.Errorf("count triage items: %w", err)
	}
	return c, nil
}

// UpdateTriageItem writes an item's operator-owned fields, but only while
// its status is still fromStatus: two people moving the same item at once
// must not both believe their transition happened. It reports false when
// somebody else changed the status first.
func (s *Store) UpdateTriageItem(ctx context.Context, t TriageItem, fromStatus string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE triage_items SET title = $3, description = $4, status = $5, assignee = $6,
	agent_id = $7, endpoint_match = $8, resolved_at = $9, resolved_by = $10, updated_at = now()
WHERE id = $1 AND status = $2`,
		t.ID, fromStatus, t.Title, t.Description, t.Status, t.Assignee, t.AgentID, t.EndpointMatch, t.ResolvedAt, t.ResolvedBy)
	if err != nil {
		return false, fmt.Errorf("update triage item: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// SetTriageSync records whether the resolution reached the source.
func (s *Store) SetTriageSync(ctx context.Context, id, state, errText string) error {
	_, err := s.pool.Exec(ctx, `UPDATE triage_items SET sync_state = $2, sync_error = $3, sync_at = now() WHERE id = $1`, id, state, errText)
	if err != nil {
		return fmt.Errorf("record triage sync: %w", err)
	}
	return nil
}

// TouchTriageItem marks an item changed, for activity that is not a field
// (a note, a fix), so the queue's ordering reflects it.
func (s *Store) TouchTriageItem(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE triage_items SET updated_at = now() WHERE id = $1`, id)
	return err
}

// TriageNote is one entry in an item's timeline.
type TriageNote struct {
	ID        string         `json:"id"`
	ItemID    string         `json:"item_id"`
	Kind      string         `json:"kind"` // note | created | updated | status | assignee | endpoint | fix | similar | sync
	Author    string         `json:"author"`
	Body      string         `json:"body"`
	Detail    map[string]any `json:"detail,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

func (s *Store) AddTriageNote(ctx context.Context, n TriageNote) error {
	detail := n.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO triage_notes (id, item_id, kind, author, body, detail) VALUES ($1,$2,$3,$4,$5,$6)`,
		n.ID, n.ItemID, n.Kind, n.Author, n.Body, raw)
	if err != nil {
		return fmt.Errorf("add triage note: %w", err)
	}
	return nil
}

func (s *Store) ListTriageNotes(ctx context.Context, itemID string) ([]TriageNote, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, item_id, kind, author, body, detail, created_at FROM triage_notes
WHERE item_id = $1 ORDER BY created_at, id`, itemID)
	if err != nil {
		return nil, fmt.Errorf("list triage notes: %w", err)
	}
	defer rows.Close()
	out := []TriageNote{}
	for rows.Next() {
		var n TriageNote
		var raw []byte
		if err := rows.Scan(&n.ID, &n.ItemID, &n.Kind, &n.Author, &n.Body, &raw, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan triage note: %w", err)
		}
		_ = json.Unmarshal(raw, &n.Detail)
		out = append(out, n)
	}
	return out, rows.Err()
}

// TriageFix is a fix run from an item on its endpoint.
type TriageFix struct {
	ID          string          `json:"id"`
	ItemID      string          `json:"item_id"`
	Kind        string          `json:"kind"` // package | playbook
	RefID       string          `json:"ref_id"`
	Name        string          `json:"name"`
	Request     json.RawMessage `json:"request,omitempty"`
	AgentID     string          `json:"agent_id"`
	RunID       string          `json:"run_id,omitempty"`
	ApprovalID  string          `json:"approval_id,omitempty"`
	State       string          `json:"state"` // dispatched | parked | skipped
	Detail      string          `json:"detail,omitempty"`
	RequestedBy string          `json:"requested_by"`
	CreatedAt   time.Time       `json:"created_at"`
	// Outcome is read from the run when the fix is listed: the deploy
	// job's status for a package (queued, running, succeeded, failed,
	// timed_out…), the playbook run's for a playbook (running, succeeded,
	// partial, failed); empty until the run exists.
	Outcome string `json:"outcome" api:"readonly"`
}

func (s *Store) CreateTriageFix(ctx context.Context, f TriageFix) error {
	req := f.Request
	if len(req) == 0 {
		req = json.RawMessage("{}")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO triage_fixes (id, item_id, kind, ref_id, name, request, agent_id, run_id, approval_id, state, detail, requested_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		f.ID, f.ItemID, f.Kind, f.RefID, f.Name, []byte(req), f.AgentID, f.RunID, f.ApprovalID, f.State, f.Detail, f.RequestedBy)
	if err != nil {
		return fmt.Errorf("create triage fix: %w", err)
	}
	return nil
}

// A parked fix has no run until its approval replays it; the replay's
// outcome names the run, so the approval request is followed for it.
const triageFixSelect = `SELECT f.id, f.item_id, f.kind, f.ref_id, f.name, f.request, f.agent_id, f.run_id, f.approval_id, f.state, f.detail,
	f.requested_by, f.created_at,
	coalesce(CASE f.kind
		WHEN 'package' THEN (SELECT j.status FROM deploy_jobs j WHERE j.run_id = f.run_id AND j.agent_id = f.agent_id AND f.run_id <> ''
		                     ORDER BY j.created_at DESC LIMIT 1)
		WHEN 'playbook' THEN (SELECT r.status FROM playbook_runs r WHERE r.id = f.run_id AND f.run_id <> '')
	END, CASE WHEN f.approval_id <> '' THEN (SELECT 'approval_' || ar.state FROM approval_requests ar WHERE ar.id = f.approval_id) END, '')
FROM triage_fixes f`

func scanTriageFix(row pgx.Row) (TriageFix, error) {
	var f TriageFix
	var req []byte
	err := row.Scan(&f.ID, &f.ItemID, &f.Kind, &f.RefID, &f.Name, &req, &f.AgentID, &f.RunID, &f.ApprovalID, &f.State, &f.Detail,
		&f.RequestedBy, &f.CreatedAt, &f.Outcome)
	f.Request = req
	return f, err
}

func (s *Store) ListTriageFixes(ctx context.Context, itemID string) ([]TriageFix, error) {
	rows, err := s.pool.Query(ctx, triageFixSelect+` WHERE f.item_id = $1 ORDER BY f.created_at, f.id`, itemID)
	if err != nil {
		return nil, fmt.Errorf("list triage fixes: %w", err)
	}
	defer rows.Close()
	out := []TriageFix{}
	for rows.Next() {
		f, err := scanTriageFix(rows)
		if err != nil {
			return nil, fmt.Errorf("scan triage fix: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetTriageFix(ctx context.Context, id string) (*TriageFix, error) {
	f, err := scanTriageFix(s.pool.QueryRow(ctx, triageFixSelect+` WHERE f.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get triage fix: %w", err)
	}
	return &f, nil
}

// SetTriageFixRun records the run a parked fix became once approved.
func (s *Store) SetTriageFixRun(ctx context.Context, id, runID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE triage_fixes SET run_id = $2, state = 'dispatched' WHERE id = $1 AND run_id = ''`, id, runID)
	if err != nil {
		return fmt.Errorf("record triage fix run: %w", err)
	}
	return nil
}

// TriageRollout is one "apply to similar endpoints" request.
type TriageRollout struct {
	ID          string    `json:"id"`
	ItemID      string    `json:"item_id"`
	FixID       string    `json:"fix_id"`
	TargetKind  string    `json:"target_kind"` // group | question
	TargetID    string    `json:"target_id"`
	TargetName  string    `json:"target_name"`
	AgentIDs    []string  `json:"agent_ids"`
	ApprovalID  string    `json:"approval_id"`
	RequestedBy string    `json:"requested_by"`
	CreatedAt   time.Time `json:"created_at"`
	// ApprovalState and Outcome are the approval request's, read when
	// listed: pending, approved, denied, expired or failed, and what the
	// replay answered.
	ApprovalState string `json:"approval_state" api:"readonly"`
	DecidedBy     string `json:"decided_by,omitempty" api:"readonly"`
	Outcome       string `json:"outcome,omitempty" api:"readonly"`
}

func (s *Store) CreateTriageRollout(ctx context.Context, r TriageRollout) error {
	if r.AgentIDs == nil {
		r.AgentIDs = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO triage_rollouts (id, item_id, fix_id, target_kind, target_id, target_name, agent_ids, approval_id, requested_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.ID, r.ItemID, r.FixID, r.TargetKind, r.TargetID, r.TargetName, r.AgentIDs, r.ApprovalID, r.RequestedBy)
	if err != nil {
		return fmt.Errorf("create triage rollout: %w", err)
	}
	return nil
}

func (s *Store) ListTriageRollouts(ctx context.Context, itemID string) ([]TriageRollout, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.id, r.item_id, r.fix_id, r.target_kind, r.target_id, r.target_name, r.agent_ids, r.approval_id,
	r.requested_by, r.created_at, coalesce(a.state, ''), coalesce(a.decided_by, ''), coalesce(a.outcome, '')
FROM triage_rollouts r LEFT JOIN approval_requests a ON a.id = r.approval_id
WHERE r.item_id = $1 ORDER BY r.created_at, r.id`, itemID)
	if err != nil {
		return nil, fmt.Errorf("list triage rollouts: %w", err)
	}
	defer rows.Close()
	out := []TriageRollout{}
	for rows.Next() {
		var r TriageRollout
		if err := rows.Scan(&r.ID, &r.ItemID, &r.FixID, &r.TargetKind, &r.TargetID, &r.TargetName, &r.AgentIDs, &r.ApprovalID,
			&r.RequestedBy, &r.CreatedAt, &r.ApprovalState, &r.DecidedBy, &r.Outcome); err != nil {
			return nil, fmt.Errorf("scan triage rollout: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EndpointIdentity is what an item's endpoint is matched on: the agent ID,
// the hostname, and the serial number from the hardware sensor.
type EndpointIdentity struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Serial   string `json:"serial,omitempty"`
	OS       string `json:"os,omitempty"`
}

// EndpointIdentities lists every endpoint in inventory with its serial
// number, for matching an item to its endpoint. Retired endpoints are in
// it: a ticket about a machine that has been quiet a month is still about
// that machine.
func (s *Store) EndpointIdentities(ctx context.Context) ([]EndpointIdentity, error) {
	// The hardware sensor's payload is a one-element list.
	rows, err := s.pool.Query(ctx, `SELECT a.agent_id, a.hostname, a.os,
	coalesce(CASE jsonb_typeof(d.data) WHEN 'array' THEN d.data->0->>'serial' ELSE d.data->>'serial' END, '')
FROM agents a LEFT JOIN agent_sensor_data d ON d.agent_id = a.agent_id AND d.sensor = 'hardware'`)
	if err != nil {
		return nil, fmt.Errorf("list endpoint identities: %w", err)
	}
	defer rows.Close()
	out := []EndpointIdentity{}
	for rows.Next() {
		var e EndpointIdentity
		if err := rows.Scan(&e.AgentID, &e.Hostname, &e.OS, &e.Serial); err != nil {
			return nil, fmt.Errorf("scan endpoint identity: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetGuideNotification returns one Guide item, or nil.
func (s *Store) GetGuideNotification(ctx context.Context, id string) (*GuideNotification, error) {
	var n GuideNotification
	err := s.pool.QueryRow(ctx, `SELECT `+guideColumns+` FROM guide_notifications WHERE id = $1`, id).Scan(
		&n.ID, &n.SubjectKey, &n.Source, &n.Kind, &n.Severity, &n.Title, &n.Detail, &n.Link, &n.Count,
		&n.FirstSeen, &n.LastSeen, &n.DismissedAt, &n.DismissedBy, &n.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get guide notification: %w", err)
	}
	return &n, nil
}

// OpenGuideForEndpoint returns the open Guide items about one endpoint:
// those whose link opens its page.
func (s *Store) OpenGuideForEndpoint(ctx context.Context, agentID string) ([]GuideNotification, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+guideColumns+` FROM guide_notifications
WHERE resolved_at IS NULL AND (link = '/endpoint/' || $1 OR starts_with(link, '/endpoint/' || $1 || '#') OR starts_with(link, '/endpoint/' || $1 || '?'))
ORDER BY last_seen DESC LIMIT 50`, agentID)
	if err != nil {
		return nil, fmt.Errorf("list endpoint guide items: %w", err)
	}
	defer rows.Close()
	out := []GuideNotification{}
	for rows.Next() {
		var n GuideNotification
		if err := rows.Scan(&n.ID, &n.SubjectKey, &n.Source, &n.Kind, &n.Severity, &n.Title, &n.Detail, &n.Link, &n.Count,
			&n.FirstSeen, &n.LastSeen, &n.DismissedAt, &n.DismissedBy, &n.ResolvedAt); err != nil {
			return nil, fmt.Errorf("scan guide notification: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
