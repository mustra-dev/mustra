package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeviceReplacementProduct is one product found on the old endpoint of a
// device replacement, and what became of it: already on the new endpoint,
// or with no catalog package that installs it there.
type DeviceReplacementProduct struct {
	// Key is the product's normalised identity (the Inventory & Usage key).
	Key        string `json:"product_key"`
	Name       string `json:"name"`
	Vendor     string `json:"vendor,omitempty"`
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`
	// PackageID and PackageName name the catalog package that matched the
	// product, when one did but does not install it on the new endpoint.
	PackageID   string `json:"package_id,omitempty"`
	PackageName string `json:"package_name,omitempty"`
	// Reason says why the product is in its list, in words.
	Reason string `json:"reason,omitempty"`
}

// DeviceReplacementItem is one catalog package a device replacement
// installs on the new endpoint, with the deployment that carries it.
type DeviceReplacementItem struct {
	PackageID   string `json:"package_id"`
	PackageName string `json:"package_name"`
	Version     string `json:"version,omitempty"`
	// Products are the names of the old endpoint's products this package
	// matched there.
	Products []string `json:"products"`
	// RunID is the ordinary software deployment that installs it; the
	// item's status is derived from that run's result on the new endpoint.
	RunID string `json:"run_id,omitempty"`
	// ApprovalID is set when the deployment was parked for approval.
	ApprovalID string `json:"approval_id,omitempty"`
	// Status: pending, running, awaiting_approval, installed, failed,
	// timed_out, no_response, skipped or refused. Stored once the job
	// finishes; while it runs it is derived on every read.
	Status string `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// DeviceReplacement is one device replacement job: the software of an old
// endpoint, installed on the endpoint that replaces it.
type DeviceReplacement struct {
	ID          string `json:"id"`
	OldAgentID  string `json:"old_agent_id"`
	OldHostname string `json:"old_hostname"`
	OldOS       string `json:"old_os"`
	NewAgentID  string `json:"new_agent_id"`
	NewHostname string `json:"new_hostname"`
	NewOS       string `json:"new_os"`
	// Ticket is the external ticket the job answers (a ServiceNow incident
	// or request number, or a sys_id), if one was given.
	Ticket       string `json:"ticket,omitempty"`
	AllowCrossOS bool   `json:"allow_cross_os"`
	RequestedBy  string `json:"requested_by"`
	// Source is "console" or "api" (an API token started it).
	Source         string                     `json:"source"`
	Items          []DeviceReplacementItem    `json:"items"`
	AlreadyPresent []DeviceReplacementProduct `json:"already_present"`
	NoMatch        []DeviceReplacementProduct `json:"no_match"`
	CreatedAt      time.Time                  `json:"created_at"`
	FinishedAt     *time.Time                 `json:"finished_at,omitempty"`
	// NoteStatus is what became of the report to the ticket: "" (no
	// ticket), "pending", "posted", "failed", "not_configured" or "skipped"
	// (a ticket reference that is not a ServiceNow one).
	NoteStatus string     `json:"note_status,omitempty"`
	NoteDetail string     `json:"note_detail,omitempty"`
	NotedAt    *time.Time `json:"noted_at,omitempty"`
}

const deviceReplacementColumns = `id, old_agent_id, old_hostname, old_os, new_agent_id, new_hostname, new_os,
       ticket, allow_cross_os, requested_by, source, items, already_present, no_match,
       created_at, finished_at, note_status, note_detail, noted_at`

func scanDeviceReplacement(row pgx.Row) (*DeviceReplacement, error) {
	var d DeviceReplacement
	var items, present, noMatch []byte
	if err := row.Scan(&d.ID, &d.OldAgentID, &d.OldHostname, &d.OldOS, &d.NewAgentID, &d.NewHostname, &d.NewOS,
		&d.Ticket, &d.AllowCrossOS, &d.RequestedBy, &d.Source, &items, &present, &noMatch,
		&d.CreatedAt, &d.FinishedAt, &d.NoteStatus, &d.NoteDetail, &d.NotedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(items, &d.Items); err != nil {
		return nil, fmt.Errorf("device replacement %s items: %w", d.ID, err)
	}
	if err := json.Unmarshal(present, &d.AlreadyPresent); err != nil {
		return nil, fmt.Errorf("device replacement %s already present: %w", d.ID, err)
	}
	if err := json.Unmarshal(noMatch, &d.NoMatch); err != nil {
		return nil, fmt.Errorf("device replacement %s no match: %w", d.ID, err)
	}
	if d.Items == nil {
		d.Items = []DeviceReplacementItem{}
	}
	if d.AlreadyPresent == nil {
		d.AlreadyPresent = []DeviceReplacementProduct{}
	}
	if d.NoMatch == nil {
		d.NoMatch = []DeviceReplacementProduct{}
	}
	return &d, nil
}

func marshalList[T any](v []T) ([]byte, error) {
	if v == nil {
		v = []T{}
	}
	return json.Marshal(v)
}

// CreateDeviceReplacement records a new job.
func (s *Store) CreateDeviceReplacement(ctx context.Context, d DeviceReplacement) error {
	items, err := marshalList(d.Items)
	if err != nil {
		return err
	}
	present, err := marshalList(d.AlreadyPresent)
	if err != nil {
		return err
	}
	noMatch, err := marshalList(d.NoMatch)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO device_replacements (id, old_agent_id, old_hostname, old_os, new_agent_id, new_hostname, new_os,
  ticket, allow_cross_os, requested_by, source, items, already_present, no_match, note_status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		d.ID, d.OldAgentID, d.OldHostname, d.OldOS, d.NewAgentID, d.NewHostname, d.NewOS,
		d.Ticket, d.AllowCrossOS, d.RequestedBy, d.Source, items, present, noMatch, d.NoteStatus)
	if err != nil {
		return fmt.Errorf("create device replacement: %w", err)
	}
	return nil
}

// SetDeviceReplacementItems stores a running job's items, as dispatched.
func (s *Store) SetDeviceReplacementItems(ctx context.Context, id string, items []DeviceReplacementItem) error {
	raw, err := marshalList(items)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE device_replacements SET items = $2 WHERE id = $1 AND finished_at IS NULL`, id, raw)
	return err
}

// GetDeviceReplacement returns one job, or nil.
func (s *Store) GetDeviceReplacement(ctx context.Context, id string) (*DeviceReplacement, error) {
	d, err := scanDeviceReplacement(s.pool.QueryRow(ctx, `SELECT `+deviceReplacementColumns+` FROM device_replacements WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

// ListDeviceReplacements returns the newest jobs first; unfinished only
// lists the jobs still running.
func (s *Store) ListDeviceReplacements(ctx context.Context, limit int, unfinished bool) ([]DeviceReplacement, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `SELECT `+deviceReplacementColumns+` FROM device_replacements
WHERE ($2 = false OR finished_at IS NULL) ORDER BY created_at DESC LIMIT $1`, limit, unfinished)
	if err != nil {
		return nil, fmt.Errorf("list device replacements: %w", err)
	}
	defer rows.Close()
	out := []DeviceReplacement{}
	for rows.Next() {
		d, err := scanDeviceReplacement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// FinishDeviceReplacement stores a job's final item results and marks it
// finished. It reports false when the job had already been finished, so
// of two servers sweeping the same job only one reports it to its ticket.
func (s *Store) FinishDeviceReplacement(ctx context.Context, id string, items []DeviceReplacementItem, noteStatus string) (bool, error) {
	raw, err := marshalList(items)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE device_replacements SET items = $2, finished_at = now(), note_status = $3
WHERE id = $1 AND finished_at IS NULL`, id, raw, noteStatus)
	if err != nil {
		return false, fmt.Errorf("finish device replacement: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetDeviceReplacementNote records what became of the report to the
// job's ticket.
func (s *Store) SetDeviceReplacementNote(ctx context.Context, id, status, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE device_replacements SET note_status = $2, note_detail = $3, noted_at = now() WHERE id = $1`, id, status, detail)
	return err
}
