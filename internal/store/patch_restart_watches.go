package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PatchRestartWatch is a patch job that restarted its endpoint, with what
// the server currently knows of the endpoint.
type PatchRestartWatch struct {
	ActionID        string
	AgentID         string
	RunID           string
	CreatedAt       time.Time
	CheckinDeadline time.Time
	ReportsHealth   bool
	KernelBefore    string
	KernelUpdates   []string
	BootedAt        *time.Time
	State           string

	// From the endpoint and the action, read when the watch is listed.
	Hostname      string
	Kernel        string
	BootTime      *time.Time
	LastHeartbeat *time.Time
	ActionStatus  string
}

// CreatePatchRestartWatch starts watching a job's restart. A redelivered
// result finds the watch already there and changes nothing.
func (s *Store) CreatePatchRestartWatch(ctx context.Context, w PatchRestartWatch) error {
	if w.KernelUpdates == nil {
		w.KernelUpdates = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO patch_restart_watches
  (action_id, agent_id, run_id, created_at, checkin_deadline, reports_health, kernel_before, kernel_updates)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (action_id) DO NOTHING`,
		w.ActionID, w.AgentID, w.RunID, w.CreatedAt, w.CheckinDeadline, w.ReportsHealth, w.KernelBefore, w.KernelUpdates)
	if err != nil {
		return fmt.Errorf("create patch restart watch: %w", err)
	}
	return nil
}

const patchRestartWatchSelect = `SELECT w.action_id, w.agent_id, w.run_id, w.created_at, w.checkin_deadline,
  w.reports_health, w.kernel_before, w.kernel_updates, w.booted_at, w.state,
  a.hostname, a.kernel_version, a.boot_time, a.last_heartbeat, act.status
FROM patch_restart_watches w
JOIN agents a ON a.agent_id = w.agent_id
JOIN agent_actions act ON act.id = w.action_id
WHERE w.closed_at IS NULL`

func scanPatchRestartWatch(row pgx.Row) (PatchRestartWatch, error) {
	var w PatchRestartWatch
	err := row.Scan(&w.ActionID, &w.AgentID, &w.RunID, &w.CreatedAt, &w.CheckinDeadline,
		&w.ReportsHealth, &w.KernelBefore, &w.KernelUpdates, &w.BootedAt, &w.State,
		&w.Hostname, &w.Kernel, &w.BootTime, &w.LastHeartbeat, &w.ActionStatus)
	return w, err
}

// OpenPatchRestartWatches lists the watches still open.
func (s *Store) OpenPatchRestartWatches(ctx context.Context) ([]PatchRestartWatch, error) {
	rows, err := s.pool.Query(ctx, patchRestartWatchSelect+` ORDER BY w.created_at`)
	if err != nil {
		return nil, fmt.Errorf("open patch restart watches: %w", err)
	}
	defer rows.Close()
	var out []PatchRestartWatch
	for rows.Next() {
		w, err := scanPatchRestartWatch(rows)
		if err != nil {
			return nil, fmt.Errorf("scan patch restart watch: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// OpenPatchRestartWatch is the open watch on one action, or nil.
func (s *Store) OpenPatchRestartWatch(ctx context.Context, agentID, actionID string) (*PatchRestartWatch, error) {
	w, err := scanPatchRestartWatch(s.pool.QueryRow(ctx,
		patchRestartWatchSelect+` AND w.action_id = $1 AND w.agent_id = $2`, actionID, agentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("patch restart watch: %w", err)
	}
	return &w, nil
}

// MarkPatchRestartBooted records that the endpoint is back on a new boot.
func (s *Store) MarkPatchRestartBooted(ctx context.Context, actionID string, bootedAt time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE patch_restart_watches SET state = 'stabilizing', booted_at = $2
WHERE action_id = $1 AND closed_at IS NULL AND booted_at IS NULL`, actionID, bootedAt)
	if err != nil {
		return fmt.Errorf("mark patch restart booted: %w", err)
	}
	return nil
}

// ClosePatchRestartWatch ends a watch. It reports false when something
// else closed it first, so only one of them acts on the outcome.
func (s *Store) ClosePatchRestartWatch(ctx context.Context, actionID, state, detail string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE patch_restart_watches SET state = $2, detail = $3, closed_at = now()
WHERE action_id = $1 AND closed_at IS NULL`, actionID, state, detail)
	if err != nil {
		return false, fmt.Errorf("close patch restart watch: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// UpdateRestartedAction moves a patch job that restarted its endpoint to
// status, adding note to the top of its transcript. Only a job still
// waiting on or watching its restart (pending_restart, verifying) moves:
// one cancelled or already closed since is left alone, reported false.
func (s *Store) UpdateRestartedAction(ctx context.Context, agentID, id, status, note string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_actions SET status = $3,
  detail = CASE WHEN $4 = '' THEN detail ELSE $4 || E'\n\n' || detail END, finished_at = now()
WHERE id = $1 AND agent_id = $2 AND status IN ('pending_restart', 'verifying')`, id, agentID, status, note)
	if err != nil {
		return false, fmt.Errorf("update restarted action: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// SucceedVerifiedAction closes a job watched through its restart as
// succeeded. Only one at 'verifying' moves: one still pending another
// restart keeps waiting on it.
func (s *Store) SucceedVerifiedAction(ctx context.Context, agentID, id, note string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_actions SET status = 'succeeded',
  detail = $3 || E'\n\n' || detail, finished_at = now()
WHERE id = $1 AND agent_id = $2 AND status = 'verifying'`, id, agentID, note)
	if err != nil {
		return false, fmt.Errorf("succeed verified action: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// HoldWaitingRunActions stops a run's patch jobs still held for their
// maintenance window from being released: an endpoint in the same run
// failed its check after patching, and the same updates are not rolled to
// more endpoints until someone has looked. Returns how many were held.
func (s *Store) HoldWaitingRunActions(ctx context.Context, runID, reason string) (int64, error) {
	if runID == "" {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `UPDATE agent_actions SET status = 'cancelled', detail = $2, finished_at = now()
WHERE run_id = $1 AND kind = 'patch_apply' AND status = 'waiting'`, runID, reason)
	if err != nil {
		return 0, fmt.Errorf("hold waiting run actions: %w", err)
	}
	return tag.RowsAffected(), nil
}
