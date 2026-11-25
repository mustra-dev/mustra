package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// RingRollout is one staged rollout of a patch run or an Enforce promotion:
// a deployment plan's rings, copied in when it started, with what each ring
// has done so far.
type RingRollout struct {
	ID string `json:"id"`
	// Kind is "patch" (a patch schedule firing or a Deploy now) or
	// "enforce" (a report-mode policy promoted to enforce ring by ring).
	Kind string `json:"kind"`
	// SourceID is the patch schedule or Enforce policy the rollout belongs
	// to; blank for a Deploy now, which has nothing to come back to.
	SourceID   string `json:"source_id"`
	SourceName string `json:"source_name"`
	PlanID     string `json:"plan_id"`
	PlanName   string `json:"plan_name"`
	// Status is running, halted (a ring missed its threshold, or a patch
	// failed its health check; waiting for an operator to resume or abort),
	// completed or aborted.
	Status string `json:"status"`
	// CurrentRing indexes Rings; equal to len(Rings) once every ring is done.
	CurrentRing int           `json:"current_ring"`
	Rings       []RolloutRing `json:"rings"`
	// Params is what the kind needs to dispatch a later ring (a patch run's
	// target and restart choice).
	Params     json.RawMessage `json:"params,omitempty"`
	HaltReason string          `json:"halt_reason,omitempty"`
	// Untouched counts endpoints of the target that no ring took, known
	// once the rollout completes: a plan of group rings that do not cover
	// the whole target leaves them alone, and says so.
	Untouched  int        `json:"untouched"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// version guards a read-modify-write against a concurrent one (the
	// rollout loop and an operator's resume).
	version int
}

// RolloutRing is one ring of a rollout: its definition from the plan, and
// its progress.
type RolloutRing struct {
	Ring
	// State is pending, running (dispatched, results coming in), soaking
	// (complete and passing, waiting out its soak time), passed, failed
	// (missed its threshold or tripped a health check) or skipped (no
	// endpoint of the target fell in it).
	State    string   `json:"state"`
	AgentIDs []string `json:"agent_ids"`
	// RunID is the patch run (deployment) this ring dispatched.
	RunID       string      `json:"run_id,omitempty"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
	SoakUntil   *time.Time  `json:"soak_until,omitempty"`
	Outcome     RingOutcome `json:"outcome"`
	Note        string      `json:"note,omitempty"`
}

// RingOutcome counts a ring's endpoints by what their results say. Every
// endpoint is in exactly one bucket; Open is still working. NoResponse is
// an endpoint that never reported, which is not a success.
type RingOutcome struct {
	Total      int `json:"total"`
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
	TimedOut   int `json:"timed_out"`
	NoResponse int `json:"no_response"`
	Unknown    int `json:"unknown"`
	Open       int `json:"open"`
}

// ErrRolloutOpen is returned when a schedule or policy already has a
// rollout running or halted.
var ErrRolloutOpen = errors.New("a rollout is already open for this")

const ringRolloutColumns = `id, kind, source_id, source_name, plan_id, plan_name, status, current_ring,
  rings, params, halt_reason, untouched, version, created_by, created_at, updated_at, finished_at`

func scanRingRollout(row pgx.Row) (*RingRollout, error) {
	var r RingRollout
	var rings, params []byte
	if err := row.Scan(&r.ID, &r.Kind, &r.SourceID, &r.SourceName, &r.PlanID, &r.PlanName, &r.Status,
		&r.CurrentRing, &rings, &params, &r.HaltReason, &r.Untouched, &r.version, &r.CreatedBy,
		&r.CreatedAt, &r.UpdatedAt, &r.FinishedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rings, &r.Rings); err != nil {
		return nil, fmt.Errorf("decode rollout rings: %w", err)
	}
	if r.Rings == nil {
		r.Rings = []RolloutRing{}
	}
	for i := range r.Rings {
		if r.Rings[i].AgentIDs == nil {
			r.Rings[i].AgentIDs = []string{}
		}
	}
	r.Params = params
	return &r, nil
}

// CreateRingRollout records a new rollout. A schedule or policy with one
// already open gets ErrRolloutOpen.
func (s *Store) CreateRingRollout(ctx context.Context, r RingRollout) (*RingRollout, error) {
	rings, err := json.Marshal(r.Rings)
	if err != nil {
		return nil, fmt.Errorf("encode rollout rings: %w", err)
	}
	params := []byte(r.Params)
	if len(params) == 0 {
		params = []byte("{}")
	}
	out, err := scanRingRollout(s.pool.QueryRow(ctx, `
INSERT INTO ring_rollouts (id, kind, source_id, source_name, plan_id, plan_name, status, current_ring, rings, params, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
RETURNING `+ringRolloutColumns,
		r.ID, r.Kind, r.SourceID, r.SourceName, r.PlanID, r.PlanName, r.Status, r.CurrentRing, rings, params, r.CreatedBy))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrRolloutOpen
	}
	if err != nil {
		return nil, fmt.Errorf("create rollout: %w", err)
	}
	return out, nil
}

// GetRingRollout reads one rollout, or (nil, nil) when there is none.
func (s *Store) GetRingRollout(ctx context.Context, id string) (*RingRollout, error) {
	r, err := scanRingRollout(s.pool.QueryRow(ctx, `SELECT `+ringRolloutColumns+` FROM ring_rollouts WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get rollout: %w", err)
	}
	return r, nil
}

// ListRingRollouts lists rollouts newest first, optionally of one kind or
// one schedule or policy. Open ones come first whatever their age: a halted
// rollout from last week is still waiting for somebody.
func (s *Store) ListRingRollouts(ctx context.Context, kind, sourceID string, limit int) ([]RingRollout, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT `+ringRolloutColumns+` FROM ring_rollouts
WHERE ($1 = '' OR kind = $1) AND ($2 = '' OR source_id = $2)
ORDER BY (status IN ('running','halted')) DESC, created_at DESC LIMIT $3`, kind, sourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list rollouts: %w", err)
	}
	return collectRingRollouts(rows)
}

// RunningRingRollouts is what the rollout loop advances.
func (s *Store) RunningRingRollouts(ctx context.Context) ([]RingRollout, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ringRolloutColumns+` FROM ring_rollouts WHERE status = 'running' ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("running rollouts: %w", err)
	}
	return collectRingRollouts(rows)
}

// OpenRingRollout returns the running or halted rollout of a schedule or
// policy, or nil.
func (s *Store) OpenRingRollout(ctx context.Context, kind, sourceID string) (*RingRollout, error) {
	r, err := scanRingRollout(s.pool.QueryRow(ctx, `SELECT `+ringRolloutColumns+` FROM ring_rollouts
WHERE kind = $1 AND source_id = $2 AND status IN ('running','halted') LIMIT 1`, kind, sourceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open rollout: %w", err)
	}
	return r, nil
}

// RunningRolloutsForRun finds the running rollouts one of whose rings
// dispatched this patch run: what a failed health check halts.
func (s *Store) RunningRolloutsForRun(ctx context.Context, runID string) ([]RingRollout, error) {
	if runID == "" {
		return nil, nil
	}
	probe, _ := json.Marshal([]map[string]string{{"run_id": runID}})
	rows, err := s.pool.Query(ctx, `SELECT `+ringRolloutColumns+` FROM ring_rollouts
WHERE status = 'running' AND rings @> $1::jsonb`, probe)
	if err != nil {
		return nil, fmt.Errorf("rollouts for run: %w", err)
	}
	return collectRingRollouts(rows)
}

func collectRingRollouts(rows pgx.Rows) ([]RingRollout, error) {
	defer rows.Close()
	out := []RingRollout{}
	for rows.Next() {
		r, err := scanRingRollout(rows)
		if err != nil {
			return nil, fmt.Errorf("scan rollout: %w", err)
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// SaveRingRollout writes a rollout's progress back. It returns false, and
// writes nothing, when the row changed since it was read; the caller reads
// it again rather than overwriting an operator's resume or abort.
func (s *Store) SaveRingRollout(ctx context.Context, r *RingRollout) (bool, error) {
	rings, err := json.Marshal(r.Rings)
	if err != nil {
		return false, fmt.Errorf("encode rollout rings: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
UPDATE ring_rollouts SET status = $3, current_ring = $4, rings = $5, halt_reason = $6, untouched = $7,
  finished_at = $8, updated_at = now(), version = version + 1
WHERE id = $1 AND version = $2`,
		r.ID, r.version, r.Status, r.CurrentRing, rings, r.HaltReason, r.Untouched, r.FinishedAt)
	if err != nil {
		return false, fmt.Errorf("save rollout: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	r.version++
	return true, nil
}

// SetEnforcePolicyMode switches a policy's mode, but only from the mode the
// caller expects: a promotion finishing switches report to enforce, and
// must not undo somebody having just set it back.
func (s *Store) SetEnforcePolicyMode(ctx context.Context, id, from, to, by string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE enforce_policies SET mode = $3, updated_at = now(), updated_by = $4
WHERE id = $1 AND mode = $2`, id, from, to, by)
	if err != nil {
		return false, fmt.Errorf("set enforce policy mode: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// PatchSchedulesUsingPlan names the schedules that roll out through a
// plan, so deleting it can refuse rather than leave them firing with no
// plan at all.
func (s *Store) PatchSchedulesUsingPlan(ctx context.Context, planID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT name FROM patch_schedules WHERE plan_id = $1 ORDER BY name`, planID)
	if err != nil {
		return nil, fmt.Errorf("schedules using plan: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
