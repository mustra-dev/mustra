package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Anomaly detection's storage. The judging lives in internal/anomaly; this
// file only moves numbers in and out. See schema.sql for why storage is
// tiered.

// PerfSnapshot is one endpoint's latest performance summary, for sampling.
// Data is the summary object alone (the sensor stores a one-element list).
type PerfSnapshot struct {
	AgentID     string
	CollectedAt time.Time
	Data        json.RawMessage
}

// RecentPerformance is every performance summary collected since since.
// Parsing is left to the caller: a malformed or hostile number in one
// endpoint's JSON must cost that endpoint its sample, not stop the whole
// fleet's sampling the way a failed cast inside one SQL statement would.
func (s *Store) RecentPerformance(ctx context.Context, since time.Time) ([]PerfSnapshot, error) {
	rows, err := s.pool.Query(ctx, `
SELECT agent_id, collected_at, data->0
FROM agent_sensor_data
WHERE sensor = 'performance' AND collected_at > $1 AND jsonb_typeof(data) = 'array'`, since)
	if err != nil {
		return nil, fmt.Errorf("recent performance: %w", err)
	}
	defer rows.Close()
	var out []PerfSnapshot
	for rows.Next() {
		var p PerfSnapshot
		var raw []byte
		if err := rows.Scan(&p.AgentID, &p.CollectedAt, &raw); err != nil {
			return nil, fmt.Errorf("scan performance: %w", err)
		}
		p.Data = raw
		out = append(out, p)
	}
	return out, rows.Err()
}

// AnomalySample is one value to store.
type AnomalySample struct {
	AgentID string
	Metric  string
	At      time.Time
	Value   float64
}

// InsertAnomalySamples stores samples. A sample already stored for the
// same moment is left alone, so sampling the same snapshot twice is a
// no-op.
func (s *Store) InsertAnomalySamples(ctx context.Context, samples []AnomalySample) error {
	if len(samples) == 0 {
		return nil
	}
	ids, metrics, ats, vals := make([]string, len(samples)), make([]string, len(samples)), make([]time.Time, len(samples)), make([]float64, len(samples))
	for i, x := range samples {
		ids[i], metrics[i], ats[i], vals[i] = x.AgentID, x.Metric, x.At, x.Value
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO anomaly_samples (agent_id, metric, at, value)
SELECT t.a, t.m, t.at, t.v
FROM unnest($1::text[], $2::text[], $3::timestamptz[], $4::float8[]) AS t(a, m, at, v)
WHERE EXISTS (SELECT 1 FROM agents WHERE agent_id = t.a)
ON CONFLICT DO NOTHING`, ids, metrics, ats, vals)
	if err != nil {
		return fmt.Errorf("insert anomaly samples: %w", err)
	}
	return nil
}

// SampleInventoryMetrics stores, for every processes and services
// snapshot collected since since, how many processes it listed and how
// many services had failed. Both are counted in SQL (the snapshots are
// large, and counting reads only text fields, which cannot fail a cast).
// at is truncated to bucket, so one snapshot is one sample however many
// times it is read.
func (s *Store) SampleInventoryMetrics(ctx context.Context, since time.Time, bucket time.Duration) error {
	secs := bucket.Seconds()
	_, err := s.pool.Exec(ctx, `
INSERT INTO anomaly_samples (agent_id, metric, at, value)
SELECT d.agent_id, 'processes', to_timestamp(floor(extract(epoch FROM d.collected_at) / $2) * $2), jsonb_array_length(d.data)
FROM agent_sensor_data d
WHERE d.sensor = 'processes' AND d.collected_at > $1 AND d.collected_at <= now() + interval '5 minutes'
  AND jsonb_typeof(d.data) = 'array'
ON CONFLICT DO NOTHING`, since, secs)
	if err != nil {
		return fmt.Errorf("sample processes: %w", err)
	}
	// Linux reports a systemd unit's SUB state ("failed"); Windows reports
	// start type and state, and an automatic service that is stopped is
	// the Windows equivalent. macOS's launchctl list says neither.
	_, err = s.pool.Exec(ctx, `
INSERT INTO anomaly_samples (agent_id, metric, at, value)
SELECT d.agent_id, 'services_failed', to_timestamp(floor(extract(epoch FROM d.collected_at) / $2) * $2),
       (SELECT count(*) FROM jsonb_array_elements(d.data) e
         WHERE jsonb_typeof(e) = 'object'
           AND (lower(e->>'status') = 'failed'
                OR (lower(e->>'start_type') = 'automatic' AND lower(e->>'status') = 'stopped')))
FROM agent_sensor_data d
WHERE d.sensor = 'services' AND d.collected_at > $1 AND d.collected_at <= now() + interval '5 minutes'
  AND jsonb_typeof(d.data) = 'array'
ON CONFLICT DO NOTHING`, since, secs)
	if err != nil {
		return fmt.Errorf("sample services: %w", err)
	}
	return nil
}

// SampleReboots records each endpoint's boot time as a boot, once, and
// then stores how many boots each endpoint that sent facts in the last
// half hour has had in the 24 hours before now, as the "reboots" sample
// at now.
func (s *Store) SampleReboots(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO anomaly_boots (agent_id, at)
SELECT a.agent_id, a.boot_time FROM agents a
WHERE a.boot_time IS NOT NULL AND a.boot_time > $1::timestamptz - interval '30 days' AND a.boot_time <= $1
  AND NOT EXISTS (SELECT 1 FROM anomaly_boots b WHERE b.agent_id = a.agent_id
                   AND b.at BETWEEN a.boot_time - interval '5 minutes' AND a.boot_time + interval '5 minutes')
ON CONFLICT DO NOTHING`, now)
	if err != nil {
		return fmt.Errorf("record boots: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO anomaly_samples (agent_id, metric, at, value)
SELECT a.agent_id, 'reboots', $1,
       (SELECT count(*) FROM anomaly_boots b WHERE b.agent_id = a.agent_id AND b.at > $1::timestamptz - interval '24 hours' AND b.at <= $1)
FROM agents a
WHERE a.boot_time IS NOT NULL AND a.last_facts > $1::timestamptz - interval '30 minutes'
ON CONFLICT DO NOTHING`, now)
	if err != nil {
		return fmt.Errorf("sample reboots: %w", err)
	}
	return nil
}

// RollUpAnomalyHours recomputes the hourly medians of every complete hour
// from since onward. Recomputing rather than inserting once means a
// snapshot that arrived late (an agent's outbox draining after an outage)
// still lands in its hour.
func (s *Store) RollUpAnomalyHours(ctx context.Context, since, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO anomaly_hourly (agent_id, metric, hour, median, lo, hi, n)
SELECT agent_id, metric, date_trunc('hour', at),
       percentile_cont(0.5) WITHIN GROUP (ORDER BY value), min(value), max(value), count(*)
FROM anomaly_samples
WHERE at >= date_trunc('hour', $1::timestamptz) AND at < date_trunc('hour', $2::timestamptz)
GROUP BY 1, 2, 3
ON CONFLICT (agent_id, metric, hour) DO UPDATE SET
  median = EXCLUDED.median, lo = EXCLUDED.lo, hi = EXCLUDED.hi, n = EXCLUDED.n`, since, now)
	if err != nil {
		return fmt.Errorf("roll up anomaly hours: %w", err)
	}
	return nil
}

// RecomputeAnomalyBaselines recomputes every baseline that has hourly
// medians since since: their median and MAD (anomaly.Compute is the same
// arithmetic, and the reference for it). One with none left in the window
// keeps its last value until PruneAnomalyData drops it.
func (s *Store) RecomputeAnomalyBaselines(ctx context.Context, since, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
WITH h AS (
  SELECT agent_id, metric, median AS v FROM anomaly_hourly WHERE hour >= $1
), m AS (
  SELECT agent_id, metric, percentile_cont(0.5) WITHIN GROUP (ORDER BY v) AS med, count(*) AS n
  FROM h GROUP BY 1, 2
)
INSERT INTO anomaly_baselines (agent_id, metric, median, mad, hours, computed_at)
SELECT m.agent_id, m.metric, m.med, percentile_cont(0.5) WITHIN GROUP (ORDER BY abs(h.v - m.med)), m.n, $2
FROM m JOIN h ON h.agent_id = m.agent_id AND h.metric = m.metric
GROUP BY m.agent_id, m.metric, m.med, m.n
ON CONFLICT (agent_id, metric) DO UPDATE SET
  median = EXCLUDED.median, mad = EXCLUDED.mad, hours = EXCLUDED.hours, computed_at = EXCLUDED.computed_at`, since, now)
	if err != nil {
		return fmt.Errorf("recompute anomaly baselines: %w", err)
	}
	return nil
}

// AnomalyBaseline is one stored baseline.
type AnomalyBaseline struct {
	AgentID string
	Metric  string
	Median  float64
	MAD     float64
	Hours   int
}

// ListAnomalyBaselines returns every baseline, or one endpoint's when
// agentID is set.
func (s *Store) ListAnomalyBaselines(ctx context.Context, agentID string) ([]AnomalyBaseline, error) {
	rows, err := s.pool.Query(ctx, `
SELECT agent_id, metric, median, mad, hours FROM anomaly_baselines
WHERE $1 = '' OR agent_id = $1`, agentID)
	if err != nil {
		return nil, fmt.Errorf("list anomaly baselines: %w", err)
	}
	defer rows.Close()
	var out []AnomalyBaseline
	for rows.Next() {
		var b AnomalyBaseline
		if err := rows.Scan(&b.AgentID, &b.Metric, &b.Median, &b.MAD, &b.Hours); err != nil {
			return nil, fmt.Errorf("scan anomaly baseline: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListAnomalySamples returns samples from since onward, oldest first, for
// every endpoint or one endpoint and metric.
func (s *Store) ListAnomalySamples(ctx context.Context, since time.Time, agentID, metric string) ([]AnomalySample, error) {
	rows, err := s.pool.Query(ctx, `
SELECT agent_id, metric, at, value FROM anomaly_samples
WHERE at >= $1 AND ($2 = '' OR agent_id = $2) AND ($3 = '' OR metric = $3)
ORDER BY agent_id, metric, at`, since, agentID, metric)
	if err != nil {
		return nil, fmt.Errorf("list anomaly samples: %w", err)
	}
	defer rows.Close()
	var out []AnomalySample
	for rows.Next() {
		var x AnomalySample
		if err := rows.Scan(&x.AgentID, &x.Metric, &x.At, &x.Value); err != nil {
			return nil, fmt.Errorf("scan anomaly sample: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// AnomalyHour is one hourly rollup.
type AnomalyHour struct {
	Hour   time.Time `json:"hour"`
	Median float64   `json:"median"`
	Lo     float64   `json:"lo"`
	Hi     float64   `json:"hi"`
	N      int       `json:"n"`
}

// ListAnomalyHours returns one endpoint's hourly rollups for a metric from
// since onward, oldest first.
func (s *Store) ListAnomalyHours(ctx context.Context, agentID, metric string, since time.Time) ([]AnomalyHour, error) {
	rows, err := s.pool.Query(ctx, `
SELECT hour, median, lo, hi, n FROM anomaly_hourly
WHERE agent_id = $1 AND metric = $2 AND hour >= $3 ORDER BY hour`, agentID, metric, since)
	if err != nil {
		return nil, fmt.Errorf("list anomaly hours: %w", err)
	}
	defer rows.Close()
	out := []AnomalyHour{}
	for rows.Next() {
		var h AnomalyHour
		if err := rows.Scan(&h.Hour, &h.Median, &h.Lo, &h.Hi, &h.N); err != nil {
			return nil, fmt.Errorf("scan anomaly hour: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Anomaly is one recorded anomaly, with the endpoint it is on.
type Anomaly struct {
	ID             string     `json:"id"`
	AgentID        string     `json:"agent_id"`
	Hostname       string     `json:"hostname"`
	OS             string     `json:"os"`
	Metric         string     `json:"metric"`
	Direction      string     `json:"direction"` // high | low
	StartedAt      time.Time  `json:"started_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	NoData         bool       `json:"no_data"` // closed because the metric stopped arriving
	BaselineMedian float64    `json:"baseline_median"`
	BaselineMAD    float64    `json:"baseline_mad"`
	Value          float64    `json:"value"`
	PeakValue      float64    `json:"peak_value"`
	PeakZ          float64    `json:"peak_z"`
	Severity       string     `json:"severity"` // low | medium | high | critical
	Score          float64    `json:"score"`
	// Change is the deployment, patch run or agent update that finished
	// on the endpoint in the day before the anomaly began.
	Change         string     `json:"change"`
	ChangeAt       *time.Time `json:"change_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by"`
	AckNote        string     `json:"ack_note"`
}

const anomalyCols = `n.id, n.agent_id, a.hostname, a.os, n.metric, n.direction, n.started_at, n.last_seen_at, n.ended_at, n.no_data,
  n.baseline_median, n.baseline_mad, n.value, n.peak_value, n.peak_z, n.severity, n.score, n.change, n.change_at,
  n.acknowledged_at, n.acknowledged_by, n.ack_note`

func scanAnomaly(row pgx.Row) (Anomaly, error) {
	var x Anomaly
	err := row.Scan(&x.ID, &x.AgentID, &x.Hostname, &x.OS, &x.Metric, &x.Direction, &x.StartedAt, &x.LastSeenAt, &x.EndedAt, &x.NoData,
		&x.BaselineMedian, &x.BaselineMAD, &x.Value, &x.PeakValue, &x.PeakZ, &x.Severity, &x.Score, &x.Change, &x.ChangeAt,
		&x.AcknowledgedAt, &x.AcknowledgedBy, &x.AckNote)
	return x, err
}

// AnomalyFilter narrows ListAnomalies. State is "open" (the default),
// "closed" or "all"; closed and all cover the last 90 days.
type AnomalyFilter struct {
	State   string
	AgentID string
}

// ListAnomalies returns anomalies, newest first.
func (s *Store) ListAnomalies(ctx context.Context, f AnomalyFilter) ([]Anomaly, error) {
	where := "n.ended_at IS NULL"
	switch f.State {
	case "closed":
		where = "n.ended_at IS NOT NULL"
	case "all":
		where = "true"
	}
	rows, err := s.pool.Query(ctx, `
SELECT `+anomalyCols+`
FROM anomalies n JOIN agents a ON a.agent_id = n.agent_id
WHERE `+where+` AND ($1 = '' OR n.agent_id = $1)
ORDER BY n.started_at DESC
LIMIT 5000`, f.AgentID)
	if err != nil {
		return nil, fmt.Errorf("list anomalies: %w", err)
	}
	defer rows.Close()
	out := []Anomaly{}
	for rows.Next() {
		x, err := scanAnomaly(rows)
		if err != nil {
			return nil, fmt.Errorf("scan anomaly: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// GetAnomaly returns one anomaly, or nil.
func (s *Store) GetAnomaly(ctx context.Context, id string) (*Anomaly, error) {
	x, err := scanAnomaly(s.pool.QueryRow(ctx, `
SELECT `+anomalyCols+` FROM anomalies n JOIN agents a ON a.agent_id = n.agent_id WHERE n.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get anomaly: %w", err)
	}
	return &x, nil
}

// OpenAnomaly records a new anomaly. It does nothing (and reports false)
// when one is already open for the endpoint and metric.
func (s *Store) OpenAnomaly(ctx context.Context, x Anomaly) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
INSERT INTO anomalies (id, agent_id, metric, direction, started_at, last_seen_at, baseline_median, baseline_mad,
  value, peak_value, peak_z, severity, score, change, change_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (agent_id, metric) WHERE ended_at IS NULL DO NOTHING`,
		x.ID, x.AgentID, x.Metric, x.Direction, x.StartedAt, x.LastSeenAt, x.BaselineMedian, x.BaselineMAD,
		x.Value, x.PeakValue, x.PeakZ, x.Severity, x.Score, x.Change, x.ChangeAt)
	if err != nil {
		return false, fmt.Errorf("open anomaly: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// UpdateAnomaly refreshes an open anomaly's latest value, peak and
// severity.
func (s *Store) UpdateAnomaly(ctx context.Context, id string, lastSeen time.Time, value, peakValue, peakZ float64, severity string, score float64) error {
	_, err := s.pool.Exec(ctx, `
UPDATE anomalies SET last_seen_at = $2, value = $3, peak_value = $4, peak_z = $5, severity = $6, score = $7
WHERE id = $1 AND ended_at IS NULL`, id, lastSeen, value, peakValue, peakZ, severity, score)
	if err != nil {
		return fmt.Errorf("update anomaly: %w", err)
	}
	return nil
}

// CloseAnomaly ends an open anomaly at endedAt.
func (s *Store) CloseAnomaly(ctx context.Context, id string, endedAt time.Time, noData bool) error {
	_, err := s.pool.Exec(ctx, `
UPDATE anomalies SET ended_at = greatest($2, started_at), no_data = $3 WHERE id = $1 AND ended_at IS NULL`, id, endedAt, noData)
	if err != nil {
		return fmt.Errorf("close anomaly: %w", err)
	}
	return nil
}

// AcknowledgeAnomalies marks anomalies as looked at, and returns the ids
// it changed (an already acknowledged one keeps who acknowledged it
// first).
func (s *Store) AcknowledgeAnomalies(ctx context.Context, ids []string, who, note string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
UPDATE anomalies SET acknowledged_at = now(), acknowledged_by = $2, ack_note = $3
WHERE id = ANY($1) AND acknowledged_at IS NULL
RETURNING id`, ids, who, note)
	if err != nil {
		return nil, fmt.Errorf("acknowledge anomalies: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RecentChange is the newest change that finished on an endpoint between
// from and to: a succeeded deployment, patch run or action, or the agent
// moving to a new version. Empty when there was none.
func (s *Store) RecentChange(ctx context.Context, agentID string, from, to time.Time) (string, *time.Time, error) {
	var what string
	var at time.Time
	err := s.pool.QueryRow(ctx, `
SELECT what, at FROM (
  SELECT summary AS what, coalesce(finished_at, started_at) AS at
  FROM agent_actions
  WHERE agent_id = $1 AND status = 'succeeded' AND summary <> ''
    AND coalesce(finished_at, started_at) BETWEEN $2 AND $3
  UNION ALL
  SELECT 'Agent updated to ' || version, first_seen
  FROM agent_version_history
  WHERE agent_id = $1 AND first_seen BETWEEN $2 AND $3
    AND EXISTS (SELECT 1 FROM agent_version_history o WHERE o.agent_id = $1 AND o.first_seen < agent_version_history.first_seen)
) c ORDER BY at DESC LIMIT 1`, agentID, from, to).Scan(&what, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("recent change: %w", err)
	}
	return what, &at, nil
}

// AnomalyRetention is how long each tier is kept.
type AnomalyRetention struct {
	Samples, Hours, Boots, Closed, ExpiredSuppressions time.Duration
}

// PruneAnomalyData drops everything past its retention.
func (s *Store) PruneAnomalyData(ctx context.Context, now time.Time, keep AnomalyRetention) error {
	for _, q := range []struct {
		sql  string
		keep time.Duration
	}{
		{`DELETE FROM anomaly_samples WHERE at < $1`, keep.Samples},
		{`DELETE FROM anomaly_hourly WHERE hour < $1`, keep.Hours},
		// Not recomputed for as long as hours are kept: it has none left.
		{`DELETE FROM anomaly_baselines WHERE computed_at < $1`, keep.Hours},
		{`DELETE FROM anomaly_boots WHERE at < $1`, keep.Boots},
		{`DELETE FROM anomalies WHERE ended_at IS NOT NULL AND ended_at < $1`, keep.Closed},
		{`DELETE FROM anomaly_suppressions WHERE expires_at IS NOT NULL AND expires_at < $1`, keep.ExpiredSuppressions},
	} {
		if _, err := s.pool.Exec(ctx, q.sql, now.Add(-q.keep)); err != nil {
			return fmt.Errorf("prune anomaly data: %w", err)
		}
	}
	return nil
}

// AnomalySuppression hides one metric's anomalies on one computer group,
// or on every endpoint when GroupID is empty.
type AnomalySuppression struct {
	ID        string     `json:"id"`
	Metric    string     `json:"metric"`
	GroupID   string     `json:"group_id"`
	Reason    string     `json:"reason"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ListAnomalySuppressions returns every suppression, newest first,
// expired ones included until they are pruned.
func (s *Store) ListAnomalySuppressions(ctx context.Context) ([]AnomalySuppression, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, metric, group_id, reason, created_by, created_at, expires_at FROM anomaly_suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list anomaly suppressions: %w", err)
	}
	defer rows.Close()
	out := []AnomalySuppression{}
	for rows.Next() {
		var x AnomalySuppression
		if err := rows.Scan(&x.ID, &x.Metric, &x.GroupID, &x.Reason, &x.CreatedBy, &x.CreatedAt, &x.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan anomaly suppression: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// CreateAnomalySuppression stores a suppression.
func (s *Store) CreateAnomalySuppression(ctx context.Context, x AnomalySuppression) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO anomaly_suppressions (id, metric, group_id, reason, created_by, created_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)`, x.ID, x.Metric, x.GroupID, x.Reason, x.CreatedBy, x.CreatedAt, x.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create anomaly suppression: %w", err)
	}
	return nil
}

// DeleteAnomalySuppression removes a suppression and returns it, or nil
// when there was none.
func (s *Store) DeleteAnomalySuppression(ctx context.Context, id string) (*AnomalySuppression, error) {
	var x AnomalySuppression
	err := s.pool.QueryRow(ctx, `
DELETE FROM anomaly_suppressions WHERE id = $1
RETURNING id, metric, group_id, reason, created_by, created_at, expires_at`, id).
		Scan(&x.ID, &x.Metric, &x.GroupID, &x.Reason, &x.CreatedBy, &x.CreatedAt, &x.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("delete anomaly suppression: %w", err)
	}
	return &x, nil
}
