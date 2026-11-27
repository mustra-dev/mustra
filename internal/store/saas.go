package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/saasmon"
)

// SaaS experience monitoring: the app library, the measurements, and the
// packaged browser extension.

// SaaSApp is one app of the library.
type SaaSApp struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	// Builtin marks an app the server seeded; it can be edited and
	// deleted like any other.
	Builtin   bool      `json:"builtin" api:"readonly"`
	CreatedAt time.Time `json:"created_at" api:"readonly"`
	UpdatedAt time.Time `json:"updated_at" api:"readonly"`
}

// ErrSaaSAppNotFound is an app ID the library does not have.
var ErrSaaSAppNotFound = errors.New("no such app")

const saasAppColumns = `id, name, domains, builtin, created_at, updated_at`

func scanSaaSApp(row pgx.Row) (SaaSApp, error) {
	var a SaaSApp
	err := row.Scan(&a.ID, &a.Name, &a.Domains, &a.Builtin, &a.CreatedAt, &a.UpdatedAt)
	if a.Domains == nil {
		a.Domains = []string{}
	}
	return a, err
}

// ListSaaSApps returns the library by name.
func (s *Store) ListSaaSApps(ctx context.Context) ([]SaaSApp, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+saasAppColumns+` FROM saas_apps ORDER BY lower(name), id`)
	if err != nil {
		return nil, fmt.Errorf("list saas apps: %w", err)
	}
	defer rows.Close()
	out := []SaaSApp{}
	for rows.Next() {
		a, err := scanSaaSApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetSaaSApp returns one app, or ErrSaaSAppNotFound.
func (s *Store) GetSaaSApp(ctx context.Context, id string) (SaaSApp, error) {
	a, err := scanSaaSApp(s.pool.QueryRow(ctx, `SELECT `+saasAppColumns+` FROM saas_apps WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrSaaSAppNotFound
	}
	return a, err
}

// CreateSaaSApp adds an app. It fails if the ID is taken.
func (s *Store) CreateSaaSApp(ctx context.Context, a SaaSApp) (SaaSApp, error) {
	return scanSaaSApp(s.pool.QueryRow(ctx, `
INSERT INTO saas_apps (id, name, domains) VALUES ($1, $2, $3)
RETURNING `+saasAppColumns, a.ID, a.Name, a.Domains))
}

// UpdateSaaSApp replaces an app's name and domains.
func (s *Store) UpdateSaaSApp(ctx context.Context, a SaaSApp) (SaaSApp, error) {
	out, err := scanSaaSApp(s.pool.QueryRow(ctx, `
UPDATE saas_apps SET name = $2, domains = $3, updated_at = now() WHERE id = $1
RETURNING `+saasAppColumns, a.ID, a.Name, a.Domains))
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrSaaSAppNotFound
	}
	return out, err
}

// DeleteSaaSApp removes an app and its measurements: an app taken out of
// the library is no longer measured, and what was measured of it goes too.
func (s *Store) DeleteSaaSApp(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM saas_apps WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete saas app: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSaaSAppNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM saas_samples WHERE app_id = $1`, id); err != nil {
		return fmt.Errorf("delete saas samples: %w", err)
	}
	return tx.Commit(ctx)
}

func int32s(v []int) []int32 {
	out := make([]int32, len(v))
	for i, x := range v {
		out[i] = int32(x)
	}
	return out
}

// histSum is an element-wise sum of two equal-length int arrays.
const histSum = `ARRAY(SELECT coalesce(a, 0) + coalesce(b, 0) FROM unnest(saas_samples.%[1]s, EXCLUDED.%[1]s) WITH ORDINALITY AS t(a, b, i) ORDER BY i)`

var saasUpsert = `
INSERT INTO saas_samples (agent_id, app_id, browser, window_start, navigations, ttfb_hist, dcl_hist, load_hist,
                          nav_4xx, nav_5xx, nav_failed, requests, req_4xx, req_5xx, req_failed, js_errors)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (agent_id, app_id, browser, window_start) DO UPDATE SET
    navigations = saas_samples.navigations + EXCLUDED.navigations,
    ttfb_hist   = ` + fmt.Sprintf(histSum, "ttfb_hist") + `,
    dcl_hist    = ` + fmt.Sprintf(histSum, "dcl_hist") + `,
    load_hist   = ` + fmt.Sprintf(histSum, "load_hist") + `,
    nav_4xx     = saas_samples.nav_4xx + EXCLUDED.nav_4xx,
    nav_5xx     = saas_samples.nav_5xx + EXCLUDED.nav_5xx,
    nav_failed  = saas_samples.nav_failed + EXCLUDED.nav_failed,
    requests    = saas_samples.requests + EXCLUDED.requests,
    req_4xx     = saas_samples.req_4xx + EXCLUDED.req_4xx,
    req_5xx     = saas_samples.req_5xx + EXCLUDED.req_5xx,
    req_failed  = saas_samples.req_failed + EXCLUDED.req_failed,
    js_errors   = saas_samples.js_errors + EXCLUDED.js_errors`

// RecordSaaSBatch adds a batch of validated aggregates. A batch already
// recorded (a redelivery after the ack was lost) changes nothing; applied
// reports which it was.
func (s *Store) RecordSaaSBatch(ctx context.Context, agentID, batchID, extVersion string, aggs []proto.SaaSAggregate) (applied bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if batchID != "" {
		tag, err := tx.Exec(ctx, `INSERT INTO saas_batches (agent_id, batch_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, agentID, batchID)
		if err != nil {
			return false, fmt.Errorf("record saas batch: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return false, nil
		}
	}
	batch := &pgx.Batch{}
	for _, a := range aggs {
		batch.Queue(saasUpsert, agentID, a.App, a.Browser, a.WindowStart.UTC(), a.Navigations,
			int32s(a.TTFBHist), int32s(a.DCLHist), int32s(a.LoadHist),
			a.Nav4xx, a.Nav5xx, a.NavFailed, a.Requests, a.Req4xx, a.Req5xx, a.ReqFailed, a.JSErrors)
	}
	batch.Queue(`
INSERT INTO saas_endpoints (agent_id, extension_version, last_report_at) VALUES ($1, $2, now())
ON CONFLICT (agent_id) DO UPDATE SET
    extension_version = CASE WHEN EXCLUDED.extension_version <> '' THEN EXCLUDED.extension_version ELSE saas_endpoints.extension_version END,
    last_report_at = now()`, agentID, extVersion)
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return false, fmt.Errorf("record saas samples: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// SaaSGroupBy is what a rollup sums per.
type SaaSGroupBy string

const (
	SaaSByApp    SaaSGroupBy = "app"
	SaaSByAgent  SaaSGroupBy = "agent"
	SaaSByBucket SaaSGroupBy = "bucket"
)

// SaaSRollupQuery selects and groups samples.
type SaaSRollupQuery struct {
	Since, Until  time.Time
	AppID         string // "" = every app
	AgentID       string // "" = every endpoint
	GroupBy       SaaSGroupBy
	BucketSeconds int // for SaaSByBucket
}

// SaaSRollupRow is one group's sums.
type SaaSRollupRow struct {
	Key       string    // app ID or agent ID
	Bucket    time.Time // for SaaSByBucket
	Endpoints int
	Totals    saasmon.Totals
}

// SaaSRollup sums histograms and counters per group, in the database: the
// histograms are added element by element by unnesting them side by side.
func (s *Store) SaaSRollup(ctx context.Context, q SaaSRollupQuery) ([]SaaSRollupRow, error) {
	var key string
	switch q.GroupBy {
	case SaaSByApp:
		key = `s.app_id`
	case SaaSByAgent:
		key = `s.agent_id`
	case SaaSByBucket:
		if q.BucketSeconds < proto.SaaSWindowSeconds {
			q.BucketSeconds = proto.SaaSWindowSeconds
		}
		key = `''`
	default:
		return nil, fmt.Errorf("unknown grouping %q", q.GroupBy)
	}
	bucket := `to_timestamp(floor(extract(epoch FROM s.window_start) / $5) * $5)`
	sql := `
SELECT ` + key + `, ` + bucket + ` AS bucket, h.i,
       count(DISTINCT s.agent_id),
       coalesce(sum(s.navigations) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.nav_4xx) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.nav_5xx) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.nav_failed) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.requests) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.req_4xx) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.req_5xx) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.req_failed) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(s.js_errors) FILTER (WHERE h.i = 1), 0),
       coalesce(sum(h.t), 0), coalesce(sum(h.d), 0), coalesce(sum(h.l), 0)
  FROM saas_samples s
  JOIN saas_apps a ON a.id = s.app_id,
       unnest(s.ttfb_hist, s.dcl_hist, s.load_hist) WITH ORDINALITY AS h(t, d, l, i)
 WHERE s.window_start >= $1 AND s.window_start < $2
   AND ($3 = '' OR s.app_id = $3)
   AND ($4 = '' OR s.agent_id = $4)
 GROUP BY 1, 2, 3
 ORDER BY 1, 2, 3`
	bucketSeconds := q.BucketSeconds
	if q.GroupBy != SaaSByBucket {
		// One bucket covering the whole range.
		bucketSeconds = int(q.Until.Sub(time.Unix(0, 0)).Seconds()) + 1
	}
	rows, err := s.pool.Query(ctx, sql, q.Since, q.Until, q.AppID, q.AgentID, bucketSeconds)
	if err != nil {
		return nil, fmt.Errorf("saas rollup: %w", err)
	}
	defer rows.Close()
	var out []SaaSRollupRow
	index := map[string]int{}
	for rows.Next() {
		var (
			k                                        string
			b                                        time.Time
			i                                        int
			endpoints                                int
			nav, n4, n5, nf, req, r4, r5, rf, js, tt int64
			dd, ll                                   int64
		)
		if err := rows.Scan(&k, &b, &i, &endpoints, &nav, &n4, &n5, &nf, &req, &r4, &r5, &rf, &js, &tt, &dd, &ll); err != nil {
			return nil, err
		}
		id := k + "|" + b.UTC().Format(time.RFC3339)
		pos, ok := index[id]
		if !ok {
			pos = len(out)
			index[id] = pos
			row := SaaSRollupRow{Key: k, Endpoints: endpoints, Totals: saasmon.Totals{
				TTFBHist: make([]int64, proto.SaaSHistogramLen), DCLHist: make([]int64, proto.SaaSHistogramLen), LoadHist: make([]int64, proto.SaaSHistogramLen)}}
			if q.GroupBy == SaaSByBucket {
				row.Bucket = b.UTC()
			}
			out = append(out, row)
		}
		r := &out[pos]
		if i == 1 {
			r.Totals.Navigations, r.Totals.Nav4xx, r.Totals.Nav5xx, r.Totals.NavFailed = nav, n4, n5, nf
			r.Totals.Requests, r.Totals.Req4xx, r.Totals.Req5xx, r.Totals.ReqFailed, r.Totals.JSErrors = req, r4, r5, rf, js
		}
		if i >= 1 && i <= proto.SaaSHistogramLen {
			r.Totals.TTFBHist[i-1], r.Totals.DCLHist[i-1], r.Totals.LoadHist[i-1] = tt, dd, ll
		}
	}
	return out, rows.Err()
}

// SaaSEndpoint is one endpoint's extension as its last report described it.
type SaaSEndpoint struct {
	AgentID          string    `json:"agent_id"`
	ExtensionVersion string    `json:"extension_version"`
	LastReportAt     time.Time `json:"last_report_at"`
}

// ListSaaSEndpoints returns every endpoint that has reported.
func (s *Store) ListSaaSEndpoints(ctx context.Context) ([]SaaSEndpoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, extension_version, last_report_at FROM saas_endpoints ORDER BY agent_id`)
	if err != nil {
		return nil, fmt.Errorf("list saas endpoints: %w", err)
	}
	defer rows.Close()
	out := []SaaSEndpoint{}
	for rows.Next() {
		var e SaaSEndpoint
		if err := rows.Scan(&e.AgentID, &e.ExtensionVersion, &e.LastReportAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneSaaS deletes samples older than before, the batch IDs that only
// matter while a redelivery is possible, and endpoints silent since before.
func (s *Store) PruneSaaS(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM saas_samples WHERE window_start < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("prune saas samples: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM saas_batches WHERE received_at < $1`, before); err != nil {
		return 0, fmt.Errorf("prune saas batches: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM saas_endpoints WHERE last_report_at < $1`, before); err != nil {
		return 0, fmt.Errorf("prune saas endpoints: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SaaSExtension describes the uploaded extension package.
type SaaSExtension struct {
	ExtensionID string    `json:"extension_id"`
	Version     string    `json:"version"`
	Name        string    `json:"name"`
	SHA256      string    `json:"sha256"`
	Size        int       `json:"size"`
	UploadedAt  time.Time `json:"uploaded_at"`
	UploadedBy  string    `json:"uploaded_by"`
}

// PutSaaSExtension replaces the stored package.
func (s *Store) PutSaaSExtension(ctx context.Context, meta SaaSExtension, crx []byte) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO saas_extension (id, extension_id, version, name, sha256, crx, uploaded_at, uploaded_by)
VALUES (1, $1, $2, $3, $4, $5, now(), $6)
ON CONFLICT (id) DO UPDATE SET extension_id = EXCLUDED.extension_id, version = EXCLUDED.version, name = EXCLUDED.name,
    sha256 = EXCLUDED.sha256, crx = EXCLUDED.crx, uploaded_at = now(), uploaded_by = EXCLUDED.uploaded_by`,
		meta.ExtensionID, meta.Version, meta.Name, meta.SHA256, crx, meta.UploadedBy)
	if err != nil {
		return fmt.Errorf("store saas extension: %w", err)
	}
	return nil
}

// GetSaaSExtension returns the package's description, and its bytes when
// withData is set; nil when none was uploaded.
func (s *Store) GetSaaSExtension(ctx context.Context, withData bool) (*SaaSExtension, []byte, error) {
	var m SaaSExtension
	var crx []byte
	data := `NULL::bytea`
	if withData {
		data = `crx`
	}
	err := s.pool.QueryRow(ctx, `SELECT extension_id, version, name, sha256, length(crx), uploaded_at, uploaded_by, `+data+` FROM saas_extension WHERE id = 1`).
		Scan(&m.ExtensionID, &m.Version, &m.Name, &m.SHA256, &m.Size, &m.UploadedAt, &m.UploadedBy, &crx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get saas extension: %w", err)
	}
	return &m, crx, nil
}

// DeleteSaaSExtension removes the stored package.
func (s *Store) DeleteSaaSExtension(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM saas_extension WHERE id = 1`)
	return err
}
