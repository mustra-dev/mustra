package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// NetworkSurvey is one survey definition. SNMPSecretEnc is the vault-
// sealed community and passphrases; it never leaves the server except
// inside a run's command, and never in an API answer.
type NetworkSurvey struct {
	ID                string
	Name              string
	Enabled           bool
	AgentIDs          []string
	Subnets           []string
	AllowOffLink      bool
	Protocols         []string
	IntervalHours     int
	PacketsPerSecond  int
	Concurrency       int
	TimeoutMillis     int
	BudgetSeconds     int
	SNMPVersion       string
	SNMPUser          string
	SNMPSecurityLevel string
	SNMPAuthProtocol  string
	SNMPPrivProtocol  string
	SNMPSecretEnc     []byte
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastRunAt         *time.Time
}

const networkSurveyColumns = `id, name, enabled, agent_ids, subnets, allow_off_link, protocols, interval_hours,
	packets_per_second, concurrency, timeout_ms, budget_seconds, snmp_version, snmp_user, snmp_security_level,
	snmp_auth_protocol, snmp_priv_protocol, snmp_secret_enc, created_by, created_at, updated_at, last_run_at`

func scanNetworkSurvey(row pgx.Row) (NetworkSurvey, error) {
	var n NetworkSurvey
	err := row.Scan(&n.ID, &n.Name, &n.Enabled, &n.AgentIDs, &n.Subnets, &n.AllowOffLink, &n.Protocols, &n.IntervalHours,
		&n.PacketsPerSecond, &n.Concurrency, &n.TimeoutMillis, &n.BudgetSeconds, &n.SNMPVersion, &n.SNMPUser, &n.SNMPSecurityLevel,
		&n.SNMPAuthProtocol, &n.SNMPPrivProtocol, &n.SNMPSecretEnc, &n.CreatedBy, &n.CreatedAt, &n.UpdatedAt, &n.LastRunAt)
	return n, err
}

// SaveNetworkSurvey inserts or replaces a survey. created_by and
// created_at are kept from the first save.
func (s *Store) SaveNetworkSurvey(ctx context.Context, n NetworkSurvey) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO network_surveys (id, name, enabled, agent_ids, subnets, allow_off_link, protocols,
		interval_hours, packets_per_second, concurrency, timeout_ms, budget_seconds, snmp_version, snmp_user, snmp_security_level,
		snmp_auth_protocol, snmp_priv_protocol, snmp_secret_enc, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, enabled = EXCLUDED.enabled, agent_ids = EXCLUDED.agent_ids,
			subnets = EXCLUDED.subnets, allow_off_link = EXCLUDED.allow_off_link, protocols = EXCLUDED.protocols,
			interval_hours = EXCLUDED.interval_hours, packets_per_second = EXCLUDED.packets_per_second,
			concurrency = EXCLUDED.concurrency, timeout_ms = EXCLUDED.timeout_ms, budget_seconds = EXCLUDED.budget_seconds,
			snmp_version = EXCLUDED.snmp_version, snmp_user = EXCLUDED.snmp_user, snmp_security_level = EXCLUDED.snmp_security_level,
			snmp_auth_protocol = EXCLUDED.snmp_auth_protocol, snmp_priv_protocol = EXCLUDED.snmp_priv_protocol,
			snmp_secret_enc = EXCLUDED.snmp_secret_enc, updated_at = now()`,
		n.ID, n.Name, n.Enabled, nonNilStrings(n.AgentIDs), nonNilStrings(n.Subnets), n.AllowOffLink, nonNilStrings(n.Protocols),
		n.IntervalHours, n.PacketsPerSecond, n.Concurrency, n.TimeoutMillis, n.BudgetSeconds, n.SNMPVersion, n.SNMPUser,
		n.SNMPSecurityLevel, n.SNMPAuthProtocol, n.SNMPPrivProtocol, n.SNMPSecretEnc, n.CreatedBy)
	if err != nil {
		return fmt.Errorf("save network survey: %w", err)
	}
	return nil
}

// GetNetworkSurvey returns nil when there is no such survey.
func (s *Store) GetNetworkSurvey(ctx context.Context, id string) (*NetworkSurvey, error) {
	n, err := scanNetworkSurvey(s.pool.QueryRow(ctx, `SELECT `+networkSurveyColumns+` FROM network_surveys WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get network survey: %w", err)
	}
	return &n, nil
}

func (s *Store) ListNetworkSurveys(ctx context.Context) ([]NetworkSurvey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+networkSurveyColumns+` FROM network_surveys ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list network surveys: %w", err)
	}
	defer rows.Close()
	out := []NetworkSurvey{}
	for rows.Next() {
		n, err := scanNetworkSurvey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan network survey: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNetworkSurvey removes a survey and its runs; what it found stays
// in Discover. It reports false when there was no such survey.
func (s *Store) DeleteNetworkSurvey(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM network_surveys WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete network survey: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// MarkNetworkSurveyRun records that a survey was just dispatched.
func (s *Store) MarkNetworkSurveyRun(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_surveys SET last_run_at = now() WHERE id = $1`, id)
	return err
}

// NetworkSurveyRun is one endpoint's run of a survey.
type NetworkSurveyRun struct {
	ID            string          `json:"id"`
	SurveyID      string          `json:"survey_id"`
	AgentID       string          `json:"agent_id"`
	Status        string          `json:"status"`
	Detail        string          `json:"detail,omitempty"`
	RequestedBy   string          `json:"requested_by,omitempty"`
	Subnets       []string        `json:"subnets"`
	BudgetSeconds int             `json:"budget_seconds"`
	StartedAt     time.Time       `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	HostsPlanned  int             `json:"hosts_planned"`
	Probes        int             `json:"probes"`
	DevicesFound  int             `json:"devices_found"`
	Summary       json.RawMessage `json:"summary,omitempty"`
}

const networkSurveyRunColumns = `id, survey_id, agent_id, status, detail, requested_by, subnets, budget_seconds,
	started_at, finished_at, hosts_planned, probes, devices_found, summary`

func scanNetworkSurveyRun(row pgx.Row) (NetworkSurveyRun, error) {
	var r NetworkSurveyRun
	err := row.Scan(&r.ID, &r.SurveyID, &r.AgentID, &r.Status, &r.Detail, &r.RequestedBy, &r.Subnets, &r.BudgetSeconds,
		&r.StartedAt, &r.FinishedAt, &r.HostsPlanned, &r.Probes, &r.DevicesFound, &r.Summary)
	return r, err
}

func (s *Store) CreateNetworkSurveyRun(ctx context.Context, r NetworkSurveyRun) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO network_survey_runs (id, survey_id, agent_id, status, detail, requested_by, subnets, budget_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, r.ID, r.SurveyID, r.AgentID, r.Status, r.Detail, r.RequestedBy, nonNilStrings(r.Subnets), r.BudgetSeconds)
	if err != nil {
		return fmt.Errorf("create network survey run: %w", err)
	}
	return nil
}

// SetNetworkSurveyRunStatus moves a run that has not reported yet; a run
// whose report is in keeps its outcome. Terminal statuses set finished_at.
func (s *Store) SetNetworkSurveyRunStatus(ctx context.Context, id, status, detail string, terminal bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE network_survey_runs SET status = $2, detail = $3,
		finished_at = CASE WHEN $4 THEN now() ELSE finished_at END
		WHERE id = $1 AND status IN ('dispatched', 'running')`, id, status, detail, terminal)
	return err
}

func (s *Store) GetNetworkSurveyRun(ctx context.Context, id string) (*NetworkSurveyRun, error) {
	r, err := scanNetworkSurveyRun(s.pool.QueryRow(ctx, `SELECT `+networkSurveyRunColumns+` FROM network_survey_runs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get network survey run: %w", err)
	}
	return &r, nil
}

// ListNetworkSurveyRuns returns the newest runs, at most limit.
func (s *Store) ListNetworkSurveyRuns(ctx context.Context, limit int) ([]NetworkSurveyRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+networkSurveyRunColumns+` FROM network_survey_runs ORDER BY started_at DESC, id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list network survey runs: %w", err)
	}
	defer rows.Close()
	out := []NetworkSurveyRun{}
	for rows.Next() {
		r, err := scanNetworkSurveyRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan network survey run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SurveyRunActive reports whether a survey has a run still going.
func (s *Store) SurveyRunActive(ctx context.Context, surveyID string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM network_survey_runs WHERE survey_id = $1 AND status IN ('dispatched', 'running')`, surveyID).Scan(&n)
	return n > 0, err
}

// ExpireNetworkSurveyRuns closes runs whose report is overdue: the run's
// budget plus grace has passed with nothing heard.
func (s *Store) ExpireNetworkSurveyRuns(ctx context.Context, grace time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE network_survey_runs SET status = 'timed_out', finished_at = now(),
		detail = 'no report arrived within the run''s time budget'
		WHERE status IN ('dispatched', 'running')
		  AND started_at + make_interval(secs => budget_seconds + $1) < now()`, grace.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// NetworkSurveyDevice is one device a survey found, as stored.
type NetworkSurveyDevice struct {
	Key        string
	MAC        string
	IP         string
	DeviceType string
	Device     json.RawMessage
	AgentID    string
	SurveyID   string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// FinishNetworkSurveyRun records a run's report and what it found, in one
// transaction: the run is never shown finished without its devices.
func (s *Store) FinishNetworkSurveyRun(ctx context.Context, run NetworkSurveyRun, devices []NetworkSurveyDevice, seenAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // a no-op after Commit
	if run.Summary == nil {
		run.Summary = json.RawMessage(`{}`)
	}
	if _, err := tx.Exec(ctx, `UPDATE network_survey_runs SET status = $2, detail = $3, finished_at = now(),
		hosts_planned = $4, probes = $5, devices_found = $6, summary = $7 WHERE id = $1`,
		run.ID, run.Status, run.Detail, run.HostsPlanned, run.Probes, run.DevicesFound, run.Summary); err != nil {
		return fmt.Errorf("finish network survey run: %w", err)
	}
	for _, d := range devices {
		if d.MAC != "" && d.IP != "" {
			// The device was known by address until now; its MAC row
			// replaces that one, keeping the first sighting.
			var first *time.Time
			if err := tx.QueryRow(ctx, `DELETE FROM network_survey_devices WHERE key = $1 RETURNING first_seen`, "ip:"+d.IP).Scan(&first); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("record survey device: %w", err)
			}
			if first != nil {
				d.FirstSeen = *first
			}
		}
		if d.FirstSeen.IsZero() {
			d.FirstSeen = seenAt
		}
		if _, err := tx.Exec(ctx, `INSERT INTO network_survey_devices (key, mac, ip, device_type, device, agent_id, survey_id, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (key) DO UPDATE SET mac = EXCLUDED.mac, ip = EXCLUDED.ip, device_type = EXCLUDED.device_type,
				device = EXCLUDED.device, agent_id = EXCLUDED.agent_id, survey_id = EXCLUDED.survey_id,
				first_seen = LEAST(network_survey_devices.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(network_survey_devices.last_seen, EXCLUDED.last_seen)`,
			d.Key, d.MAC, d.IP, d.DeviceType, d.Device, d.AgentID, d.SurveyID, d.FirstSeen, seenAt); err != nil {
			return fmt.Errorf("record survey device: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListNetworkSurveyDevices(ctx context.Context) ([]NetworkSurveyDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, mac, ip, device_type, device, agent_id, survey_id, first_seen, last_seen
		FROM network_survey_devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("list survey devices: %w", err)
	}
	defer rows.Close()
	out := []NetworkSurveyDevice{}
	for rows.Next() {
		var d NetworkSurveyDevice
		if err := rows.Scan(&d.Key, &d.MAC, &d.IP, &d.DeviceType, &d.Device, &d.AgentID, &d.SurveyID, &d.FirstSeen, &d.LastSeen); err != nil {
			return nil, fmt.Errorf("scan survey device: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
