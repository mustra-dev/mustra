package store

import (
	"context"
	"fmt"
	"time"
)

// Read-only summaries of one endpoint, over tables other modules own, for
// a triage item's page. Nothing here collects anything: each is what the
// module's own page would show for the endpoint, cut down.

// StateCount is a count of rows in one state.
type StateCount struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// EndpointFinding is one compliance check or Enforce setting not in its
// good state.
type EndpointFinding struct {
	Policy    string    `json:"policy"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	State     string    `json:"state"`
	CheckedAt time.Time `json:"checked_at"`
}

// EndpointComplianceSummary counts an endpoint's compliance results by
// state (pass, fail, unknown…) and lists its failures, worst first.
func (s *Store) EndpointComplianceSummary(ctx context.Context, agentID string, limit int) ([]StateCount, []EndpointFinding, error) {
	counts, err := s.stateCounts(ctx, `SELECT state, count(*) FROM compliance_results WHERE agent_id = $1 GROUP BY state ORDER BY state`, agentID)
	if err != nil {
		return nil, nil, fmt.Errorf("compliance summary: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT coalesce(p.name, r.policy_id), r.title, r.severity, r.state, r.checked_at
FROM compliance_results r LEFT JOIN compliance_policies p ON p.id = r.policy_id
WHERE r.agent_id = $1 AND r.state = 'fail'
ORDER BY CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, r.title LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("compliance failures: %w", err)
	}
	findings, err := scanFindings(rows)
	return counts, findings, err
}

// EndpointEnforceSummary counts an endpoint's Enforce settings by state
// (compliant, drifted, remediated, failed, failing, unknown) and lists
// those not compliant.
func (s *Store) EndpointEnforceSummary(ctx context.Context, agentID string, limit int) ([]StateCount, []EndpointFinding, error) {
	counts, err := s.stateCounts(ctx, `SELECT state, count(*) FROM enforce_results WHERE agent_id = $1 GROUP BY state ORDER BY state`, agentID)
	if err != nil {
		return nil, nil, fmt.Errorf("enforce summary: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT coalesce(p.name, r.policy_id), r.name, r.severity, r.state, r.checked_at
FROM enforce_results r LEFT JOIN enforce_policies p ON p.id = r.policy_id
WHERE r.agent_id = $1 AND r.state NOT IN ('compliant', 'remediated')
ORDER BY CASE r.state WHEN 'failing' THEN 0 WHEN 'failed' THEN 1 WHEN 'drifted' THEN 2 ELSE 3 END, r.name LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("enforce findings: %w", err)
	}
	findings, err := scanFindings(rows)
	return counts, findings, err
}

// EndpointVulnerabilityCounts counts an endpoint's vulnerability findings
// by severity.
func (s *Store) EndpointVulnerabilityCounts(ctx context.Context, agentID string) ([]StateCount, error) {
	c, err := s.stateCounts(ctx, `SELECT severity, count(*) FROM agent_vulnerabilities WHERE agent_id = $1 GROUP BY severity ORDER BY severity`, agentID)
	if err != nil {
		return nil, fmt.Errorf("vulnerability counts: %w", err)
	}
	return c, nil
}

// EndpointChange is one recent file or registry change on an endpoint.
type EndpointChange struct {
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	What       string    `json:"what,omitempty"`
	Expected   bool      `json:"expected"`
	Because    string    `json:"because,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
}

// RecentEndpointChanges lists an endpoint's integrity changes since a
// time, newest first.
func (s *Store) RecentEndpointChanges(ctx context.Context, agentID string, since time.Time, limit int) ([]EndpointChange, int, error) {
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM integrity_changes WHERE agent_id = $1 AND detected_at >= $2`, agentID, since).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count changes: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT path, kind, what, expected, because, detected_at FROM integrity_changes
WHERE agent_id = $1 AND detected_at >= $2 ORDER BY detected_at DESC LIMIT $3`, agentID, since, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("recent changes: %w", err)
	}
	defer rows.Close()
	out := []EndpointChange{}
	for rows.Next() {
		var c EndpointChange
		if err := rows.Scan(&c.Path, &c.Kind, &c.What, &c.Expected, &c.Because, &c.DetectedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// EndpointDeployment is one recent deploy job on an endpoint.
type EndpointDeployment struct {
	RunID     string    `json:"run_id"`
	PackageID string    `json:"package_id"`
	Package   string    `json:"package"`
	Operation string    `json:"operation"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RecentEndpointDeployments lists the latest deploy jobs on an endpoint.
func (s *Store) RecentEndpointDeployments(ctx context.Context, agentID string, limit int) ([]EndpointDeployment, error) {
	rows, err := s.pool.Query(ctx, `SELECT j.run_id, j.package_id, coalesce(p.name, j.package_id), coalesce(j.job->>'operation', ''),
	j.status, j.detail, j.created_at, j.updated_at
FROM deploy_jobs j LEFT JOIN software_packages p ON p.id = j.package_id
WHERE j.agent_id = $1 ORDER BY j.created_at DESC LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("recent deployments: %w", err)
	}
	defer rows.Close()
	out := []EndpointDeployment{}
	for rows.Next() {
		var d EndpointDeployment
		if err := rows.Scan(&d.RunID, &d.PackageID, &d.Package, &d.Operation, &d.Status, &d.Detail, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) stateCounts(ctx context.Context, q, agentID string) ([]StateCount, error) {
	rows, err := s.pool.Query(ctx, q, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StateCount{}
	for rows.Next() {
		var c StateCount
		if err := rows.Scan(&c.State, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type findingRows interface {
	Next() bool
	Scan(...any) error
	Close()
	Err() error
}

func scanFindings(rows findingRows) ([]EndpointFinding, error) {
	defer rows.Close()
	out := []EndpointFinding{}
	for rows.Next() {
		var f EndpointFinding
		if err := rows.Scan(&f.Policy, &f.Title, &f.Severity, &f.State, &f.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
