package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RemediationImport records that a remediation gallery entry was imported:
// at which gallery version, and the action package and playbook it became.
// PackageID or PlaybookID is empty once that object has been deleted.
type RemediationImport struct {
	GalleryID  string    `json:"gallery_id"`
	Version    int       `json:"version"`
	PackageID  string    `json:"package_id,omitempty"`
	PlaybookID string    `json:"playbook_id,omitempty"`
	ImportedBy string    `json:"imported_by"`
	ImportedAt time.Time `json:"imported_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

const remediationImportColumns = `gallery_id, version, coalesce(package_id,''), coalesce(playbook_id,''), imported_by, imported_at, updated_at`

func scanRemediationImport(scan func(dest ...any) error) (RemediationImport, error) {
	var r RemediationImport
	err := scan(&r.GalleryID, &r.Version, &r.PackageID, &r.PlaybookID, &r.ImportedBy, &r.ImportedAt, &r.UpdatedAt)
	return r, err
}

func (s *Store) ListRemediationImports(ctx context.Context) ([]RemediationImport, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+remediationImportColumns+` FROM remediation_imports ORDER BY gallery_id`)
	if err != nil {
		return nil, fmt.Errorf("list remediation imports: %w", err)
	}
	defer rows.Close()
	out := []RemediationImport{}
	for rows.Next() {
		r, err := scanRemediationImport(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan remediation import: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRemediationImport reports nil, nil when the entry was never imported.
func (s *Store) GetRemediationImport(ctx context.Context, galleryID string) (*RemediationImport, error) {
	r, err := scanRemediationImport(s.pool.QueryRow(ctx,
		`SELECT `+remediationImportColumns+` FROM remediation_imports WHERE gallery_id = $1`, galleryID).Scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get remediation import: %w", err)
	}
	return &r, nil
}

// SaveRemediationImport records the current state of an import. The
// importer and import time stay those of the first import.
func (s *Store) SaveRemediationImport(ctx context.Context, r RemediationImport) error {
	var pkg, pb *string
	if r.PackageID != "" {
		pkg = &r.PackageID
	}
	if r.PlaybookID != "" {
		pb = &r.PlaybookID
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO remediation_imports (gallery_id, version, package_id, playbook_id, imported_by)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (gallery_id) DO UPDATE SET
  version = EXCLUDED.version, package_id = EXCLUDED.package_id,
  playbook_id = EXCLUDED.playbook_id, updated_at = now()`,
		r.GalleryID, r.Version, pkg, pb, r.ImportedBy)
	if err != nil {
		return fmt.Errorf("save remediation import: %w", err)
	}
	return nil
}

// WithAdvisoryLock runs fn while holding a Postgres session advisory lock
// on key, so two servers (or two requests) doing the same read-then-write
// take turns instead of both writing.
func (s *Store) WithAdvisoryLock(ctx context.Context, key string, fn func() error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext($1))`, key); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	// Unlocked on a fresh context: a cancelled request must still release
	// the lock, or the pooled connection keeps it.
	defer func() {
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, key); err != nil {
			// The connection is in an unknown state; do not return it to
			// the pool still holding the lock.
			conn.Conn().Close(context.Background())
		}
	}()
	return fn()
}
