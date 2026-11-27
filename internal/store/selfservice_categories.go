package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SelfServiceCategory is one section the Self Service window files its
// catalog under. A package names the categories it belongs to in
// SoftwarePackage.CategoryIDs; the list's order is Position.
type SelfServiceCategory struct {
	ID string `json:"id" api:"readonly"`
	// Name is what the window shows. Unique, ignoring case.
	Name string `json:"name" api:"required"`
	// Icon is a name from the console's line-icon set, or empty for none.
	Icon string `json:"icon"`
	// Position orders the list, lowest first.
	Position int `json:"position" api:"readonly"`
	// PackageCount is how many packages are filed under it, offered in
	// Self Service or not.
	PackageCount int       `json:"package_count" api:"readonly"`
	CreatedAt    time.Time `json:"created_at" api:"readonly"`
	UpdatedAt    time.Time `json:"updated_at" api:"readonly"`
	CreatedBy    string    `json:"created_by" api:"readonly"`
	UpdatedBy    string    `json:"updated_by" api:"readonly"`
}

// ErrCategoryNameTaken is a create or rename to a name another category
// already has, ignoring case. Two "Browsers" in the window's sidebar would
// be indistinguishable to the person choosing between them.
var ErrCategoryNameTaken = errors.New("a category with that name already exists")

const selfServiceCategoryColumns = `c.id, c.name, c.icon, c.position,
       (SELECT count(*) FROM software_packages p WHERE c.id = ANY(p.category_ids)),
       c.created_at, c.updated_at, c.created_by, c.updated_by`

func scanSelfServiceCategory(row pgx.Row) (*SelfServiceCategory, error) {
	var c SelfServiceCategory
	if err := row.Scan(&c.ID, &c.Name, &c.Icon, &c.Position, &c.PackageCount,
		&c.CreatedAt, &c.UpdatedAt, &c.CreatedBy, &c.UpdatedBy); err != nil {
		return nil, err
	}
	return &c, nil
}

func categoryNameErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrCategoryNameTaken
	}
	return err
}

// ListSelfServiceCategories returns every category in display order.
func (s *Store) ListSelfServiceCategories(ctx context.Context) ([]SelfServiceCategory, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+selfServiceCategoryColumns+`
FROM selfservice_categories c ORDER BY c.position, lower(c.name)`)
	if err != nil {
		return nil, fmt.Errorf("list self service categories: %w", err)
	}
	defer rows.Close()
	out := []SelfServiceCategory{}
	for rows.Next() {
		c, err := scanSelfServiceCategory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan self service category: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetSelfServiceCategory returns one category, or nil when there is none.
func (s *Store) GetSelfServiceCategory(ctx context.Context, id string) (*SelfServiceCategory, error) {
	c, err := scanSelfServiceCategory(s.pool.QueryRow(ctx, `SELECT `+selfServiceCategoryColumns+`
FROM selfservice_categories c WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get self service category: %w", err)
	}
	return c, nil
}

// CreateSelfServiceCategory adds a category at the end of the list.
func (s *Store) CreateSelfServiceCategory(ctx context.Context, c SelfServiceCategory) (*SelfServiceCategory, error) {
	if _, err := s.pool.Exec(ctx, `
INSERT INTO selfservice_categories (id, name, icon, position, created_by, updated_by)
VALUES ($1, $2, $3, (SELECT coalesce(max(position), 0) + 1 FROM selfservice_categories), $4, $4)`,
		c.ID, c.Name, c.Icon, c.CreatedBy); err != nil {
		return nil, fmt.Errorf("create self service category: %w", categoryNameErr(err))
	}
	return s.GetSelfServiceCategory(ctx, c.ID)
}

// UpdateSelfServiceCategory renames a category or changes its icon. Its
// place in the list moves only through ReorderSelfServiceCategories. Nil
// means there is no such category.
func (s *Store) UpdateSelfServiceCategory(ctx context.Context, c SelfServiceCategory) (*SelfServiceCategory, error) {
	tag, err := s.pool.Exec(ctx, `
UPDATE selfservice_categories SET name = $2, icon = $3, updated_by = $4, updated_at = now()
 WHERE id = $1`, c.ID, c.Name, c.Icon, c.UpdatedBy)
	if err != nil {
		return nil, fmt.Errorf("update self service category: %w", categoryNameErr(err))
	}
	if tag.RowsAffected() == 0 {
		return nil, nil
	}
	return s.GetSelfServiceCategory(ctx, c.ID)
}

// DeleteSelfServiceCategory removes a category and takes it off every
// package filed under it, in one transaction, so no package is left
// pointing at a category that is gone. False means there was none.
func (s *Store) DeleteSelfServiceCategory(ctx context.Context, id string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM selfservice_categories WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete self service category: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE software_packages SET category_ids = array_remove(category_ids, $1)
 WHERE $1 = ANY(category_ids)`, id); err != nil {
		return false, fmt.Errorf("unfile packages from category: %w", err)
	}
	return true, tx.Commit(ctx)
}

// ReorderSelfServiceCategories sets the display order to ids, first to
// last. A category ids leaves out keeps its position number, so callers
// pass the whole list.
func (s *Store) ReorderSelfServiceCategories(ctx context.Context, ids []string, by string) error {
	if _, err := s.pool.Exec(ctx, `
UPDATE selfservice_categories SET position = array_position($1::text[], id), updated_by = $2, updated_at = now()
 WHERE id = ANY($1::text[])`, ids, by); err != nil {
		return fmt.Errorf("reorder self service categories: %w", err)
	}
	return nil
}
