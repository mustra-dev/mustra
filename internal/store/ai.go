package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AIConnection is one model provider the console's assistant may use.
// APIKey is sealed by the server's vault and never leaves the server: the
// API says only whether one is set.
type AIConnection struct {
	ID        string    `json:"id" api:"readonly"`
	Name      string    `json:"name" api:"required"`
	Provider  string    `json:"provider" api:"required"` // anthropic | openai | azure_openai | gemini | openai_compatible
	BaseURL   string    `json:"base_url"`
	Model     string    `json:"model" api:"required"`
	APIKey    string    `json:"-"`
	MaxTokens int       `json:"max_tokens"`
	CreatedBy string    `json:"created_by" api:"readonly"`
	CreatedAt time.Time `json:"created_at" api:"readonly"`
	UpdatedAt time.Time `json:"updated_at" api:"readonly"`
}

const aiConnectionColumns = `id, name, provider, base_url, model, api_key, max_tokens, created_by, created_at, updated_at`

func scanAIConnection(row pgx.Row) (*AIConnection, error) {
	var c AIConnection
	if err := row.Scan(&c.ID, &c.Name, &c.Provider, &c.BaseURL, &c.Model, &c.APIKey, &c.MaxTokens,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) ListAIConnections(ctx context.Context) ([]AIConnection, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+aiConnectionColumns+` FROM ai_connections ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list ai connections: %w", err)
	}
	defer rows.Close()
	out := []AIConnection{}
	for rows.Next() {
		c, err := scanAIConnection(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ai connection: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetAIConnection returns nil when there is no such connection.
func (s *Store) GetAIConnection(ctx context.Context, id string) (*AIConnection, error) {
	c, err := scanAIConnection(s.pool.QueryRow(ctx, `SELECT `+aiConnectionColumns+` FROM ai_connections WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get ai connection: %w", err)
	}
	return c, nil
}

// UpsertAIConnection creates or replaces a connection; APIKey is stored
// as given (already sealed).
func (s *Store) UpsertAIConnection(ctx context.Context, c AIConnection) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO ai_connections (id, name, provider, base_url, model, api_key, max_tokens, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, provider = EXCLUDED.provider, base_url = EXCLUDED.base_url,
  model = EXCLUDED.model, api_key = EXCLUDED.api_key, max_tokens = EXCLUDED.max_tokens, updated_at = now()`,
		c.ID, c.Name, c.Provider, c.BaseURL, c.Model, c.APIKey, c.MaxTokens, c.CreatedBy)
	if err != nil {
		return fmt.Errorf("save ai connection: %w", err)
	}
	return nil
}

// DeleteAIConnection reports whether a connection was deleted.
func (s *Store) DeleteAIConnection(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ai_connections WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete ai connection: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
