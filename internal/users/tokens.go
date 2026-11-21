package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

// APIToken is the metadata view of an API token. It never carries the token or its hash.
type APIToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Username   string     `json:"username"`
	Role       auth.Role  `json:"role"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// CreatedAPIToken is returned once when an API token is issued.
type CreatedAPIToken struct {
	APIToken
	Token string `json:"token"`
}

// ListAPITokens returns one page of API tokens (metadata only) and the total count.
func (s *Store) ListAPITokens(ctx context.Context, limit, offset int32) ([]APIToken, int64, error) {
	q := gen.New(s.Pool)
	rows, err := q.ListAPITokens(ctx, gen.ListAPITokensParams{Lim: limit, Off: offset})
	if err != nil {
		return nil, 0, fmt.Errorf("list api tokens: %w", err)
	}
	total, err := q.CountAPITokens(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count api tokens: %w", err)
	}
	out := make([]APIToken, len(rows))
	for i, r := range rows {
		out[i] = APIToken{
			ID:         r.ID,
			UserID:     r.UserID,
			Username:   r.Username,
			Role:       auth.Role(r.Role),
			Name:       r.Name,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
		}
	}
	return out, total, nil
}

// CreateAPIToken issues a new bearer API token for userID (defaulting to actor.ID),
// stores only its SHA-256 hash, writes audit_log (without the token), and returns
// the plaintext token once.
func (s *Store) CreateAPIToken(ctx context.Context, actor *auth.User, name string, userID *int64) (CreatedAPIToken, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 {
		return CreatedAPIToken{}, fmt.Errorf("%w: name must be 1..100 characters", ErrInvalid)
	}
	targetID := actor.ID
	if userID != nil {
		if *userID <= 0 {
			return CreatedAPIToken{}, fmt.Errorf("%w: user_id must be a positive integer", ErrInvalid)
		}
		targetID = *userID
	}
	raw, hash, err := auth.NewAPIToken()
	if err != nil {
		return CreatedAPIToken{}, err
	}
	var out CreatedAPIToken
	err = s.tx(ctx, func(q *gen.Queries) error {
		u, err := q.GetUser(ctx, targetID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: user %d", ErrNotFound, targetID)
		}
		if err != nil {
			return fmt.Errorf("get user %d: %w", targetID, err)
		}
		row, err := q.CreateAPIToken(ctx, gen.CreateAPITokenParams{
			UserID:    u.ID,
			TokenHash: hash,
			Name:      name,
		})
		if err != nil {
			return fmt.Errorf("create api token: %w", err)
		}
		out = CreatedAPIToken{
			APIToken: APIToken{
				ID:         row.ID,
				UserID:     row.UserID,
				Username:   u.Username,
				Role:       auth.Role(u.Role),
				Name:       row.Name,
				CreatedAt:  row.CreatedAt,
				LastUsedAt: row.LastUsedAt,
			},
			Token: raw,
		}
		return audit.Log(ctx, q, &actor.ID, "token.create", "api_token", fmt.Sprint(row.ID),
			map[string]any{"name": name, "user_id": u.ID, "username": u.Username, "role": u.Role})
	})
	return out, err
}

// RevokeAPIToken deletes an API token and records the revocation in audit_log.
func (s *Store) RevokeAPIToken(ctx context.Context, actor *auth.User, id int64) error {
	return s.tx(ctx, func(q *gen.Queries) error {
		row, err := q.DeleteAPIToken(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("revoke api token %d: %w", id, err)
		}
		return audit.Log(ctx, q, &actor.ID, "token.revoke", "api_token", fmt.Sprint(id),
			map[string]any{"name": row.Name, "user_id": row.UserID})
	})
}
