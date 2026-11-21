package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// APITokenLookup resolves a bearer API token to its enabled user (nil if invalid).
type APITokenLookup interface {
	UserForAPIToken(ctx context.Context, token string) (*User, error)
}

// NewAPIToken generates a random bearer API token and its SHA-256 hash.
// The plaintext token is returned once to the caller; only the hash is stored.
func NewAPIToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("read api token: %w", err)
	}
	token = "rvn_" + base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

// UserForAPIToken returns the enabled user owning a valid API token, or nil,
// and updates api_tokens.last_used_at. Plaintext tokens are never logged.
func (s *Service) UserForAPIToken(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, nil
	}
	if s == nil || s.q == nil {
		return nil, errors.New("auth service unavailable")
	}
	row, err := s.q.GetAPITokenUser(ctx, hashToken(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("api token lookup: %w", err)
	}
	if err := s.q.TouchAPIToken(ctx, row.TokenID); err != nil {
		return nil, fmt.Errorf("touch api token %d: %w", row.TokenID, err)
	}
	u := User{ID: row.ID, Username: row.Username, Role: Role(row.Role)}
	return &u, nil
}
