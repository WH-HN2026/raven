// Package auth implements local users (argon2id), server-side sessions, the
// RBAC map (rbac.go) and the HTTP middleware (middleware.go).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/audit"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

var ErrInvalidCredentials = errors.New("invalid username or password")

// User is the authenticated principal stored in the request context.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     Role   `json:"role"`
}

type Service struct {
	q   *gen.Queries
	ttl time.Duration
}

func NewService(q *gen.Queries, sessionTTL time.Duration) *Service {
	return &Service{q: q, ttl: sessionTTL}
}

// dummyHash is verified against when the user doesn't exist, so a login for an
// unknown user costs the same time as one with a wrong password.
var dummyHash, _ = HashPassword("dummy password for timing")

// Login checks the credentials, creates a session and returns its token. The
// token is only ever returned to the client; the DB stores its SHA-256.
func (s *Service) Login(ctx context.Context, username, password string) (string, User, error) {
	row, err := s.q.GetUserByUsername(ctx, username)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _ = VerifyPassword(dummyHash, password)
		_ = audit.Log(ctx, s.q, nil, "auth.login_failed", "user", "", map[string]string{"username": username})
		return "", User{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", User{}, fmt.Errorf("login %s: %w", username, err)
	}
	ok, err := VerifyPassword(row.PasswordHash, password)
	if err != nil {
		return "", User{}, fmt.Errorf("login %s: %w", username, err)
	}
	if !ok || row.Disabled {
		_ = audit.Log(ctx, s.q, nil, "auth.login_failed", "user", fmt.Sprint(row.ID), map[string]string{"username": username})
		return "", User{}, ErrInvalidCredentials
	}
	token, hash, err := newToken()
	if err != nil {
		return "", User{}, err
	}
	if err := s.q.CreateSession(ctx, gen.CreateSessionParams{
		TokenHash: hash, UserID: row.ID, ExpiresAt: time.Now().Add(s.ttl),
	}); err != nil {
		return "", User{}, fmt.Errorf("create session: %w", err)
	}
	if err := audit.Log(ctx, s.q, &row.ID, "auth.login", "user", fmt.Sprint(row.ID), nil); err != nil {
		return "", User{}, err
	}
	return token, toUser(row), nil
}

func (s *Service) Logout(ctx context.Context, token string, u User) error {
	if err := s.q.DeleteSession(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return audit.Log(ctx, s.q, &u.ID, "auth.logout", "user", fmt.Sprint(u.ID), nil)
}

// UserForToken returns the user owning a valid, unexpired session, or nil.
func (s *Service) UserForToken(ctx context.Context, token string) (*User, error) {
	row, err := s.q.GetSessionUser(ctx, hashToken(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("session lookup: %w", err)
	}
	u := toUser(row)
	return &u, nil
}

// EnsureBootstrapAdmin creates the admin from ASI_ADMIN_USERNAME/PASSWORD
// when no enabled admin exists yet (first start).
func (s *Service) EnsureBootstrapAdmin(ctx context.Context, username, password string) error {
	n, err := s.q.CountAdmins(ctx)
	if err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if n > 0 {
		return nil
	}
	if password == "" {
		return errors.New("no admin user exists and ASI_ADMIN_PASSWORD is empty")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	u, err := s.q.CreateUser(ctx, gen.CreateUserParams{Username: username, PasswordHash: hash, Role: string(RoleAdmin)})
	if err != nil {
		return fmt.Errorf("create bootstrap admin %s: %w", username, err)
	}
	slog.Info("bootstrap admin created", "username", username)
	return audit.Log(ctx, s.q, nil, "user.create", "user", fmt.Sprint(u.ID),
		map[string]string{"username": username, "role": string(RoleAdmin), "reason": "bootstrap"})
}

// CleanupSessions deletes expired sessions; called periodically from main.
func (s *Service) CleanupSessions(ctx context.Context) error {
	return s.q.DeleteExpiredSessions(ctx)
}

func toUser(r gen.User) User {
	return User{ID: r.ID, Username: r.Username, Role: Role(r.Role)}
}

func newToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("read token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
