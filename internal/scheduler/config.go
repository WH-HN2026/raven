package scheduler

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

var (
	ErrInvalid   = errors.New("invalid input")
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	ErrForbidden = errors.New("forbidden")
)

type ConfigStore struct {
	Pool           *pgxpool.Pool
	ValidateStages func([]string) ([]string, error)
	DefaultStages  func() []string
	IsAggressive   func([]string) bool
}

func (s ConfigStore) isAggressive(stages []string) bool {
	if s.IsAggressive == nil {
		return false
	}
	return s.IsAggressive(stages)
}

func canAggressive(u *auth.User) bool {
	return u != nil && auth.Can(u.Role, auth.PermScanAggressive)
}

func userIDPtr(u *auth.User) *int64 {
	if u == nil {
		return nil
	}
	return &u.ID
}

func logConfigChange(ctx context.Context, q *gen.Queries, u *auth.User, action, object string, id int64, diff any) error {
	return audit.Log(ctx, q, userIDPtr(u), action, object, strconv.FormatInt(id, 10), diff)
}

func dbCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

func defaultTo[T any](value *T, fallback T) T {
	if value == nil {
		return fallback
	}
	return *value
}

func (s ConfigStore) write(ctx context.Context, fn func(*gen.Queries) error) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		return fn(gen.New(tx))
	})
}
