package scheduler

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/audit"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

var (
	ErrInvalid  = errors.New("invalid input")
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type ConfigStore struct {
	Pool *pgxpool.Pool
}

func logConfigChange(ctx context.Context, q *gen.Queries, userID int64, action, object string, id int64, diff any) error {
	return audit.Log(ctx, q, &userID, action, object, strconv.FormatInt(id, 10), diff)
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
