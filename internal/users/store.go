package users

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

// User is the API view of a user. It never carries the password hash.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      auth.Role `json:"role"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

func fromRow(r gen.User) User {
	return User{ID: r.ID, Username: r.Username, Role: auth.Role(r.Role), Disabled: r.Disabled, CreatedAt: r.CreatedAt}
}

// Store is the DB side of user administration. Every mutation writes
// audit_log in the same transaction.
type Store struct {
	Pool *pgxpool.Pool
}

func (s *Store) tx(ctx context.Context, fn func(q *gen.Queries) error) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error { return fn(gen.New(tx)) })
}

// List returns one page of users (ordered by username) and the total count.
func (s *Store) List(ctx context.Context, limit, offset int32, order db.ListOrder) ([]User, int64, error) {
	q := gen.New(s.Pool)
	rows, err := q.ListUsers(ctx, gen.ListUsersParams{SortKey: order.Key(), Lim: limit, Off: offset})
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	total, err := q.CountUsers(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}
	out := make([]User, len(rows))
	for i, r := range rows {
		out[i] = User{ID: r.ID, Username: r.Username, Role: auth.Role(r.Role), Disabled: r.Disabled, CreatedAt: r.CreatedAt}
	}
	return out, total, nil
}

// Create adds a user after validating username, password policy and role.
func (s *Store) Create(ctx context.Context, actor *auth.User, username, password string, role auth.Role) (User, error) {
	if err := ValidateUsername(username); err != nil {
		return User{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	if err := validateRole(role); err != nil {
		return User{}, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	var out User
	err = s.tx(ctx, func(q *gen.Queries) error {
		row, err := q.CreateUser(ctx, gen.CreateUserParams{Username: username, PasswordHash: hash, Role: string(role)})
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("%w: %s", ErrConflict, username)
			}
			return fmt.Errorf("create user %s: %w", username, err)
		}
		out = fromRow(row)
		return audit.Log(ctx, q, &actor.ID, "user.create", "user", fmt.Sprint(row.ID),
			map[string]string{"username": username, "role": string(role)})
	})
	return out, err
}

// Update applies p to user id under the rules in planUpdate. Role change,
// disabling and password reset revoke all of the user's sessions.
func (s *Store) Update(ctx context.Context, actor *auth.User, id int64, p Patch) (User, error) {
	var out User
	err := s.tx(ctx, func(q *gen.Queries) error {
		admins, err := q.LockEnabledAdmins(ctx)
		if err != nil {
			return fmt.Errorf("lock admins: %w", err)
		}
		row, err := q.GetUserForUpdate(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get user %d: %w", id, err)
		}
		cur := state{Role: auth.Role(row.Role), Disabled: row.Disabled}
		next, revoke, err := planUpdate(actor.ID, id, cur, p, admins)
		if err != nil {
			return err
		}
		hash := row.PasswordHash
		if p.Password != nil {
			if hash, err = auth.HashPassword(*p.Password); err != nil {
				return err
			}
		}
		upd, err := q.UpdateUser(ctx, gen.UpdateUserParams{
			ID: id, Role: string(next.Role), Disabled: next.Disabled, PasswordHash: hash,
		})
		if err != nil {
			return fmt.Errorf("update user %d: %w", id, err)
		}
		if revoke {
			if err := q.DeleteUserSessions(ctx, id); err != nil {
				return fmt.Errorf("revoke sessions of user %d: %w", id, err)
			}
		}
		out = fromRow(upd)
		diff := map[string]any{"username": row.Username, "sessions_revoked": revoke}
		if next.Role != cur.Role {
			diff["role"] = map[string]auth.Role{"from": cur.Role, "to": next.Role}
		}
		if next.Disabled != cur.Disabled {
			diff["disabled"] = map[string]bool{"from": cur.Disabled, "to": next.Disabled}
		}
		if p.Password != nil {
			diff["password_reset"] = true
		}
		return audit.Log(ctx, q, &actor.ID, "user.update", "user", fmt.Sprint(id), diff)
	})
	return out, err
}

// Delete removes user id (its sessions cascade).
func (s *Store) Delete(ctx context.Context, actor *auth.User, id int64) error {
	return s.tx(ctx, func(q *gen.Queries) error {
		admins, err := q.LockEnabledAdmins(ctx)
		if err != nil {
			return fmt.Errorf("lock admins: %w", err)
		}
		row, err := q.GetUserForUpdate(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get user %d: %w", id, err)
		}
		if err := checkDelete(actor.ID, id, state{Role: auth.Role(row.Role), Disabled: row.Disabled}, admins); err != nil {
			return err
		}
		if err := q.DeleteUser(ctx, id); err != nil {
			return fmt.Errorf("delete user %d: %w", id, err)
		}
		return audit.Log(ctx, q, &actor.ID, "user.delete", "user", fmt.Sprint(id),
			map[string]string{"username": row.Username, "role": row.Role})
	})
}

// ErrWrongPassword: the current password given to ChangeOwnPassword is wrong.
var ErrWrongPassword = errors.New("current password is wrong")

// ChangeOwnPassword sets actor's password after checking the current one, and
// revokes the actor's other sessions (the one with currentToken stays).
func (s *Store) ChangeOwnPassword(ctx context.Context, actor *auth.User, currentToken, current, next string) error {
	if err := ValidatePassword(next); err != nil {
		return err
	}
	err := s.tx(ctx, func(q *gen.Queries) error {
		row, err := q.GetUserForUpdate(ctx, actor.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get user %d: %w", actor.ID, err)
		}
		ok, err := auth.VerifyPassword(row.PasswordHash, current)
		if err != nil {
			return fmt.Errorf("verify password of user %d: %w", actor.ID, err)
		}
		if !ok {
			return ErrWrongPassword
		}
		hash, err := auth.HashPassword(next)
		if err != nil {
			return err
		}
		if _, err := q.UpdateUser(ctx, gen.UpdateUserParams{
			ID: row.ID, Role: row.Role, Disabled: row.Disabled, PasswordHash: hash,
		}); err != nil {
			return fmt.Errorf("update password of user %d: %w", actor.ID, err)
		}
		if err := q.DeleteOtherUserSessions(ctx, gen.DeleteOtherUserSessionsParams{
			UserID: row.ID, TokenHash: auth.TokenHash(currentToken),
		}); err != nil {
			return fmt.Errorf("revoke other sessions of user %d: %w", actor.ID, err)
		}
		return audit.Log(ctx, q, &actor.ID, "user.password_change", "user", fmt.Sprint(actor.ID),
			map[string]any{"sessions_revoked": "others"})
	})
	if errors.Is(err, ErrWrongPassword) {
		// The transaction rolled back; record the failed attempt on its own.
		if aerr := audit.Log(ctx, gen.New(s.Pool), &actor.ID, "user.password_change_failed", "user", fmt.Sprint(actor.ID), nil); aerr != nil {
			return aerr
		}
	}
	return err
}
