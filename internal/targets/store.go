package targets

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/audit"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
	ErrConflict  = errors.New("already exists")
	ErrInvalid   = errors.New("invalid input")
)

// Store is the DB side of targets and scope. Every mutation writes audit_log
// in the same transaction. The HTTP handlers and the MCP server call it.
type Store struct {
	Pool *pgxpool.Pool
}

func (s *Store) tx(ctx context.Context, fn func(q *gen.Queries) error) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error { return fn(gen.New(tx)) })
}

func userID(u *auth.User) *int64 {
	if u == nil {
		return nil
	}
	return &u.ID
}

// ListTargets returns one page of targets and the total count.
func (s *Store) ListTargets(ctx context.Context, limit, offset int32) ([]gen.Target, int64, error) {
	q := gen.New(s.Pool)
	items, err := q.ListTargets(ctx, gen.ListTargetsParams{Limit: limit, Offset: offset})
	if err != nil {
		return nil, 0, fmt.Errorf("list targets: %w", err)
	}
	total, err := q.CountTargets(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count targets: %w", err)
	}
	return items, total, nil
}

// AddTargets upserts entries (re-adding merges tags) with the given source
// (manual|csv|json) and writes one audit row.
func (s *Store) AddTargets(ctx context.Context, u *auth.User, source string, entries []Entry) ([]gen.Target, error) {
	out := make([]gen.Target, 0, len(entries))
	err := s.tx(ctx, func(q *gen.Queries) error {
		values := make([]string, 0, len(entries))
		for _, e := range entries {
			t, err := q.UpsertTarget(ctx, gen.UpsertTargetParams{
				Kind: string(e.Kind), Value: e.Value, Source: source, Tags: cleanTags(e.Tags), Note: e.Note, CreatedBy: userID(u),
			})
			if err != nil {
				return fmt.Errorf("add target %s: %w", e.Value, err)
			}
			out = append(out, t)
			values = append(values, e.Value)
		}
		return audit.Log(ctx, q, userID(u), "targets.add", "target", "", map[string]any{"source": source, "values": values})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteTarget removes a target.
func (s *Store) DeleteTarget(ctx context.Context, u *auth.User, id int64) error {
	return s.tx(ctx, func(q *gen.Queries) error {
		t, err := q.DeleteTarget(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("delete target %d: %w", id, err)
		}
		return audit.Log(ctx, q, userID(u), "targets.delete", "target", strconv.FormatInt(id, 10),
			map[string]any{"kind": t.Kind, "value": t.Value})
	})
}

// ListScope returns one page of the entries of a profile (nil = global).
func (s *Store) ListScope(ctx context.Context, profileID *int64, limit, offset int32) ([]gen.ScopeEntry, int64, error) {
	q := gen.New(s.Pool)
	items, err := q.ListScopeEntries(ctx, gen.ListScopeEntriesParams{ProfileID: profileID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, 0, fmt.Errorf("list scope: %w", err)
	}
	total, err := q.CountScopeEntries(ctx, profileID)
	if err != nil {
		return nil, 0, fmt.Errorf("count scope: %w", err)
	}
	return items, total, nil
}

// ScopeInput is a new scope entry. Kind may be empty (auto-detected).
type ScopeInput struct {
	Kind      Kind   `json:"kind"`
	Value     string `json:"value"`
	List      string `json:"list"`
	ProfileID *int64 `json:"profile_id"`
	Note      string `json:"note"`
}

// canEdit: global entries (the blacklist) need scope:global on top of
// scope:write, which the route already checked.
func canEdit(u *auth.User, profileID *int64) bool {
	return profileID != nil || (u != nil && auth.Can(u.Role, auth.PermGlobalScope))
}

// AddScopeEntry validates and stores a scope entry. Unlike targets, scope
// CIDRs have no size cap (excluding a /8 is fine).
func (s *Store) AddScopeEntry(ctx context.Context, u *auth.User, in ScopeInput) (gen.ScopeEntry, error) {
	if !canEdit(u, in.ProfileID) {
		return gen.ScopeEntry{}, fmt.Errorf("%w: global scope entries need %s", ErrForbidden, auth.PermGlobalScope)
	}
	if in.List != "include" && in.List != "exclude" {
		return gen.ScopeEntry{}, fmt.Errorf("%w: list must be include or exclude", ErrInvalid)
	}
	k, v, err := Classify(in.Value)
	if err != nil {
		return gen.ScopeEntry{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if in.Kind != "" && in.Kind != k {
		return gen.ScopeEntry{}, fmt.Errorf("%w: %q is a %s, not a %s", ErrInvalid, in.Value, k, in.Kind)
	}
	var e gen.ScopeEntry
	err = s.tx(ctx, func(q *gen.Queries) error {
		e, err = q.InsertScopeEntry(ctx, gen.InsertScopeEntryParams{
			Kind: string(k), Value: v, List: in.List, ProfileID: in.ProfileID, Note: in.Note, CreatedBy: userID(u),
		})
		var pe *pgconn.PgError
		switch {
		case errors.As(err, &pe) && pe.Code == "23505":
			return fmt.Errorf("%w: %s %s is already in this list", ErrConflict, k, v)
		case errors.As(err, &pe) && pe.Code == "23503":
			return fmt.Errorf("%w: profile %d does not exist", ErrInvalid, *in.ProfileID)
		case err != nil:
			return fmt.Errorf("add scope entry: %w", err)
		}
		return audit.Log(ctx, q, userID(u), "scope.add", "scope_entry", strconv.FormatInt(e.ID, 10),
			map[string]any{"kind": e.Kind, "value": e.Value, "list": e.List, "profile_id": e.ProfileID})
	})
	return e, err
}

// DeleteScopeEntry removes an entry; global ones need scope:global.
func (s *Store) DeleteScopeEntry(ctx context.Context, u *auth.User, id int64) error {
	return s.tx(ctx, func(q *gen.Queries) error {
		e, err := q.GetScopeEntry(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get scope entry %d: %w", id, err)
		}
		if !canEdit(u, e.ProfileID) {
			return fmt.Errorf("%w: global scope entries need %s", ErrForbidden, auth.PermGlobalScope)
		}
		if err := q.DeleteScopeEntry(ctx, id); err != nil {
			return fmt.Errorf("delete scope entry %d: %w", id, err)
		}
		return audit.Log(ctx, q, userID(u), "scope.delete", "scope_entry", strconv.FormatInt(id, 10),
			map[string]any{"kind": e.Kind, "value": e.Value, "list": e.List, "profile_id": e.ProfileID})
	})
}

// LoadScanInput reads all targets and the effective scope of a profile
// (global entries + the profile's own) for Expand.
func (s *Store) LoadScanInput(ctx context.Context, profileID int64) ([]Entry, Scope, error) {
	q := gen.New(s.Pool)
	ts, err := q.ListAllTargets(ctx)
	if err != nil {
		return nil, Scope{}, fmt.Errorf("load targets: %w", err)
	}
	entries := make([]Entry, 0, len(ts))
	for _, t := range ts {
		entries = append(entries, Entry{Kind: Kind(t.Kind), Value: t.Value, Tags: t.Tags, Note: t.Note})
	}
	rules, err := q.ListEffectiveScope(ctx, &profileID)
	if err != nil {
		return nil, Scope{}, fmt.Errorf("load scope: %w", err)
	}
	var sc Scope
	for _, r := range rules {
		rule := Rule{Kind: Kind(r.Kind), Value: r.Value}
		if r.List == "include" {
			sc.Include = append(sc.Include, rule)
		} else {
			sc.Exclude = append(sc.Exclude, rule)
		}
	}
	return entries, sc, nil
}

// ScanList loads the profile's input and expands it (what S3 calls).
func (s *Store) ScanList(ctx context.Context, profileID int64, r Resolver, lim Limits) (*ScanList, error) {
	ts, sc, err := s.LoadScanInput(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return Expand(ctx, ts, sc, r, lim)
}
