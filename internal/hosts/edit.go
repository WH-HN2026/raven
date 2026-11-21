package hosts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/audit"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dojo"
)

// User edits (task D6). They write only user-owned columns (owner,
// criticality, notes_enc, user_tags) and services.overrides, never the
// scan-owned ones (architecture §5).

var (
	// ErrInvalid wraps a rejected edit.
	ErrInvalid = errors.New("invalid edit")
	// ErrServiceNotFound: no service with that id.
	ErrServiceNotFound = errors.New("service not found")
)

// Criticalities are the allowed hosts.criticality values ("" = unset).
var Criticalities = []string{"", "low", "medium", "high", "critical"}

const (
	maxOwnerLen    = 200
	maxNotesLen    = 20000
	maxUserTags    = 50
	maxUserTagLen  = 64
	maxOverrideLen = 200
)

var userTagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*$`)

// Patch edits a host's user-owned fields (nil = unchanged).
type Patch struct {
	Owner       *string   `json:"owner"`
	Criticality *string   `json:"criticality"`
	Notes       *string   `json:"notes"`
	UserTags    *[]string `json:"user_tags"`
}

// Dojo write-through outcome of a host edit (EditResult.DojoSync).
const (
	DojoSynced  = "synced"  // the asset was updated
	DojoPending = "pending" // no asset yet, or Dojo not ready: not written
	DojoFailed  = "failed"  // Dojo answered with an error (logged)
)

// EditResult is the edited host plus the Dojo write-through outcome.
type EditResult struct {
	*Detail
	DojoSync string `json:"dojo_sync"`
}

// NormalizeUserTags lowercases, trims, validates, dedupes and sorts tags.
func NormalizeUserTags(tags []string) ([]string, error) {
	out := []string{}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if len(t) > maxUserTagLen || !userTagRe.MatchString(t) {
			return nil, fmt.Errorf("%w: tag %q: use a-z, 0-9 and . _ / - (max %d chars)", ErrInvalid, t, maxUserTagLen)
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if len(out) > maxUserTags {
		return nil, fmt.Errorf("%w: at most %d tags", ErrInvalid, maxUserTags)
	}
	slices.Sort(out)
	return out, nil
}

// normalize validates p and returns it with trimmed/normalized values.
func (p Patch) normalize() (Patch, error) {
	if p.Owner == nil && p.Criticality == nil && p.Notes == nil && p.UserTags == nil {
		return p, fmt.Errorf("%w: nothing to change", ErrInvalid)
	}
	if p.Owner != nil {
		o := strings.TrimSpace(*p.Owner)
		if utf8.RuneCountInString(o) > maxOwnerLen || strings.ContainsAny(o, "\r\n") {
			return p, fmt.Errorf("%w: owner must be one line of at most %d characters", ErrInvalid, maxOwnerLen)
		}
		p.Owner = &o
	}
	if p.Criticality != nil {
		c := strings.ToLower(strings.TrimSpace(*p.Criticality))
		if !slices.Contains(Criticalities, c) {
			return p, fmt.Errorf("%w: criticality must be empty or one of low, medium, high, critical", ErrInvalid)
		}
		p.Criticality = &c
	}
	if p.Notes != nil {
		n := strings.TrimSpace(*p.Notes)
		if len(n) > maxNotesLen {
			return p, fmt.Errorf("%w: notes are longer than %d bytes", ErrInvalid, maxNotesLen)
		}
		p.Notes = &n
	}
	if p.UserTags != nil {
		t, err := NormalizeUserTags(*p.UserTags)
		if err != nil {
			return p, err
		}
		p.UserTags = &t
	}
	return p, nil
}

type change struct {
	Before any `json:"before"`
	After  any `json:"after"`
}

// Edit updates a host's user-owned fields and writes audit_log (notes only
// as "changed", never their text), then writes the result through to the
// IP's Dojo asset when it has one and c is non-nil. A Dojo failure doesn't
// undo the edit; it is logged and reported in DojoSync.
func Edit(ctx context.Context, pool *pgxpool.Pool, c dojo.WriteClient, actor *int64, ip netip.Addr, p Patch) (*EditResult, error) {
	p, err := p.normalize()
	if err != nil {
		return nil, err
	}
	ip = ip.Unmap()
	var assetID *int64
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		cur, err := q.GetHostUserFieldsForUpdate(ctx, ip)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get host %s: %w", ip, err)
		}
		assetID = cur.DojoAssetID
		next := gen.UpdateHostUserFieldsParams{
			Ip: ip, Owner: cur.Owner, Criticality: cur.Criticality, Notes: cur.Notes, UserTags: cur.UserTags,
		}
		diff := map[string]any{}
		if p.Owner != nil && *p.Owner != cur.Owner {
			diff["owner"] = change{cur.Owner, *p.Owner}
			next.Owner = *p.Owner
		}
		if p.Criticality != nil && *p.Criticality != cur.Criticality {
			diff["criticality"] = change{cur.Criticality, *p.Criticality}
			next.Criticality = *p.Criticality
		}
		if p.Notes != nil && *p.Notes != cur.Notes {
			diff["notes"] = "changed"
			next.Notes = *p.Notes
		}
		if p.UserTags != nil && !slices.Equal(*p.UserTags, cur.UserTags) {
			diff["user_tags"] = change{cur.UserTags, *p.UserTags}
			next.UserTags = *p.UserTags
		}
		if len(diff) == 0 {
			return nil
		}
		if err := q.UpdateHostUserFields(ctx, next); err != nil {
			return fmt.Errorf("update host %s: %w", ip, err)
		}
		return audit.Log(ctx, q, actor, "host.update", "host", ip.String(), diff)
	})
	if err != nil {
		return nil, err
	}
	d, err := Get(ctx, pool, ip)
	if err != nil {
		return nil, err
	}
	res := &EditResult{Detail: d, DojoSync: DojoPending}
	if assetID == nil || c == nil {
		return res, nil
	}
	err = dojo.WriteHostAsset(ctx, pool, c, *assetID, dojo.HostAsset{
		IP: ip, Owner: d.Owner, Criticality: d.Criticality, Notes: d.Notes, UserTags: d.UserTags,
	})
	if err != nil {
		slog.Error("host edit: dojo write-through", "ip", ip, "asset", *assetID, "err", err)
		res.DojoSync = DojoFailed
		return res, nil
	}
	res.DojoSync = DojoSynced
	return res, nil
}

// ServiceOverrideKeys are the services.overrides keys a user can set.
var ServiceOverrideKeys = []string{"name", "product", "version"}

// MergeOverrides applies patch to the overrides object cur: a string sets
// the key, null removes it. Only ServiceOverrideKeys are accepted; other keys
// already in cur are kept.
func MergeOverrides(cur []byte, patch map[string]json.RawMessage) ([]byte, error) {
	if len(patch) == 0 {
		return nil, fmt.Errorf("%w: nothing to change", ErrInvalid)
	}
	m := map[string]json.RawMessage{}
	if len(cur) > 0 && string(cur) != "null" {
		if err := json.Unmarshal(cur, &m); err != nil {
			m = map[string]json.RawMessage{}
		}
	}
	for k, v := range patch {
		if !slices.Contains(ServiceOverrideKeys, k) {
			return nil, fmt.Errorf("%w: override %q: only %s can be overridden", ErrInvalid, k, strings.Join(ServiceOverrideKeys, ", "))
		}
		if string(v) == "null" {
			delete(m, k)
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, fmt.Errorf("%w: override %q must be a string or null", ErrInvalid, k)
		}
		s = strings.TrimSpace(s)
		if utf8.RuneCountInString(s) > maxOverrideLen || strings.ContainsAny(s, "\r\n") {
			return nil, fmt.Errorf("%w: override %q must be one line of at most %d characters", ErrInvalid, k, maxOverrideLen)
		}
		b, _ := json.Marshal(s)
		m[k] = b
	}
	return json.Marshal(m)
}

// EditServiceOverrides merges patch into services.overrides (the only
// column it writes) and writes audit_log. It returns the service with the
// overrides applied.
func EditServiceOverrides(ctx context.Context, pool *pgxpool.Pool, actor *int64, id int64, patch map[string]json.RawMessage) (*Service, error) {
	var out *Service
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		cur, err := q.GetServiceOverridesForUpdate(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrServiceNotFound
		}
		if err != nil {
			return fmt.Errorf("get service %d: %w", id, err)
		}
		next, err := MergeOverrides(cur.Overrides, patch)
		if err != nil {
			return err
		}
		if err := q.UpdateServiceOverrides(ctx, gen.UpdateServiceOverridesParams{ID: id, Overrides: next}); err != nil {
			return fmt.Errorf("update service %d: %w", id, err)
		}
		if err := audit.Log(ctx, q, actor, "service.update", "service", strconv.FormatInt(id, 10),
			change{objectOrEmpty(cur.Overrides), json.RawMessage(next)}); err != nil {
			return err
		}
		row, err := q.GetService(ctx, id)
		if err != nil {
			return fmt.Errorf("get service %d: %w", id, err)
		}
		s := serviceFromRow(gen.ListHostServicesRow(row))
		out = &s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
