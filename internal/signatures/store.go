package signatures

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

var (
	ErrNotFound = errors.New("signature not found")
	ErrConflict = errors.New("a signature with this template id already exists")
	ErrBuiltin  = errors.New("built-in signatures can't be edited or deleted, only enabled or disabled")
	ErrInvalid  = errors.New("invalid signature")
)

// Signature is a stored nuclei template enriched with severity and tags parsed
// from its YAML info block.
type Signature struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	TemplateYAML    string    `json:"template_yaml"`
	Severity        string    `json:"severity"`
	Tags            []string  `json:"tags"`
	Enabled         bool      `json:"enabled"`
	Valid           bool      `json:"valid"`
	ValidationError string    `json:"validation_error"`
	Builtin         bool      `json:"builtin"`
	CreatedBy       *int64    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}

// ListFilter selects signatures for List. Zero values mean "no filter".
type ListFilter struct {
	Tag   string // exact tag match (case-insensitive)
	Order db.ListOrder
}

func enrich(r gen.Signature) Signature {
	sig, _ := signatureMetadata(r)
	return sig
}

func signatureMetadata(r gen.Signature) (Signature, string) {
	tpl, _ := Validate([]byte(r.TemplateYaml))
	tags := make([]string, len(tpl.Tags))
	copy(tags, tpl.Tags)
	return Signature{
		ID:              r.ID,
		Name:            r.Name,
		TemplateYAML:    r.TemplateYaml,
		Severity:        strings.ToLower(strings.TrimSpace(tpl.Severity)),
		Tags:            tags,
		Enabled:         r.Enabled,
		Valid:           r.Valid,
		ValidationError: r.ValidationError,
		Builtin:         r.Builtin,
		CreatedBy:       r.CreatedBy,
		CreatedAt:       r.CreatedAt,
	}, cmp.Or(tpl.Name, r.Name)
}

func hasTag(tags []string, want string) bool {
	return slices.ContainsFunc(tags, func(t string) bool { return strings.EqualFold(t, want) })
}

// InvalidError is returned when a template can't be saved at all (no usable
// id) or an invalid one is enabled. Issues are the validator's findings.
type InvalidError struct {
	Msg    string
	Issues []Issue
}

func (e *InvalidError) Error() string {
	if len(e.Issues) == 0 {
		return e.Msg
	}
	return e.Msg + ": " + Summary(e.Issues)
}
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// Store is the DB side of signatures. Every mutation writes audit_log in the
// same transaction. The HTTP handlers and the MCP server call it.
type Store struct {
	Pool *pgxpool.Pool
}

// Update is a partial update: nil fields are kept.
type Update struct {
	TemplateYAML *string
	Enabled      *bool
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

func ids(id int64) string { return strconv.FormatInt(id, 10) }

// List returns one page of signatures (built-ins first) and the total,
// optionally filtered by tag.
func (s *Store) List(ctx context.Context, f ListFilter, limit, offset int32) ([]Signature, int64, error) {
	q := gen.New(s.Pool)
	tag := strings.TrimSpace(f.Tag)
	if tag == "" && f.Order.Column == "" {
		rows, err := q.ListSignatures(ctx, gen.ListSignaturesParams{Limit: limit, Offset: offset})
		if err != nil {
			return nil, 0, fmt.Errorf("list signatures: %w", err)
		}
		total, err := q.CountSignatures(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("count signatures: %w", err)
		}
		items := make([]Signature, len(rows))
		for i, r := range rows {
			items[i] = enrich(r)
		}
		return items, total, nil
	}
	rows, err := q.ListAllSignatures(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list signatures: %w", err)
	}
	type namedSignature struct {
		Signature
		displayName string
	}
	matched := make([]namedSignature, 0, len(rows))
	for _, r := range rows {
		sig, name := signatureMetadata(r)
		if tag == "" || hasTag(sig.Tags, tag) {
			matched = append(matched, namedSignature{sig, name})
		}
	}
	if f.Order.Column != "" {
		slices.SortFunc(matched, func(a, b namedSignature) int {
			n := compareSignatures(f.Order.Column, a.Signature, b.Signature, a.displayName, b.displayName)
			if f.Order.Direction == "desc" {
				n = -n
			}
			return cmp.Or(n, cmp.Compare(a.ID, b.ID))
		})
	}
	total := int64(len(matched))
	start := int(offset)
	if start >= len(matched) {
		return []Signature{}, total, nil
	}
	end := len(matched)
	if limit > 0 && start+int(limit) < end {
		end = start + int(limit)
	}
	items := make([]Signature, end-start)
	for i, sig := range matched[start:end] {
		items[i] = sig.Signature
	}
	return items, total, nil
}

// Get returns one signature.
func (s *Store) Get(ctx context.Context, id int64) (Signature, error) {
	sig, err := gen.New(s.Pool).GetSignature(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Signature{}, ErrNotFound
	}
	if err != nil {
		return Signature{}, fmt.Errorf("get signature %d: %w", id, err)
	}
	return enrich(sig), nil
}

// Enabled returns the templates nuclei should run (enabled ⇒ valid).
func (s *Store) Enabled(ctx context.Context) ([]gen.Signature, error) {
	items, err := gen.New(s.Pool).ListEnabledSignatures(ctx)
	if err != nil {
		return nil, fmt.Errorf("list enabled signatures: %w", err)
	}
	return items, nil
}

// check validates src and returns the name (template id) to store it under.
// A template without a usable id can't be stored; other problems are kept
// in validation_error and the signature stays disabled.
func check(src string) (name string, issues []Issue, err error) {
	tpl, issues := Validate([]byte(src))
	if tpl.ID == "" || !idRe.MatchString(tpl.ID) || len(tpl.ID) > 100 {
		return "", issues, &InvalidError{Msg: "template needs a valid id", Issues: issues}
	}
	return tpl.ID, issues, nil
}

func uniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// Create stores a user signature. Invalid templates are saved disabled with
// their validation_error.
func (s *Store) Create(ctx context.Context, u *auth.User, src string, enabled bool) (Signature, error) {
	var out gen.Signature
	name, issues, err := check(src)
	if err != nil {
		return Signature{}, err
	}
	valid := len(issues) == 0
	err = s.tx(ctx, func(q *gen.Queries) error {
		out, err = q.InsertSignature(ctx, gen.InsertSignatureParams{
			Name: name, TemplateYaml: src, Enabled: enabled && valid, Valid: valid,
			ValidationError: Summary(issues), Builtin: false, CreatedBy: userID(u),
		})
		if uniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return fmt.Errorf("insert signature %s: %w", name, err)
		}
		return audit.Log(ctx, q, userID(u), "signatures.create", "signature", ids(out.ID),
			map[string]any{"name": name, "valid": valid, "enabled": out.Enabled})
	})
	if err != nil {
		return Signature{}, err
	}
	return enrich(out), nil
}

// Update changes a signature. Built-ins accept only Enabled; enabling an
// invalid template is rejected.
func (s *Store) Update(ctx context.Context, u *auth.User, id int64, in Update) (Signature, error) {
	var out gen.Signature
	err := s.tx(ctx, func(q *gen.Queries) error {
		cur, err := q.GetSignature(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get signature %d: %w", id, err)
		}
		p := gen.UpdateSignatureParams{ID: id, Name: cur.Name, TemplateYaml: cur.TemplateYaml,
			Enabled: cur.Enabled, Valid: cur.Valid, ValidationError: cur.ValidationError}
		yamlChanged := in.TemplateYAML != nil && *in.TemplateYAML != cur.TemplateYaml
		if yamlChanged {
			if cur.Builtin {
				return ErrBuiltin
			}
			name, issues, err := check(*in.TemplateYAML)
			if err != nil {
				return err
			}
			p.Name, p.TemplateYaml = name, *in.TemplateYAML
			p.Valid, p.ValidationError = len(issues) == 0, Summary(issues)
			if !p.Valid {
				p.Enabled = false
			}
		}
		if in.Enabled != nil {
			if *in.Enabled && !p.Valid {
				return &InvalidError{Msg: "an invalid signature can't be enabled"}
			}
			p.Enabled = *in.Enabled
		}
		out, err = q.UpdateSignature(ctx, p)
		if uniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return fmt.Errorf("update signature %d: %w", id, err)
		}
		return audit.Log(ctx, q, userID(u), "signatures.update", "signature", ids(id), map[string]any{
			"name": out.Name, "template_changed": yamlChanged, "valid": out.Valid,
			"enabled": map[string]bool{"from": cur.Enabled, "to": out.Enabled},
		})
	})
	if err != nil {
		return Signature{}, err
	}
	return enrich(out), nil
}

// Delete removes a user signature; built-ins can't be deleted.
func (s *Store) Delete(ctx context.Context, u *auth.User, id int64) error {
	return s.tx(ctx, func(q *gen.Queries) error {
		cur, err := q.GetSignature(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get signature %d: %w", id, err)
		}
		if cur.Builtin {
			return ErrBuiltin
		}
		if _, err := q.DeleteSignature(ctx, id); err != nil {
			return fmt.Errorf("delete signature %d: %w", id, err)
		}
		return audit.Log(ctx, q, userID(u), "signatures.delete", "signature", ids(id), map[string]any{"name": cur.Name})
	})
}

// Builtin is one template of the shipped pack.
type Builtin struct {
	File string
	YAML string
}

// SyncBuiltins makes the signatures table match the pack: new templates are
// inserted (enabled when valid), changed ones updated (keeping the user's
// enabled choice), removed ones deleted. A user signature with the same id
// wins over a built-in. Writes one system audit row when anything changed.
func (s *Store) SyncBuiltins(ctx context.Context, pack []Builtin) error {
	return s.tx(ctx, func(q *gen.Queries) error {
		var keep, added, updated, skipped []string
		for _, b := range pack {
			name, issues, err := check(b.YAML)
			if err != nil {
				return fmt.Errorf("built-in %s: %w", b.File, err)
			}
			valid := len(issues) == 0
			keep = append(keep, name)
			cur, err := q.GetSignatureByName(ctx, name)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				_, err = q.InsertSignature(ctx, gen.InsertSignatureParams{
					Name: name, TemplateYaml: b.YAML, Enabled: valid, Valid: valid,
					ValidationError: Summary(issues), Builtin: true,
				})
				added = append(added, name)
			case err != nil:
			case !cur.Builtin:
				skipped = append(skipped, name)
			case cur.TemplateYaml == b.YAML:
			default:
				_, err = q.UpdateSignature(ctx, gen.UpdateSignatureParams{
					ID: cur.ID, Name: name, TemplateYaml: b.YAML, Enabled: cur.Enabled && valid,
					Valid: valid, ValidationError: Summary(issues),
				})
				updated = append(updated, name)
			}
			if err != nil {
				return fmt.Errorf("sync built-in %s: %w", name, err)
			}
		}
		removed, err := q.DeleteBuiltinsExcept(ctx, keep)
		if err != nil {
			return fmt.Errorf("delete old built-ins: %w", err)
		}
		if len(added)+len(updated)+len(removed) == 0 {
			return nil
		}
		return audit.Log(ctx, q, nil, "signatures.sync_builtin", "signature", "", map[string]any{
			"added": added, "updated": updated, "removed": removed, "skipped_user_owned": skipped,
		})
	})
}

// templateFile reports whether a pack file name is a template.
func templateFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") && !strings.HasPrefix(name, ".")
}
