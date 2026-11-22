package dojo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

// Write-through edits (architecture §4, task D6): finding triage and notes
// go to Dojo first, then the mirror row is updated from Dojo's answer; host
// user fields go to the IP's Asset (description + "user:" tags).

var (
	// ErrNotReady: Dojo is not configured or its bootstrap hasn't finished.
	ErrNotReady = errors.New("dojo not ready")
	// ErrNotFound: the finding is not in the mirror.
	ErrNotFound = errors.New("finding not found")
	// ErrInvalid wraps a rejected edit (bad value or a combination Dojo refuses).
	ErrInvalid = errors.New("invalid edit")
)

// UserTagPrefix marks asset tags that come from RAVEN user tags. Every other
// tag on an asset (raven, host:*, tech:*, … and tags set in Dojo) is kept.
const UserTagPrefix = "user:"

// MaxNoteLen bounds a finding note (bytes).
const MaxNoteLen = 20000

// WriteClient is the part of Dojo that interactive API calls need (write-through
// finding/host edits and on-demand target import).
type WriteClient interface {
	PatchFinding(ctx context.Context, id int64, p FindingPatch) (*Finding, error)
	AddFindingNote(ctx context.Context, findingID int64, text string) error
	GetAsset(ctx context.Context, id int64) (*Asset, error)
	UpdateAsset(ctx context.Context, id int64, u AssetUpdate) (*Asset, error)
	ListAssets(ctx context.Context, q AssetQuery) (*Page[Asset], error)
	ListURLs(ctx context.Context, q URLQuery) (*Page[URL], error)
}

var _ WriteClient = (*HTTPClient)(nil)

// AssetUpdate is a partial asset PATCH (nil/empty = unchanged).
type AssetUpdate struct {
	Description                *string  `json:"description,omitempty"`
	Tags                       []string `json:"tags,omitempty"`
	EnableSimpleRiskAcceptance *bool    `json:"enable_simple_risk_acceptance,omitempty"`
}

func (c *HTTPClient) GetAsset(ctx context.Context, id int64) (*Asset, error) {
	var out Asset
	if err := c.do(ctx, http.MethodGet, "/api/v2/assets/"+itoa(id)+"/", nil, nil, &out); err != nil {
		return nil, fmt.Errorf("dojo get asset %d: %w", id, err)
	}
	return &out, nil
}

func (c *HTTPClient) UpdateAsset(ctx context.Context, id int64, u AssetUpdate) (*Asset, error) {
	var out Asset
	if err := c.do(ctx, http.MethodPatch, "/api/v2/assets/"+itoa(id)+"/", nil, u, &out); err != nil {
		return nil, fmt.Errorf("dojo update asset %d: %w", id, err)
	}
	return &out, nil
}

// Lazy holds the write client once the async bootstrap has produced it.
// The zero value is ready to use; Get returns nil until Set.
type Lazy struct {
	mu sync.RWMutex
	c  WriteClient
}

func (l *Lazy) Set(c WriteClient) {
	l.mu.Lock()
	l.c = c
	l.mu.Unlock()
}

// Get returns the client or nil (also for a nil *Lazy).
func (l *Lazy) Get() WriteClient {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.c
}

// ── findings ──

// FindingState is the triage state a patch is checked against.
type FindingState struct {
	Active, Verified, FalseP, RiskAccepted, IsMitigated bool
}

func (p FindingPatch) empty() bool {
	return p.Severity == nil && p.Active == nil && p.Verified == nil && p.FalseP == nil &&
		p.RiskAccepted == nil && p.IsMitigated == nil
}

func (s FindingState) apply(p FindingPatch) FindingState {
	set := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	set(&s.Active, p.Active)
	set(&s.Verified, p.Verified)
	set(&s.FalseP, p.FalseP)
	set(&s.RiskAccepted, p.RiskAccepted)
	set(&s.IsMitigated, p.IsMitigated)
	return s
}

// NormalizePatch validates p against the current state and fills in the
// fields an explicit change implies, so Dojo doesn't reject the PATCH:
//   - active=true clears false_p, risk_accepted and is_mitigated;
//   - false_p=true clears active and verified ("False positive findings
//     cannot be verified");
//   - risk_accepted=true or is_mitigated=true clears active ("Active findings
//     cannot be risk accepted").
//
// Implied fields are only added when they change the current value and the
// caller didn't set them. Explicit contradictions are ErrInvalid.
func NormalizePatch(cur FindingState, p FindingPatch) (FindingPatch, error) {
	if p.empty() {
		return p, fmt.Errorf("%w: nothing to change", ErrInvalid)
	}
	if p.Severity != nil {
		s := strings.TrimSpace(*p.Severity)
		i := -1
		for j, v := range Severities {
			if strings.EqualFold(v, s) {
				i = j
			}
		}
		if i < 0 {
			return p, fmt.Errorf("%w: severity must be one of %s", ErrInvalid, strings.Join(Severities, ", "))
		}
		v := Severities[i]
		p.Severity = &v
	}
	out := p
	imply := func(dst **bool, explicit *bool, curVal, v bool) {
		if explicit == nil && *dst == nil && curVal != v {
			*dst = &v
		}
	}
	if isTrue(p.Active) {
		imply(&out.FalseP, p.FalseP, cur.FalseP, false)
		imply(&out.RiskAccepted, p.RiskAccepted, cur.RiskAccepted, false)
		imply(&out.IsMitigated, p.IsMitigated, cur.IsMitigated, false)
	}
	if isTrue(p.FalseP) {
		imply(&out.Active, p.Active, cur.Active, false)
		imply(&out.Verified, p.Verified, cur.Verified, false)
	}
	if isTrue(p.RiskAccepted) || isTrue(p.IsMitigated) {
		imply(&out.Active, p.Active, cur.Active, false)
	}
	s := cur.apply(out)
	switch {
	case s.FalseP && s.Verified:
		return p, fmt.Errorf("%w: a false positive can't be verified", ErrInvalid)
	case s.Active && s.RiskAccepted:
		return p, fmt.Errorf("%w: an active finding can't be risk accepted", ErrInvalid)
	case s.Active && s.FalseP:
		return p, fmt.Errorf("%w: an active finding can't be a false positive", ErrInvalid)
	case s.Active && s.IsMitigated:
		return p, fmt.Errorf("%w: an active finding can't be mitigated", ErrInvalid)
	}
	return out, nil
}

func isTrue(b *bool) bool { return b != nil && *b }

func mirrorFromRow(r gen.GetDojoFindingRow, dojoPublicURL string) *MirrorFinding {
	m := &MirrorFinding{
		ID: r.ID, AssetID: r.AssetID, IP: r.Ip, Title: r.Title, Severity: r.Severity, Active: r.Active,
		Verified: r.Verified, FalseP: r.FalseP, OutOfScope: r.OutOfScope, RiskAccepted: r.RiskAccepted,
		Duplicate: r.Duplicate, IsMitigated: r.IsMitigated,
		Tags: nonNil(r.Tags), Scanner: r.Scanner, DojoURL: FindingURL(dojoPublicURL, r.ID),
	}
	if r.Date != "" {
		d := r.Date
		m.Date = &d
	}
	return m
}

type triage struct {
	Severity     string `json:"severity"`
	Active       bool   `json:"active"`
	Verified     bool   `json:"verified"`
	FalseP       bool   `json:"false_p"`
	RiskAccepted bool   `json:"risk_accepted"`
	IsMitigated  bool   `json:"is_mitigated"`
}

func triageOf(m *MirrorFinding) triage {
	return triage{m.Severity, m.Active, m.Verified, m.FalseP, m.RiskAccepted, m.IsMitigated}
}

func getMirror(ctx context.Context, q *gen.Queries, id int64, dojoPublicURL string) (*MirrorFinding, error) {
	r, err := q.GetDojoFinding(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mirror finding %d: %w", id, err)
	}
	return mirrorFromRow(r, dojoPublicURL), nil
}

// EditFinding applies a triage patch to a mirrored finding: validate against
// the mirror, PATCH Dojo, then update the mirror from Dojo's answer and write
// audit_log (before/after). c nil = ErrNotReady.
func EditFinding(ctx context.Context, pool *pgxpool.Pool, c WriteClient, actor *int64, id int64, p FindingPatch, dojoPublicURL string) (*MirrorFinding, error) {
	q := gen.New(pool)
	before, err := getMirror(ctx, q, id, dojoPublicURL)
	if err != nil {
		return nil, err
	}
	p, err = NormalizePatch(FindingState{before.Active, before.Verified, before.FalseP, before.RiskAccepted, before.IsMitigated}, p)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrNotReady
	}
	// Dojo refuses simple risk acceptance unless the asset allows it.
	if isTrue(p.RiskAccepted) && !before.RiskAccepted && before.AssetID != nil {
		on := true
		if _, err := c.UpdateAsset(ctx, *before.AssetID, AssetUpdate{EnableSimpleRiskAcceptance: &on}); err != nil {
			return nil, fmt.Errorf("edit finding %d: %w", id, err)
		}
	}
	f, err := c.PatchFinding(ctx, id, p)
	if err != nil {
		if IsStatus(err, http.StatusBadRequest) {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return nil, fmt.Errorf("edit finding %d: %w", id, err)
	}
	var after *MirrorFinding
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		u := gen.UpdateDojoFindingTriageParams{
			ID: id, Severity: normSeverity(f.Severity), Active: f.Active, Verified: f.Verified, FalseP: f.FalseP,
			OutOfScope: f.OutOfScope, RiskAccepted: f.RiskAccepted, Duplicate: f.Duplicate,
			IsMitigated: f.IsMitigated, Tags: nonNil(f.Tags),
		}
		if !f.LastStatusUpdate.IsZero() {
			t := f.LastStatusUpdate
			u.LastStatusUpdate = &t
		}
		if err := q.UpdateDojoFindingTriage(ctx, u); err != nil {
			return fmt.Errorf("update mirror finding %d: %w", id, err)
		}
		var err error
		if after, err = getMirror(ctx, q, id, dojoPublicURL); err != nil {
			return err
		}
		return audit.Log(ctx, q, actor, "finding.update", "finding", itoa(id),
			map[string]any{"patch": p, "before": triageOf(before), "after": triageOf(after)})
	})
	if err != nil {
		return nil, err
	}
	return after, nil
}

// AddNote adds a note to a mirrored finding in Dojo (notes are not mirrored)
// and writes audit_log with the note's length, not its text.
func AddNote(ctx context.Context, pool *pgxpool.Pool, c WriteClient, actor *int64, id int64, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("%w: note text is empty", ErrInvalid)
	}
	if len(text) > MaxNoteLen {
		return fmt.Errorf("%w: note is longer than %d bytes", ErrInvalid, MaxNoteLen)
	}
	q := gen.New(pool)
	if _, err := getMirror(ctx, q, id, ""); err != nil {
		return err
	}
	if c == nil {
		return ErrNotReady
	}
	if err := c.AddFindingNote(ctx, id, text); err != nil {
		if IsStatus(err, http.StatusBadRequest) {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return err
	}
	return audit.Log(ctx, q, actor, "finding.note", "finding", itoa(id), map[string]any{"length": len(text)})
}

// ── hosts → assets ──

// HostAsset is what an IP's asset shows of the host's user-owned fields.
type HostAsset struct {
	IP          netip.Addr
	Owner       string
	Criticality string
	Notes       string
	UserTags    []string // without UserTagPrefix
}

// AssetDescription renders the asset description from the user fields.
func AssetDescription(h HostAsset) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host %s (managed by RAVEN)\n", h.IP)
	var meta []string
	if h.Owner != "" {
		meta = append(meta, "**Owner:** "+h.Owner)
	}
	if h.Criticality != "" {
		meta = append(meta, "**Criticality:** "+h.Criticality)
	}
	if len(meta) > 0 {
		b.WriteString("\n" + strings.Join(meta, "\n") + "\n")
	}
	if n := strings.TrimSpace(h.Notes); n != "" {
		b.WriteString("\n" + n + "\n")
	}
	return b.String()
}

// MergeAssetTags returns the asset's tags with its "user:" tags replaced by
// userTags (prefixed). Every other tag is kept in its order; duplicates are
// dropped case-insensitively.
func MergeAssetTags(have, userTags []string) []string {
	out := make([]string, 0, len(have)+len(userTags))
	seen := map[string]bool{}
	add := func(t string) {
		if k := strings.ToLower(t); t != "" && !seen[k] {
			seen[k] = true
			out = append(out, t)
		}
	}
	for _, t := range have {
		if !strings.HasPrefix(strings.ToLower(t), UserTagPrefix) {
			add(t)
		}
	}
	for _, t := range userTags {
		add(UserTagPrefix + t)
	}
	return out
}

// WriteHostAsset sets the asset's description and user tags from h and
// refreshes its mirror row.
func WriteHostAsset(ctx context.Context, pool *pgxpool.Pool, c WriteClient, assetID int64, h HostAsset) error {
	a, err := c.GetAsset(ctx, assetID)
	if err != nil {
		return err
	}
	desc := AssetDescription(h)
	a, err = c.UpdateAsset(ctx, assetID, AssetUpdate{Description: &desc, Tags: MergeAssetTags(a.Tags, h.UserTags)})
	if err != nil {
		return err
	}
	if err := gen.New(pool).UpsertDojoAsset(ctx, mirrorAsset(*a, time.Now().UTC())); err != nil {
		return fmt.Errorf("mirror asset %d: %w", assetID, err)
	}
	return nil
}
