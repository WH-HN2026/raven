package dojo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

// SyncTag is the tag on every finding RAVEN pushes; the sync pulls only those.
const SyncTag = "raven"

// syncPageSize is the Dojo page size used by the sync.
const syncPageSize = 250

// Syncer pulls the Dojo read-model (architecture §4 "Pull / read-model"):
// the Assets of one organization and the findings tagged "raven" of that
// organization go into dojo_assets / dojo_findings.
type Syncer struct {
	Client         Client
	Pool           *pgxpool.Pool
	OrganizationID int64
}

// SyncStats is the result of one pass.
type SyncStats struct {
	Assets          int
	Findings        int
	AssetsDeleted   int64
	FindingsDeleted int64
	Duration        time.Duration
}

// Run syncs once now and then every interval until ctx is done. Errors are
// logged, never fatal.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		st, err := s.SyncOnce(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			slog.Error("dojo sync failed", "err", err)
		default:
			slog.Info("dojo sync done", "assets", st.Assets, "findings", st.Findings,
				"assets_deleted", st.AssetsDeleted, "findings_deleted", st.FindingsDeleted,
				"duration", st.Duration.Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SyncOnce is one full resync. It reads everything from Dojo first and only
// then, in one transaction, upserts the mirror and deletes rows Dojo no longer
// has; a failed read leaves the mirror untouched.
func (s *Syncer) SyncOnce(ctx context.Context) (SyncStats, error) {
	start := time.Now()
	var st SyncStats
	if s.OrganizationID == 0 {
		return st, errors.New("dojo sync: no organization id")
	}
	assets, err := pageAll(ctx, func(limit, offset int) (*Page[Asset], error) {
		return s.Client.ListAssets(ctx, AssetQuery{OrganizationID: s.OrganizationID, Limit: limit, Offset: offset})
	})
	if err != nil {
		return st, fmt.Errorf("dojo sync assets: %w", err)
	}
	findings, err := pageAll(ctx, func(limit, offset int) (*Page[Finding], error) {
		return s.Client.ListFindings(ctx, FindingQuery{
			Tags: []string{SyncTag}, OrganizationID: s.OrganizationID, Related: true, Limit: limit, Offset: offset,
		})
	})
	if err != nil {
		return st, fmt.Errorf("dojo sync findings: %w", err)
	}

	now := time.Now().UTC()
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		assetIDs := make([]int64, 0, len(assets))
		for _, a := range assets {
			if err := q.UpsertDojoAsset(ctx, mirrorAsset(a, now)); err != nil {
				return fmt.Errorf("upsert asset %d: %w", a.ID, err)
			}
			assetIDs = append(assetIDs, a.ID)
		}
		findingIDs := make([]int64, 0, len(findings))
		for _, f := range findings {
			if err := q.UpsertDojoFinding(ctx, mirrorFinding(f, now)); err != nil {
				return fmt.Errorf("upsert finding %d: %w", f.ID, err)
			}
			findingIDs = append(findingIDs, f.ID)
		}
		var err error
		if st.AssetsDeleted, err = q.DeleteDojoAssetsNotIn(ctx, assetIDs); err != nil {
			return fmt.Errorf("delete stale assets: %w", err)
		}
		if st.FindingsDeleted, err = q.DeleteDojoFindingsNotIn(ctx, findingIDs); err != nil {
			return fmt.Errorf("delete stale findings: %w", err)
		}
		return nil
	})
	if err != nil {
		return st, fmt.Errorf("dojo sync write mirror: %w", err)
	}
	st.Assets, st.Findings, st.Duration = len(assets), len(findings), time.Since(start)
	return st, nil
}

// pageAll collects every page of a DRF list. It stops at count, or on an
// empty page (so a list that shrinks while paging still terminates).
func pageAll[T any](ctx context.Context, list func(limit, offset int) (*Page[T], error)) ([]T, error) {
	var out []T
	for offset := 0; ; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := list(syncPageSize, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Results...)
		offset += len(p.Results)
		if len(p.Results) == 0 || offset >= p.Count {
			return out, nil
		}
	}
}

// ipFromName: an RAVEN asset is named after its IP (D5); others ("RAVEN Planning") have none.
func ipFromName(name string) *netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(name))
	if err != nil {
		return nil
	}
	a = a.Unmap()
	return &a
}

func mirrorAsset(a Asset, now time.Time) gen.UpsertDojoAssetParams {
	return gen.UpsertDojoAssetParams{ID: a.ID, Name: a.Name, Ip: ipFromName(a.Name), Tags: nonNil(a.Tags), SyncedAt: now}
}

func mirrorFinding(f Finding, now time.Time) gen.UpsertDojoFindingParams {
	p := gen.UpsertDojoFindingParams{
		ID:           f.ID,
		Title:        f.Title,
		Severity:     normSeverity(f.Severity),
		Active:       f.Active,
		Verified:     f.Verified,
		FalseP:       f.FalseP,
		OutOfScope:   f.OutOfScope,
		RiskAccepted: f.RiskAccepted,
		Duplicate:    f.Duplicate,
		IsMitigated:  f.IsMitigated,
		Tags:         nonNil(f.Tags),
		Scanner:      ScannerFromScanType(f.TestTypeName),
		SyncedAt:     now,
	}
	if id, name := f.Asset(); id != 0 {
		p.AssetID = &id
		p.Ip = ipFromName(name)
	}
	if d, err := time.Parse(time.DateOnly, f.Date); err == nil {
		p.Date = pgtype.Date{Time: d, Valid: true}
	}
	if !f.LastStatusUpdate.IsZero() {
		t := f.LastStatusUpdate
		p.LastStatusUpdate = &t
	}
	return p
}

// Severities are Dojo's values, in descending order.
var Severities = []string{"Critical", "High", "Medium", "Low", "Info"}

// normSeverity maps Dojo's severity to the mirror's CHECK set (unknown → Info).
func normSeverity(s string) string {
	for _, v := range Severities {
		if strings.EqualFold(s, v) {
			return v
		}
	}
	return "Info"
}

// ScannerFromScanType maps a Dojo scan/test type to our scanner name:
// "Nmap Scan" → "nmap", "Nuclei Scan" → "nuclei", our INFO findings
// ("Generic Findings Import") → "raven"; anything else is lowercased.
func ScannerFromScanType(t string) string {
	switch t {
	case "":
		return ""
	case "Generic Findings Import":
		return "raven"
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), " Scan"))
}
