package dojo

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/cve"
)

// CVE matching (task C3, architecture §11): a periodic pass matches open
// services against the committed CVE data, then every active IP whose match
// set changed is reimported into its "RAVEN CVE match" test with
// close_old_findings, so a version change closes findings for the old version.

// DefaultCVEProfile names the engagement for IPs no profile run has seen up
// (e.g. imported hosts).
const DefaultCVEProfile = "default"

// CVEPusher pushes one IP's CVE findings.
type CVEPusher struct {
	Client         Client
	OrganizationID int64
}

// Push ensures Asset "<ip>" → Engagement "RAVEN: <profile>" → Test "RAVEN CVE
// match" and reimports the IP's match set (possibly empty) into it.
func (p *CVEPusher) Push(ctx context.Context, h cve.PushHost, date time.Time) (*ImportResult, error) {
	profile := h.Profile
	if profile == "" {
		profile = DefaultCVEProfile
	}
	tags := AssetTags(h.Hostnames)
	asset, err := p.Client.GetOrCreateAsset(ctx, AssetSpec{
		Name: h.IP.String(), Description: "Host " + h.IP.String() + " (managed by RAVEN)",
		OrganizationID: p.OrganizationID, Tags: tags,
	})
	if err != nil {
		return nil, err
	}
	eng, err := p.Client.GetOrCreateEngagement(ctx, EngagementSpec{
		AssetID: asset.ID, Name: EngagementName(profile), Tags: []string{TagASI},
	})
	if err != nil {
		return nil, err
	}
	test, err := p.Client.GetOrCreateTest(ctx, TestSpec{
		EngagementID: eng.ID, ScanType: GenericScanType, Title: cve.TestTitle,
	})
	if err != nil {
		return nil, err
	}
	doc, err := cve.Report(h.Matches, date)
	if err != nil {
		return nil, err
	}
	return p.Client.ReimportScan(ctx, ImportRequest{
		ScanType: GenericScanType, TestID: test.ID,
		FileName: "raven-cve-" + h.IP.String() + ".json", File: bytes.NewReader(doc),
		CloseOldFindings: true, Tags: []string{TagASI}, TagFindings: true, ScanDate: date,
	})
}

// CVESync runs match passes and pushes.
type CVESync struct {
	Pool    *pgxpool.Pool
	Matcher *cve.Matcher
	Pusher  *CVEPusher // nil = match only (Dojo disabled or not bootstrapped yet)
	Next    *Syncer    // triggered after each triggered pass (D7); nil = none

	kick Trigger
}

// Trigger asks Run for one extra pass now (coalesced, non-blocking); that
// pass then triggers Next, so the mirror sync sees the CVE push.
func (s *CVESync) Trigger() { s.kick.Fire() }

// Once runs one match pass and pushes the IPs whose match set changed. A
// failed IP keeps its old hash and is retried on the next pass.
func (s *CVESync) Once(ctx context.Context) error {
	now := time.Now()
	res, err := cve.RunPass(ctx, s.Pool, s.Matcher, now)
	if err != nil {
		return err
	}
	if s.Pusher == nil {
		slog.Info("cve match pass", "services", res.Services, "matches", res.Matches, "removed", res.Removed)
		return nil
	}
	hosts, err := cve.PushCandidates(ctx, s.Pool)
	if err != nil {
		return err
	}
	ok, failed := 0, 0
	for _, h := range hosts {
		if _, err := s.Pusher.Push(ctx, h, now); err != nil {
			failed++
			slog.Warn("cve push failed", "ip", h.IP, "err", err)
			continue
		}
		if err := cve.MarkPushed(ctx, s.Pool, h.IP, h.Hash, now); err != nil {
			failed++
			slog.Warn("cve push", "ip", h.IP, "err", err)
			continue
		}
		ok++
	}
	slog.Info("cve match pass", "services", res.Services, "matches", res.Matches, "removed", res.Removed,
		"pushed", ok, "push_failed", failed)
	if failed > 0 {
		return fmt.Errorf("cve push: %d of %d IPs failed", failed, len(hosts))
	}
	return nil
}

// Run runs Once now, then every interval and on every Trigger, until ctx ends.
func (s *CVESync) Run(ctx context.Context, interval time.Duration) {
	loop(ctx, interval, &s.kick, func(triggered bool) {
		if err := s.Once(ctx); err != nil && ctx.Err() == nil {
			slog.Error("cve match", "err", err)
		}
		if triggered && s.Next != nil && ctx.Err() == nil {
			s.Next.Trigger()
		}
	})
}
