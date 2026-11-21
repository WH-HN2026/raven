package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
)

func defaultNucleiActive() scanner.Scanner {
	return nuclei.NewActive(nuclei.ActiveConfig{
		TemplatesDir: os.Getenv("RAVEN_NUCLEI_TEMPLATES"),
	})
}

type batchExtraIngest = func(ctx context.Context, q *gen.Queries) error

// runNucleiActiveStage executes the aggressive nuclei_active stage per live
// httpx URL of the batch. A failure on one URL is logged and counted in
// runs.stats.nuclei_active_errors without failing the batch; parent context
// cancellation (run stop / schedule window end) still aborts immediately.
func (s *Service) runNucleiActiveStage(ctx context.Context, b gen.Batch, prof gen.Profile, web *scanner.Result) (batchExtraIngest, error) {
	if web == nil {
		return nil, nil
	}
	in := nuclei.BuildInput(b.Ips, web.Observations)
	if len(in.URLs) == 0 {
		return nil, nil
	}

	var (
		raw       []byte
		succeeded int
		urlErrors int
	)
	rate := s.webRate(prof)
	for _, rawURL := range in.URLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			slog.Warn("nuclei_active invalid url", "run", b.RunID, "batch", b.ID, "url", rawURL, "err", err)
			urlErrors++
			continue
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			slog.Warn("nuclei_active non-literal url host", "run", b.RunID, "batch", b.ID, "url", rawURL, "err", err)
			urlErrors++
			continue
		}
		res, err := s.cfg.NucleiActive.Run(ctx, scanner.Input{
			IPs:  []netip.Addr{ip.Unmap()},
			URLs: []string{rawURL},
		}, scanner.Options{RateLimit: rate})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			slog.Warn("nuclei_active url failed", "run", b.RunID, "batch", b.ID, "url", rawURL, "err", err)
			urlErrors++
			continue
		}
		succeeded++
		if res != nil && len(bytes.TrimSpace(res.Raw)) > 0 {
			raw = append(raw, res.Raw...)
			if raw[len(raw)-1] != '\n' {
				raw = append(raw, '\n')
			}
		}
	}

	return func(ctx context.Context, q *gen.Queries) error {
		if succeeded > 0 {
			if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
				RunID: b.RunID, BatchID: &b.ID, Scanner: s.cfg.NucleiActive.Name(), Content: string(raw),
			}); err != nil {
				return fmt.Errorf("ingest nuclei_active artifact: %w", err)
			}
		}
		if err := q.AddRunNucleiActiveErrors(ctx, gen.AddRunNucleiActiveErrorsParams{ID: b.RunID, Delta: int32(urlErrors)}); err != nil {
			return fmt.Errorf("record nuclei_active_errors for run %d: %w", b.RunID, err)
		}
		return nil
	}, nil
}
