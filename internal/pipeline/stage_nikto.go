package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nikto"
)

const niktoStageConcurrency = 2

type niktoStageResult struct {
	res    *scanner.Result
	urls   int
	errors int
}

// scanNikto runs the aggressive nikto stage against httpx-confirmed literal-IP
// origins of this batch. Each URL runs in its own nikto invocation with bounded
// concurrency (1–2). A tool failure on one URL is logged and counted in
// nikto_errors without failing the batch; context cancellation still aborts.
func (s *Service) scanNikto(ctx context.Context, b gen.Batch, prof gen.Profile, web *scanner.Result) (*niktoStageResult, error) {
	if web == nil {
		return nil, nil
	}
	in := nikto.BuildInput(b.Ips, web.Observations)
	if len(in.URLs) == 0 {
		return nil, nil
	}

	conc := min(niktoStageConcurrency, len(in.URLs))
	perProcRate := max(1, s.webRate(prof)/conc)

	type urlRes struct {
		raw []byte
		err error
	}
	out := make([]urlRes, len(in.URLs))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, targetURL := range in.URLs {
		wg.Add(1)
		go func(idx int, rawURL string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[idx].err = ctx.Err()
				return
			}
			t0 := time.Now()
			singleIn := singleURLInput(in.IPs, rawURL)
			res, err := s.cfg.Nikto.Run(ctx, singleIn, scanner.Options{RateLimit: perProcRate})
			dur := time.Since(t0)
			if ctx.Err() != nil {
				out[idx].err = ctx.Err()
				return
			}
			if err != nil {
				slog.Warn("nikto url failed", "run", b.RunID, "batch", b.ID, "url", rawURL,
					"duration_ms", dur.Milliseconds(), "err", err)
				out[idx].err = err
				return
			}
			findings := 0
			var raw []byte
			if res != nil {
				findings = len(res.Observations)
				raw = res.Raw
			}
			slog.Info("nikto url done", "run", b.RunID, "batch", b.ID, "url", rawURL,
				"duration_ms", dur.Milliseconds(), "findings", findings)
			out[idx].raw = raw
		}(i, targetURL)
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var chunks [][]byte
	errCount := 0
	for _, r := range out {
		if r.err != nil {
			errCount++
			continue
		}
		if len(r.raw) > 0 {
			chunks = append(chunks, r.raw)
		}
	}

	var parsed *scanner.Result
	if len(chunks) > 0 {
		combined, err := nikto.CombineRaw(chunks)
		if err != nil {
			slog.Warn("nikto combine output failed", "run", b.RunID, "batch", b.ID, "err", err)
			errCount++
		} else if len(combined) > 0 {
			parsed, err = nikto.Parse(combined)
			if err != nil {
				slog.Warn("nikto parse combined output failed", "run", b.RunID, "batch", b.ID, "err", err)
				errCount++
			}
		}
	}

	return &niktoStageResult{res: parsed, urls: len(in.URLs), errors: errCount}, nil
}

func (s *Service) ingestNikto(ctx context.Context, q *gen.Queries, b gen.Batch, nr *niktoStageResult) error {
	if nr == nil {
		return nil
	}
	// Accumulate stage stats on runs.stats; re-reading under the run lock the
	// caller already holds sees earlier stages' merges.
	run, err := q.LockRun(ctx, b.RunID)
	if err != nil {
		return fmt.Errorf("lock run %d: %w", b.RunID, err)
	}
	var existing map[string]any
	if len(run.Stats) > 0 {
		_ = json.Unmarshal(run.Stats, &existing)
	}
	patch, err := json.Marshal(map[string]any{
		"nikto_urls":   jsonInt(existing["nikto_urls"]) + nr.urls,
		"nikto_errors": jsonInt(existing["nikto_errors"]) + nr.errors,
	})
	if err != nil {
		return fmt.Errorf("marshal nikto stats: %w", err)
	}
	if err := q.MergeRunStats(ctx, gen.MergeRunStatsParams{ID: run.ID, Stats: patch}); err != nil {
		return fmt.Errorf("merge nikto stats: %w", err)
	}
	if nr.res != nil && len(nr.res.Raw) > 0 {
		if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
			RunID: b.RunID, BatchID: &b.ID, Scanner: StageNikto, Content: string(nr.res.Raw),
		}); err != nil {
			return fmt.Errorf("ingest nikto artifact: %w", err)
		}
	}
	return nil
}

func singleURLInput(ips []netip.Addr, rawURL string) scanner.Input {
	return scanner.Input{IPs: ips, URLs: []string{rawURL}}
}
