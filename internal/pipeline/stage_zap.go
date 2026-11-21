package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/zap"
)

type zapBatchResult struct {
	result *scanner.Result
	errors int
}

func (s *Service) scanZAP(ctx context.Context, b gen.Batch, prof gen.Profile, web *scanner.Result) (zapBatchResult, error) {
	if web == nil || s.cfg.ZAP == nil {
		return zapBatchResult{}, nil
	}
	in := zap.BuildInput(b.Ips, web.Observations)
	if len(in.URLs) == 0 {
		return zapBatchResult{}, nil
	}
	opt := scanner.Options{RateLimit: s.webRate(prof)}
	if detailed, ok := s.cfg.ZAP.(zap.DetailedRunner); ok {
		rep, err := detailed.RunDetailed(ctx, in, opt)
		if ctx.Err() != nil {
			return zapBatchResult{}, ctx.Err()
		}
		if err != nil {
			slog.Warn("zap stage failed", "run", b.RunID, "batch", b.ID, "err", err)
			return zapBatchResult{errors: len(in.URLs)}, nil
		}
		for _, o := range rep.Outcomes {
			if o.Err != nil {
				slog.Warn("zap url failed", "run", b.RunID, "batch", b.ID, "url", o.URL,
					"dur", o.Duration.Round(time.Millisecond), "err", o.Err)
			} else {
				slog.Info("zap url done", "run", b.RunID, "batch", b.ID, "url", o.URL,
					"dur", o.Duration.Round(time.Millisecond), "alerts", o.Alerts)
			}
		}
		return zapBatchResult{result: rep.Result, errors: rep.Errors}, nil
	}
	res, err := s.cfg.ZAP.Run(ctx, in, opt)
	if ctx.Err() != nil {
		return zapBatchResult{}, ctx.Err()
	}
	if err != nil {
		slog.Warn("zap stage failed", "run", b.RunID, "batch", b.ID, "err", err)
		return zapBatchResult{errors: len(in.URLs)}, nil
	}
	return zapBatchResult{result: res}, nil
}

func (s *Service) ingestZAP(ctx context.Context, q *gen.Queries, b gen.Batch, zr zapBatchResult) error {
	if zr.errors > 0 {
		if err := q.AddRunZapErrors(ctx, gen.AddRunZapErrorsParams{
			ID:    b.RunID,
			Delta: int32(zr.errors),
		}); err != nil {
			return fmt.Errorf("record zap errors: %w", err)
		}
	}
	if zr.result == nil || len(zr.result.Raw) == 0 {
		return nil
	}
	if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
		RunID: b.RunID, BatchID: &b.ID, Scanner: StageZAP, Content: string(zr.result.Raw),
	}); err != nil {
		return fmt.Errorf("ingest zap artifact: %w", err)
	}
	return nil
}
