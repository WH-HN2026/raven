package pipeline

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

// RunFinishedHook lets a batch hook enqueue work in the same transaction as a
// completed run's inactive transitions. The worker sees the committed stats.
type RunFinishedHook interface {
	AfterRunFinished(ctx context.Context, tx pgx.Tx, runID int64) error
}

func (s *Service) finishBatchRun(ctx context.Context, tx pgx.Tx, q *gen.Queries, runID int64, status string, stats map[string]any, inactiveIPs []string) error {
	if err := finishRun(ctx, q, runID, status, stats); err != nil {
		return err
	}
	if hook, ok := s.cfg.Hook.(RunFinishedHook); ok && status == "done" && len(inactiveIPs) > 0 {
		if err := hook.AfterRunFinished(ctx, tx, runID); err != nil {
			return fmt.Errorf("enqueue run-finished hook for run %d: %w", runID, err)
		}
	}
	return nil
}
