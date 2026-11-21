// Package scheduler checks persisted schedules and dispatches due work.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

type Dispatcher interface {
	DispatchSchedule(context.Context, int64) error
}

type Scheduler struct {
	Queries *gen.Queries
	Runs    Dispatcher
}

// Run checks immediately, then every interval.
func (s Scheduler) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Error("check scan schedules", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s Scheduler) RunOnce(ctx context.Context) error {
	ids, err := s.Queries.ListEnabledScheduleIDs(ctx)
	if err != nil {
		return fmt.Errorf("list enabled schedules: %w", err)
	}
	var failures []error
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.Runs.DispatchSchedule(ctx, id); err != nil {
			failures = append(failures, fmt.Errorf("schedule %d: %w", id, err))
		}
	}
	return errors.Join(failures...)
}
