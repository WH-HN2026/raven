package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scheduler"
)

var (
	errWindowClosed   = errors.New("scan window closed")
	errDojoAggressive = errors.New("Dojo schedule cannot start aggressive profile")
)

// DispatchSchedule checks the next action without locks. The transition
// rechecks it under the profile and schedule locks before changing state.
func (s *Service) DispatchSchedule(ctx context.Context, id int64) error {
	q := gen.New(s.pool)
	schedule, err := q.GetSchedule(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	latest, err := latestScheduledRun(ctx, q, id)
	if err != nil {
		return err
	}
	calendar, err := scheduler.NewCalendar(schedule)
	if err != nil {
		return err
	}
	now := time.Now()
	switch {
	case latest.Status == "suspended":
		if _, _, open := calendar.Window(now); open {
			err = s.resumeScheduledRun(ctx, schedule, latest)
		}
	case isActive(latest.Status):
		if latest.ScheduleWindowEnd != nil && !now.Before(*latest.ScheduleWindowEnd) {
			err = s.pauseScheduledRun(ctx, latest)
		}
	case calendar.Due(now, lastStart(latest)):
		_, err = s.startRun(ctx, nil, schedule.ProfileID, &id)
		if errors.Is(err, errDojoAggressive) {
			slog.Warn("scheduler: skipping Dojo schedule for aggressive profile",
				"schedule_id", id, "profile_id", schedule.ProfileID)
			_ = audit.Log(ctx, q, nil, "schedules.dojo_skip_aggressive", "schedule", strconv.FormatInt(id, 10), map[string]any{
				"aggressive": true, "schedule_id": id, "profile_id": schedule.ProfileID, "reason": "aggressive_profile_not_allowed",
			})
			return nil
		}
	}
	if errors.Is(err, ErrConflict) {
		return nil // another dispatcher or an overlapping run won the slot
	}
	return err
}

func latestScheduledRun(ctx context.Context, q *gen.Queries, scheduleID int64) (gen.Run, error) {
	r, err := q.GetLatestScheduledRun(ctx, &scheduleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return gen.Run{}, nil
	}
	return r, err
}

func lastStart(r gen.Run) time.Time {
	if r.StartedAt != nil {
		return *r.StartedAt
	}
	return r.CreatedAt
}

func lockScheduleForProfile(ctx context.Context, q *gen.Queries, id, profileID int64) (gen.Schedule, error) {
	schedule, err := q.LockSchedule(ctx, id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return gen.Schedule{}, err
	}
	if err != nil || !schedule.Enabled || schedule.ProfileID != profileID {
		return gen.Schedule{}, fmt.Errorf("%w: schedule changed", ErrConflict)
	}
	return schedule, nil
}

// prepareScheduledStart runs after acquiring the profile lock. The schedule
// lock serializes dispatches with edits and makes the Dojo start one-shot.
func prepareScheduledStart(ctx context.Context, q *gen.Queries, id int64, prof gen.Profile) (time.Time, *time.Time, error) {
	schedule, err := lockScheduleForProfile(ctx, q, id, prof.ID)
	if err != nil {
		return time.Time{}, nil, err
	}
	if schedule.Source == "dojo" && IsAggressive(EffectiveStages(prof.Stages)) {
		return time.Time{}, nil, fmt.Errorf("%w: schedule %d profile %q", errDojoAggressive, id, prof.Name)
	}
	latest, err := latestScheduledRun(ctx, q, id)
	if err != nil {
		return time.Time{}, nil, err
	}
	calendar, err := scheduler.NewCalendar(schedule)
	if err != nil {
		return time.Time{}, nil, err
	}
	now := time.Now()
	if latest.Status == "suspended" || isActive(latest.Status) || !calendar.Due(now, lastStart(latest)) {
		return time.Time{}, nil, fmt.Errorf("%w: schedule %d is not due", ErrConflict, id)
	}
	_, end, _ := calendar.Window(now)
	return now, optionalDeadline(end), nil
}

func optionalDeadline(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Service) resumeScheduledRun(ctx context.Context, schedule gen.Schedule, previous gen.Run) error {
	runID := previous.ID
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		profile, err := q.LockProfile(ctx, previous.ProfileID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil || !profile.Enabled {
			return err
		}
		schedule, err := q.LockSchedule(ctx, schedule.ID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !schedule.Enabled) {
			return nil
		}
		if err != nil {
			return err
		}
		if schedule.Source == "dojo" && IsAggressive(EffectiveStages(profile.Stages)) {
			slog.Warn("scheduler: skipping resume of Dojo schedule for aggressive profile",
				"schedule_id", schedule.ID, "profile_id", profile.ID, "profile", profile.Name)
			return nil
		}
		run, err := q.LockRun(ctx, runID)
		if err != nil {
			return err
		}
		if run.Status != "suspended" || run.ScheduleID == nil || *run.ScheduleID != schedule.ID {
			return nil
		}
		calendar, err := scheduler.NewCalendar(schedule)
		if err != nil {
			return err
		}
		now := time.Now()
		_, end, open := calendar.Window(now)
		if !open || (run.ScheduleWindowEnd != nil && now.Before(*run.ScheduleWindowEnd)) {
			return nil
		}
		n, err := q.CountActiveRuns(ctx, run.ProfileID)
		if err != nil || n > 0 {
			return err
		}
		pending, err := q.ListPendingBatches(ctx, runID)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			return fmt.Errorf("suspended run %d has no pending batches", runID)
		}
		ids := make([]int64, 0, len(pending))
		jobs := make([]river.InsertManyParams, 0, len(pending))
		for _, b := range pending {
			var names map[string][]string
			if err := json.Unmarshal(b.Hostnames, &names); err != nil {
				return fmt.Errorf("decode names for batch %d: %w", b.ID, err)
			}
			ids = append(ids, b.ID)
			jobs = append(jobs, newBatchJob(runID, b.ID, names))
		}
		if err := s.enqueueBatches(ctx, tx, ids, jobs); err != nil {
			return err
		}
		if err := q.ResumeScheduledRun(ctx, gen.ResumeScheduledRunParams{ID: runID, ScheduleWindowEnd: optionalDeadline(end)}); err != nil {
			return err
		}
		return audit.Log(ctx, q, nil, "runs.resume", "run", strconv.FormatInt(runID, 10),
			map[string]any{"schedule_id": schedule.ID, "batches": len(ids)})
	})
}

// pauseScheduledRun is also usable by a worker whose scanner context expired.
// The stored deadline identifies the window even after a concurrent resume.
func (s *Service) pauseScheduledRun(ctx context.Context, run gen.Run) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		current, err := q.LockRun(ctx, run.ID)
		if err != nil {
			return err
		}
		if !isActive(current.Status) || current.ScheduleWindowEnd == nil ||
			!current.ScheduleWindowEnd.Equal(*run.ScheduleWindowEnd) {
			return nil
		}
		return suspendLockedRun(ctx, q, current)
	})
}

func suspendLockedRun(ctx context.Context, q *gen.Queries, run gen.Run) error {
	// Supersede all original jobs under the run lock. Outstanding workers use
	// the same deadline, and their jobs can no longer change these batches.
	if err := q.ResetWindowBatches(ctx, run.ID); err != nil {
		return err
	}
	if err := q.SuspendScheduledRun(ctx, run.ID); err != nil {
		return err
	}
	return audit.Log(ctx, q, nil, "runs.suspend", "run", strconv.FormatInt(run.ID, 10),
		map[string]any{"schedule_id": run.ScheduleID, "window_end": run.ScheduleWindowEnd})
}

// Check ownership under the run lock. A job from an earlier window may
// still be returning from cancellation when a new one has been enqueued.
func scheduledJobOwnsBatch(ctx context.Context, q *gen.Queries, batchID int64, jobID *int64) (bool, error) {
	b, err := q.GetBatch(ctx, batchID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return b.JobID != nil && jobID != nil && *b.JobID == *jobID, nil
}

func newBatchJob(runID, id int64, hostnames map[string][]string) river.InsertManyParams {
	return river.InsertManyParams{
		Args:       BatchArgs{BatchID: id, RunID: runID, Hostnames: hostnames},
		InsertOpts: &river.InsertOpts{MaxAttempts: maxAttempts},
	}
}

func (s *Service) enqueueBatches(ctx context.Context, tx pgx.Tx, ids []int64, jobs []river.InsertManyParams) error {
	if len(jobs) == 0 {
		return nil
	}
	res, err := s.river.InsertManyTx(ctx, tx, jobs)
	if err != nil {
		return fmt.Errorf("enqueue batches: %w", err)
	}
	q := gen.New(tx)
	for i, r := range res {
		if err := q.SetBatchJob(ctx, gen.SetBatchJobParams{ID: ids[i], JobID: &r.Job.ID}); err != nil {
			return fmt.Errorf("set batch job: %w", err)
		}
	}
	return nil
}
