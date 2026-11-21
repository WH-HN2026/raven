package scheduler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

type ScheduleInput struct {
	ProfileID   int64      `json:"profile_id"`
	Cron        *string    `json:"cron"`
	WindowStart *time.Time `json:"window_start"`
	WindowEnd   *time.Time `json:"window_end"`
	Timezone    *string    `json:"timezone"`
	Enabled     *bool      `json:"enabled"`
}

func (in ScheduleInput) apply(s gen.Schedule) (gen.Schedule, error) {
	s.ProfileID = in.ProfileID
	if s.ProfileID < 1 {
		return gen.Schedule{}, fmt.Errorf("%w: profile_id must be positive", ErrInvalid)
	}
	s.Timezone = defaultTo(in.Timezone, s.Timezone)
	s.Enabled = defaultTo(in.Enabled, s.Enabled)
	s.WindowStart, s.WindowEnd = in.WindowStart, in.WindowEnd
	s.Cron = pgtype.Text{}
	if in.Cron != nil {
		cron := strings.Join(strings.Fields(*in.Cron), " ")
		s.Cron = pgtype.Text{String: cron, Valid: true}
	}
	if _, err := NewCalendar(s); err != nil {
		return gen.Schedule{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return s, nil
}

func (s ConfigStore) CreateSchedule(ctx context.Context, userID int64, in ScheduleInput) (gen.Schedule, error) {
	schedule, err := in.apply(gen.Schedule{Source: "ui", Timezone: "Europe/Warsaw", Enabled: true})
	if err != nil {
		return gen.Schedule{}, err
	}
	err = s.write(ctx, func(q *gen.Queries) error {
		schedule, err = q.CreateSchedule(ctx, gen.CreateScheduleParams{
			ProfileID: schedule.ProfileID, Cron: schedule.Cron, WindowStart: schedule.WindowStart,
			WindowEnd: schedule.WindowEnd, Timezone: schedule.Timezone, Enabled: schedule.Enabled,
		})
		if err := scheduleWriteError(err); err != nil {
			return err
		}
		return logConfigChange(ctx, q, userID, "schedules.create", "schedule", schedule.ID, schedule)
	})
	return schedule, err
}

func (s ConfigStore) UpdateSchedule(ctx context.Context, userID, id int64, in ScheduleInput) (gen.Schedule, error) {
	var updated gen.Schedule
	err := s.write(ctx, func(q *gen.Queries) error {
		prior, err := lockUISchedule(ctx, q, id)
		if err != nil {
			return err
		}
		schedule, err := in.apply(prior)
		if err != nil {
			return err
		}
		if prior.ProfileID != schedule.ProfileID {
			if err := requireIdleSchedule(ctx, q, id); err != nil {
				return err
			}
		}
		updated, err = q.UpdateUISchedule(ctx, gen.UpdateUIScheduleParams{
			ID: id, ProfileID: schedule.ProfileID, Cron: schedule.Cron, WindowStart: schedule.WindowStart,
			WindowEnd: schedule.WindowEnd, Timezone: schedule.Timezone, Enabled: schedule.Enabled,
		})
		if err := scheduleWriteError(err); err != nil {
			return err
		}
		return logConfigChange(ctx, q, userID, "schedules.update", "schedule", id, updated)
	})
	return updated, err
}

func (s ConfigStore) DeleteSchedule(ctx context.Context, userID, id int64) error {
	return s.write(ctx, func(q *gen.Queries) error {
		if _, err := lockUISchedule(ctx, q, id); err != nil {
			return err
		}
		if err := requireIdleSchedule(ctx, q, id); err != nil {
			return err
		}
		if err := q.DeleteUISchedule(ctx, id); err != nil {
			return err
		}
		return logConfigChange(ctx, q, userID, "schedules.delete", "schedule", id, nil)
	})
}

func lockUISchedule(ctx context.Context, q *gen.Queries, id int64) (gen.Schedule, error) {
	row, err := q.LockSchedule(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return gen.Schedule{}, fmt.Errorf("%w: schedule %d", ErrNotFound, id)
	}
	if err != nil {
		return gen.Schedule{}, err
	}
	if row.Source != "ui" {
		return gen.Schedule{}, fmt.Errorf("%w: Dojo schedules are read-only", ErrConflict)
	}
	return row, nil
}

func requireIdleSchedule(ctx context.Context, q *gen.Queries, id int64) error {
	active, err := q.HasActiveScheduledRun(ctx, &id)
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("%w: schedule has an unfinished run", ErrConflict)
	}
	return nil
}

func scheduleWriteError(err error) error {
	if dbCode(err, "23503") {
		return fmt.Errorf("%w: profile does not exist", ErrInvalid)
	}
	return err
}
