package scheduler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

type scheduleAudit struct {
	gen.Schedule
	Aggressive bool `json:"aggressive,omitempty"`
}

type ScheduleInput struct {
	Name        *string    `json:"name"`
	ProfileID   int64      `json:"profile_id"`
	Cron        *string    `json:"cron"`
	WindowStart *time.Time `json:"window_start"`
	WindowEnd   *time.Time `json:"window_end"`
	Timezone    *string    `json:"timezone"`
	Enabled     *bool      `json:"enabled"`
}

func (in ScheduleInput) apply(s gen.Schedule) (gen.Schedule, error) {
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if len(name) > 200 {
			return gen.Schedule{}, fmt.Errorf("%w: name must be at most 200 characters", ErrInvalid)
		}
		s.Name = name
	}
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

func (s ConfigStore) CreateSchedule(ctx context.Context, u *auth.User, in ScheduleInput) (gen.Schedule, error) {
	schedule, err := in.apply(gen.Schedule{Source: "ui", Timezone: "Europe/Warsaw", Enabled: true})
	if err != nil {
		return gen.Schedule{}, err
	}
	err = s.write(ctx, func(q *gen.Queries) error {
		prof, err := q.GetProfile(ctx, schedule.ProfileID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: profile does not exist", ErrInvalid)
		}
		if err != nil {
			return err
		}
		aggressive := s.isAggressive(prof.Stages)
		if aggressive && !canAggressive(u) {
			return fmt.Errorf("%w: scheduling an aggressive profile needs %s", ErrForbidden, auth.PermScanAggressive)
		}
		schedule, err = q.CreateSchedule(ctx, gen.CreateScheduleParams{
			Name: schedule.Name, ProfileID: schedule.ProfileID, Cron: schedule.Cron, WindowStart: schedule.WindowStart,
			WindowEnd: schedule.WindowEnd, Timezone: schedule.Timezone, Enabled: schedule.Enabled,
		})
		if err := scheduleWriteError(err); err != nil {
			return err
		}
		return logConfigChange(ctx, q, u, "schedules.create", "schedule", schedule.ID, scheduleAudit{Schedule: schedule, Aggressive: aggressive})
	})
	return schedule, err
}

func (s ConfigStore) UpdateSchedule(ctx context.Context, u *auth.User, id int64, in ScheduleInput) (gen.Schedule, error) {
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
		targetProf, err := q.GetProfile(ctx, schedule.ProfileID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: profile does not exist", ErrInvalid)
		}
		if err != nil {
			return err
		}
		targetAgg := s.isAggressive(targetProf.Stages)
		priorAgg := targetAgg
		if prior.ProfileID != schedule.ProfileID {
			priorProf, err := q.GetProfile(ctx, prior.ProfileID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			priorAgg = err == nil && s.isAggressive(priorProf.Stages)
		}
		if (priorAgg || targetAgg) && !canAggressive(u) {
			return fmt.Errorf("%w: scheduling an aggressive profile needs %s", ErrForbidden, auth.PermScanAggressive)
		}
		if prior.ProfileID != schedule.ProfileID {
			if err := requireIdleSchedule(ctx, q, id); err != nil {
				return err
			}
		}
		updated, err = q.UpdateUISchedule(ctx, gen.UpdateUIScheduleParams{
			ID: id, Name: schedule.Name, ProfileID: schedule.ProfileID, Cron: schedule.Cron, WindowStart: schedule.WindowStart,
			WindowEnd: schedule.WindowEnd, Timezone: schedule.Timezone, Enabled: schedule.Enabled,
		})
		if err := scheduleWriteError(err); err != nil {
			return err
		}
		return logConfigChange(ctx, q, u, "schedules.update", "schedule", id, scheduleAudit{Schedule: updated, Aggressive: priorAgg || targetAgg})
	})
	return updated, err
}

func (s ConfigStore) DeleteSchedule(ctx context.Context, u *auth.User, id int64) error {
	return s.write(ctx, func(q *gen.Queries) error {
		prior, err := lockUISchedule(ctx, q, id)
		if err != nil {
			return err
		}
		priorProf, err := q.GetProfile(ctx, prior.ProfileID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		aggressive := err == nil && s.isAggressive(priorProf.Stages)
		if aggressive && !canAggressive(u) {
			return fmt.Errorf("%w: aggressive schedules need %s", ErrForbidden, auth.PermScanAggressive)
		}
		if err := requireIdleSchedule(ctx, q, id); err != nil {
			return err
		}
		if err := q.DeleteUISchedule(ctx, id); err != nil {
			return err
		}
		var diff any
		if aggressive {
			diff = map[string]any{"aggressive": true, "profile_id": prior.ProfileID}
		}
		return logConfigChange(ctx, q, u, "schedules.delete", "schedule", id, diff)
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
