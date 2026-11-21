package dojo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

// ProfileTagPrefix is the Dojo engagement tag prefix selecting the ASI scan
// profile for a planned engagement under "ASI Planning" (architecture §4, D9).
const ProfileTagPrefix = "asi-profile:"

// DefaultScheduleTimezone matches schedules.timezone's DB default.
const DefaultScheduleTimezone = "Europe/Warsaw"

// engagementStatusNotFound is stored in runs.stats.dojo_engagement_status when
// Dojo answers 404 for an engagement so we stop retrying a deleted one.
const engagementStatusNotFound = "not_found"

// PlanningPoller polls the "ASI Planning" asset for "Not Started" engagements
// tagged "asi-profile:<name>" into schedules(source='dojo') and mirrors run
// status back to Dojo engagement status ("In Progress" / "Completed").
type PlanningPoller struct {
	Client          Client
	Pool            *pgxpool.Pool
	PlanningAssetID int64
	Timezone        string // empty → DefaultScheduleTimezone
}

// PlanningStats summarizes one poll pass.
type PlanningStats struct {
	Found         int
	Upserted      int
	Skipped       int
	Disabled      int64
	StatusUpdated int
	StatusFailed  int
	Duration      time.Duration
}

// Run polls once now and then every interval until ctx is done. Errors are
// logged, never fatal.
func (p *PlanningPoller) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		st, err := p.PollOnce(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			slog.Error("dojo planning poll failed", "err", err,
				"upserted", st.Upserted, "disabled", st.Disabled,
				"status_updated", st.StatusUpdated, "status_failed", st.StatusFailed)
		default:
			slog.Info("dojo planning poll done", "found", st.Found, "upserted", st.Upserted,
				"skipped", st.Skipped, "disabled", st.Disabled,
				"status_updated", st.StatusUpdated,
				"duration", st.Duration.Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PollOnce runs one full planning pass:
//  1. Sync status of runs tied to Dojo schedules back to their engagements
//     (In Progress / Completed), PATCHing only when the status changes.
//  2. List "Not Started" engagements of ASI Planning tagged asi-profile:<name>.
//  3. In one transaction, upsert matching schedules and disable Dojo schedules
//     whose engagement disappeared / is no longer Not Started and has no run.
func (p *PlanningPoller) PollOnce(ctx context.Context) (PlanningStats, error) {
	start := time.Now()
	var st PlanningStats
	if p.PlanningAssetID == 0 {
		return st, errors.New("dojo planning: no planning asset id")
	}
	tz, loc := resolveTimezone(p.Timezone)

	statusErr := p.syncRunStatuses(ctx, &st)

	engs, err := pageAll(ctx, func(limit, offset int) (*Page[Engagement], error) {
		return p.Client.ListEngagements(ctx, EngagementQuery{
			AssetID:     p.PlanningAssetID,
			Status:      EngagementNotStarted,
			TagContains: ProfileTagPrefix,
			Limit:       limit,
			Offset:      offset,
		})
	})
	if err != nil {
		st.Duration = time.Since(start)
		return st, errors.Join(statusErr, fmt.Errorf("dojo planning list engagements: %w", err))
	}
	st.Found = len(engs)

	err = pgx.BeginFunc(ctx, p.Pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		profs, err := q.ListAllProfileNames(ctx)
		if err != nil {
			return fmt.Errorf("list profiles: %w", err)
		}
		idx := newProfileIndex(profs)
		activeIDs := make([]int64, 0, len(engs))
		for _, e := range engs {
			params, reason := mapPlannedEngagement(e, idx, tz, loc)
			if reason != "" {
				st.Skipped++
				slog.Warn("dojo planning: skipping engagement",
					"engagement_id", e.ID, "engagement", e.Name, "reason", reason)
				continue
			}
			if _, err := q.UpsertDojoSchedule(ctx, params); err != nil {
				return fmt.Errorf("upsert schedule for engagement %d: %w", e.ID, err)
			}
			activeIDs = append(activeIDs, e.ID)
			st.Upserted++
		}
		st.Disabled, err = q.DisableStaleDojoSchedules(ctx, activeIDs)
		if err != nil {
			return fmt.Errorf("disable stale schedules: %w", err)
		}
		return nil
	})
	st.Duration = time.Since(start)
	if err != nil {
		return st, errors.Join(statusErr, fmt.Errorf("dojo planning write schedules: %w", err))
	}
	return st, statusErr
}

func (p *PlanningPoller) syncRunStatuses(ctx context.Context, st *PlanningStats) error {
	q := gen.New(p.Pool)
	rows, err := q.ListDojoScheduleRunStatuses(ctx)
	if err != nil {
		return fmt.Errorf("dojo planning list run statuses: %w", err)
	}
	var errs []error
	for _, r := range rows {
		if r.DojoEngagementID == nil {
			continue
		}
		want, ok := nextEngagementStatus(r.RunStatus, r.SentStatus)
		if !ok {
			continue
		}
		engID := *r.DojoEngagementID
		if err := p.Client.SetEngagementStatus(ctx, engID, want); err != nil {
			if IsStatus(err, http.StatusNotFound) {
				slog.Warn("dojo planning: engagement not found, skipping status sync",
					"engagement_id", engID, "run_id", r.RunID, "want", want)
				if recErr := q.SetRunDojoEngagementStatus(ctx, gen.SetRunDojoEngagementStatusParams{
					ID: r.RunID, Status: engagementStatusNotFound,
				}); recErr != nil {
					errs = append(errs, fmt.Errorf("record missing engagement %d on run %d: %w", engID, r.RunID, recErr))
				}
				continue
			}
			st.StatusFailed++
			slog.Warn("dojo planning: set engagement status failed",
				"engagement_id", engID, "run_id", r.RunID, "want", want, "err", err)
			errs = append(errs, fmt.Errorf("set engagement %d status %q (run %d): %w", engID, want, r.RunID, err))
			continue
		}
		if err := q.SetRunDojoEngagementStatus(ctx, gen.SetRunDojoEngagementStatusParams{
			ID: r.RunID, Status: want,
		}); err != nil {
			errs = append(errs, fmt.Errorf("record engagement %d status %q on run %d: %w", engID, want, r.RunID, err))
			continue
		}
		st.StatusUpdated++
	}
	return errors.Join(errs...)
}

// targetEngagementStatus maps an ASI run status to the Dojo engagement status
// it should mirror, or "" when no status transition should be sent yet.
func targetEngagementStatus(runStatus string) string {
	switch runStatus {
	case "running", "suspended":
		return EngagementInProgress
	case "done", "failed", "stopped":
		return EngagementCompleted
	default:
		return ""
	}
}

// nextEngagementStatus returns the status to PATCH to Dojo and true if a PATCH
// is needed, or ("", false) when nothing changed or the engagement is gone.
func nextEngagementStatus(runStatus, sentStatus string) (string, bool) {
	if sentStatus == engagementStatusNotFound {
		return "", false
	}
	want := targetEngagementStatus(runStatus)
	if want == "" || want == sentStatus {
		return "", false
	}
	return want, true
}

// parseProfileTag extracts the profile name from the first tag starting with
// "asi-profile:" (case-insensitive prefix; Dojo forces tags to lowercase).
func parseProfileTag(tags []string) (string, bool) {
	for _, raw := range tags {
		t := strings.TrimSpace(raw)
		if len(t) <= len(ProfileTagPrefix) {
			continue
		}
		if !strings.EqualFold(t[:len(ProfileTagPrefix)], ProfileTagPrefix) {
			continue
		}
		if name := strings.TrimSpace(t[len(ProfileTagPrefix):]); name != "" {
			return name, true
		}
	}
	return "", false
}

// profileIndex resolves profile names from Dojo tags (exact match preferred,
// falling back to case-insensitive match because Dojo lowercases all tags).
type profileIndex struct {
	exact map[string]int64
	lower map[string]int64
}

func newProfileIndex(rows []gen.ListAllProfileNamesRow) profileIndex {
	idx := profileIndex{
		exact: make(map[string]int64, len(rows)),
		lower: make(map[string]int64, len(rows)),
	}
	for _, r := range rows {
		idx.exact[r.Name] = r.ID
		k := strings.ToLower(r.Name)
		if _, exists := idx.lower[k]; !exists {
			idx.lower[k] = r.ID
		}
	}
	return idx
}

func (p profileIndex) resolve(name string) (int64, bool) {
	if id, ok := p.exact[name]; ok {
		return id, true
	}
	id, ok := p.lower[strings.ToLower(name)]
	return id, ok
}

// parseEngagementWindow converts Dojo's target_start / target_end fields into
// schedule window timestamps. Dojo stores them as YYYY-MM-DD calendar dates,
// so target_start maps to 00:00:00 of that day in loc and target_end maps to
// 00:00:00 of the following day (exclusive end, covering the full target_end
// day and satisfying schedules' CHECK window_end > window_start even when
// target_start == target_end). Full RFC3339 timestamps are accepted as-is.
func parseEngagementWindow(targetStart, targetEnd string, loc *time.Location) (*time.Time, *time.Time, error) {
	if loc == nil {
		loc = time.UTC
	}
	start, err := parseEngagementTime(targetStart, false, loc)
	if err != nil {
		return nil, nil, fmt.Errorf("target_start: %w", err)
	}
	end, err := parseEngagementTime(targetEnd, true, loc)
	if err != nil {
		return nil, nil, fmt.Errorf("target_end: %w", err)
	}
	if start != nil && end != nil && !end.After(*start) {
		return nil, nil, fmt.Errorf("window_end %s is not after window_start %s",
			end.Format(time.RFC3339), start.Format(time.RFC3339))
	}
	return start, end, nil
}

func parseEngagementTime(raw string, endOfDay bool, loc *time.Location) (*time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	if t, err := time.ParseInLocation(time.DateOnly, s, loc); err == nil {
		if endOfDay {
			t = t.AddDate(0, 0, 1)
		}
		return &t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, nil
	}
	return nil, fmt.Errorf("invalid date %q", raw)
}

func mapPlannedEngagement(e Engagement, profiles profileIndex, tz string, loc *time.Location) (gen.UpsertDojoScheduleParams, string) {
	profName, ok := parseProfileTag(e.Tags)
	if !ok {
		return gen.UpsertDojoScheduleParams{}, "missing asi-profile:<name> tag"
	}
	profID, ok := profiles.resolve(profName)
	if !ok {
		return gen.UpsertDojoScheduleParams{}, fmt.Sprintf("unknown profile %q", profName)
	}
	start, end, err := parseEngagementWindow(e.TargetStart, e.TargetEnd, loc)
	if err != nil {
		return gen.UpsertDojoScheduleParams{}, err.Error()
	}
	engID := e.ID
	return gen.UpsertDojoScheduleParams{
		ProfileID:        profID,
		DojoEngagementID: &engID,
		WindowStart:      start,
		WindowEnd:        end,
		Timezone:         tz,
	}, ""
}

func resolveTimezone(name string) (string, *time.Location) {
	if strings.TrimSpace(name) == "" {
		name = DefaultScheduleTimezone
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		slog.Warn("dojo planning: unknown timezone, falling back to UTC", "timezone", name, "err", err)
		return "UTC", time.UTC
	}
	return name, loc
}
