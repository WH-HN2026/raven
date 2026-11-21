package scheduler

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

const cronLookback = 48 * time.Hour

// Cron admits every minute, every Nth minute, every Nth hour on the hour,
// or a fixed local time every hour or day. The last three fields must be '*'.
type Cron struct {
	hour, minute         int
	hourStep, minuteStep int
}

func ParseCron(expr string) (Cron, error) {
	fields := strings.Fields(expr)
	if len(fields) == 5 && fields[2] == "*" && fields[3] == "*" && fields[4] == "*" {
		h, hStep, hOK := cronField(fields[1], 23)
		m, mStep, mOK := cronField(fields[0], 59)
		if hOK && mOK && ((hStep == 1 && h == -1) || (h >= 0 && m >= 0) || (hStep > 1 && m == 0)) {
			return Cron{hour: h, minute: m, hourStep: hStep, minuteStep: mStep}, nil
		}
	}
	return Cron{}, errors.New("cron must be '* * * * *', '*/N * * * *', '0 */N * * *', 'M * * * *', or 'M H * * *'")
}

func cronField(field string, maxValue int) (value, step int, ok bool) {
	if field == "*" {
		return -1, 1, true
	}
	if value, found := strings.CutPrefix(field, "*/"); found {
		n, err := strconv.Atoi(value)
		return -1, n, err == nil && n >= 1 && n <= maxValue+1
	}
	n, err := strconv.Atoi(field)
	return n, 1, err == nil && n >= 0 && n <= maxValue
}

func matches(value, fixed, step int) bool {
	if fixed >= 0 {
		return value == fixed
	}
	return step > 0 && value%step == 0
}

// Next returns the first occurrence strictly after after, in after's location.
// A nonexistent clock minute is skipped; a repeated minute has two instants.
func (c Cron) Next(after time.Time) time.Time {
	end := after.Add(cronLookback)
	for at := after.Truncate(time.Minute).Add(time.Minute); !at.After(end); at = at.Add(time.Minute) {
		if matches(at.Hour(), c.hour, c.hourStep) && matches(at.Minute(), c.minute, c.minuteStep) {
			return at
		}
	}
	return time.Time{}
}

// Calendar interprets UI bounds as a daily local time window and Dojo bounds
// as an absolute, one-shot time window. A window includes its start only.
type Calendar struct {
	schedule gen.Schedule
	loc      *time.Location
	cron     Cron
}

func NewCalendar(s gen.Schedule) (Calendar, error) {
	c := Calendar{schedule: s}
	if s.Source == "dojo" {
		return c, nil
	}
	if s.Source != "ui" {
		return Calendar{}, fmt.Errorf("unknown schedule source %q", s.Source)
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil || s.Timezone == "" || s.Timezone == "Local" {
		return Calendar{}, errors.New("timezone must be an IANA timezone name")
	}
	c.loc = loc
	if !s.Cron.Valid {
		return Calendar{}, errors.New("cron is required for UI schedules")
	}
	c.cron, err = ParseCron(s.Cron.String)
	if err != nil {
		return Calendar{}, err
	}
	if (s.WindowStart == nil) != (s.WindowEnd == nil) {
		return Calendar{}, errors.New("both window_start and window_end are required for a daily window")
	}
	if s.WindowStart != nil {
		if !s.WindowEnd.After(*s.WindowStart) {
			return Calendar{}, errors.New("window_end must be after window_start")
		}
		if compareClock(s.WindowStart.In(loc), s.WindowEnd.In(loc)) == 0 {
			return Calendar{}, errors.New("daily window start and end must be different local times")
		}
	}
	return c, nil
}

// Due reports whether to start a run at now. A zero last means no previous run.
// A UI occurrence must fall in the current window. Missed windows are skipped.
func (c Calendar) Due(now, last time.Time) bool {
	start, _, open := c.Window(now)
	if !open || !c.schedule.Enabled {
		return false
	}
	if c.schedule.Source == "dojo" {
		return last.IsZero()
	}
	floor := now.Add(-cronLookback)
	if c.schedule.CreatedAt.After(floor) {
		floor = c.schedule.CreatedAt.Add(-time.Nanosecond)
	}
	if start.After(floor) {
		floor = start.Add(-time.Nanosecond)
	}
	if last.After(floor) {
		floor = last
	}
	next := c.cron.Next(floor.In(c.loc))
	return !next.IsZero() && !next.After(now)
}

// Window returns the bounds of the current window, if one is open.
// A zero bound means the corresponding side is unbounded.
func (c Calendar) Window(now time.Time) (start, end time.Time, open bool) {
	s := c.schedule
	if s.Source == "dojo" {
		if s.WindowStart == nil || s.WindowEnd == nil {
			return time.Time{}, time.Time{}, false
		}
		start, end = *s.WindowStart, *s.WindowEnd
		return start, end, !now.Before(start) && now.Before(end)
	}
	if s.WindowStart == nil {
		return time.Time{}, time.Time{}, true
	}
	local := now.In(c.loc)
	begin, finish := s.WindowStart.In(c.loc), s.WindowEnd.In(c.loc)
	overnight := compareClock(begin, finish) > 0
	for _, back := range []int{0, -1} {
		start = localBoundary(local, begin, back)
		endDay := back
		if overnight {
			endDay++
		}
		end = localBoundary(local, finish, endDay)
		if !now.Before(start) && now.Before(end) {
			return start, end, true
		}
	}
	return time.Time{}, time.Time{}, false
}

func compareClock(a, b time.Time) int {
	return cmp.Compare(clockOffset(a), clockOffset(b))
}

func clockOffset(t time.Time) time.Duration {
	h, m, s := t.Clock()
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second + time.Duration(t.Nanosecond())
}

// localBoundary chooses the first occurrence of a repeated clock time and
// the transition instant for a clock time skipped by a spring-forward.
func localBoundary(day, clock time.Time, days int) time.Time {
	wall := time.Date(day.Year(), day.Month(), day.Day()+days, clock.Hour(), clock.Minute(), clock.Second(), clock.Nanosecond(), time.UTC)
	loc := day.Location()
	_, offset := wall.Add(-24 * time.Hour).In(loc).Zone()
	at := wall.Add(-time.Duration(offset) * time.Second).In(loc)
	_, actualOffset := at.Zone()
	if offset != actualOffset {
		transition, _ := at.ZoneBounds()
		adjusted := wall.Add(-time.Duration(actualOffset) * time.Second).In(loc)
		if adjusted.Before(transition) {
			return transition
		}
		return adjusted
	}
	return at
}
