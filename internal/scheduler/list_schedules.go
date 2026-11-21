package scheduler

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

func (s ConfigStore) ListSchedules(ctx context.Context, limit, offset int32, order db.ListOrder) ([]gen.Schedule, int64, error) {
	q := gen.New(s.Pool)
	if order.Column == "" {
		rows, err := q.ListSchedules(ctx, gen.ListSchedulesParams{Limit: limit, Offset: offset})
		if err != nil {
			return nil, 0, err
		}
		total, err := q.CountSchedules(ctx)
		return rows, total, err
	}
	rows, err := q.ListAllSchedules(ctx)
	if err != nil {
		return nil, 0, err
	}
	names := map[int64]string{}
	if order.Column == "profile" {
		profiles, err := q.ListAllProfileNames(ctx)
		if err != nil {
			return nil, 0, err
		}
		for _, p := range profiles {
			names[p.ID] = p.Name
		}
	}
	now := time.Now()
	type sortValue struct {
		text   string
		number int64
	}
	keys := make(map[int64]sortValue, len(rows))
	for _, row := range rows {
		switch order.Column {
		case "name":
			keys[row.ID] = sortValue{text: cmp.Or(row.Name, "#"+strconv.FormatInt(row.ID, 10))}
		case "profile":
			keys[row.ID] = sortValue{text: names[row.ProfileID]}
		case "source":
			keys[row.ID] = sortValue{text: row.Source, number: valueOrZero(row.DojoEngagementID)}
		case "repeats":
			keys[row.ID] = sortValue{text: cmp.Or(row.Cron.String, row.Source)}
		case "window":
			keys[row.ID] = sortValue{number: windowStartKey(row)}
		case "next_window":
			keys[row.ID] = sortValue{number: nextWindowKey(row, now)}
		case "timezone":
			keys[row.ID] = sortValue{text: row.Timezone}
		case "enabled":
			status := "off"
			if row.Source == "dojo" {
				status = "read-only"
			} else if row.Enabled {
				status = "on"
			}
			keys[row.ID] = sortValue{text: status}
		}
	}
	slices.SortFunc(rows, func(a, b gen.Schedule) int {
		ka, kb := keys[a.ID], keys[b.ID]
		n := cmp.Or(cmp.Compare(strings.ToLower(ka.text), strings.ToLower(kb.text)), cmp.Compare(ka.number, kb.number))
		if order.Direction == "desc" {
			n = -n
		}
		return cmp.Or(n, cmp.Compare(a.ID, b.ID))
	})
	total := len(rows)
	start := min(int(offset), total)
	end := min(start+int(limit), total)
	return rows[start:end], int64(total), nil
}

func valueOrZero(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func windowStartKey(s gen.Schedule) int64 {
	if s.WindowStart == nil || s.WindowEnd == nil {
		return 0
	}
	if s.Source == "dojo" {
		return s.WindowStart.UnixMilli()
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return 0
	}
	return clockOffset(s.WindowStart.In(loc)).Milliseconds()
}

// Open windows sort before upcoming windows, and ended windows come last.
func nextWindowKey(s gen.Schedule, now time.Time) int64 {
	if s.WindowStart == nil || s.WindowEnd == nil {
		return 0
	}
	if s.Source == "dojo" {
		if now.Before(*s.WindowStart) {
			return s.WindowStart.UnixMilli()
		}
		if !now.Before(*s.WindowEnd) {
			return 1<<63 - 1
		}
		return 0
	}
	cal, err := NewCalendar(s)
	if err != nil {
		return 0
	}
	if _, _, open := cal.Window(now); open {
		return 0
	}
	local, start := now.In(cal.loc), s.WindowStart.In(cal.loc)
	next := localBoundary(local, start, 0)
	if !now.Before(next) {
		next = localBoundary(local, start, 1)
	}
	return next.UnixMilli()
}
