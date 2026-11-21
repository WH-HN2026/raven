package scheduler

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

func parseTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestCronNext(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, expr, after, next string
	}{
		{"minutes", "*/15 * * * *", "2026-11-21T10:15:00+01:00", "2026-11-21T10:30:00+01:00"},
		{"hours", "0 */4 * * *", "2026-11-21T23:55:00+01:00", "2026-11-22T00:00:00+01:00"},
		{"daily", "5 9 * * *", "2026-11-21T08:00:00Z", "2026-11-21T09:05:00+01:00"},
		{"spring gap", "30 2 * * *", "2026-03-28T02:30:00+01:00", "2026-03-30T02:30:00+02:00"},
		{"fall repeat", "30 2 * * *", "2026-10-25T02:30:00+02:00", "2026-10-25T02:30:00+01:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseCron(tc.expr)
			if err != nil {
				t.Fatal(err)
			}
			got := c.Next(parseTime(t, tc.after).In(loc))
			if want := parseTime(t, tc.next); !got.Equal(want) {
				t.Fatalf("next = %s, want %s", got, want)
			}
		})
	}
	for _, expr := range []string{"", "*/0 * * * *", "61 * * * *", "5 25 * * *", "0 9 * * 1", "@daily"} {
		if _, err := ParseCron(expr); err == nil {
			t.Errorf("accepted invalid cron %q", expr)
		}
	}
}

func TestCalendarUIDue(t *testing.T) {
	start := parseTime(t, "2026-11-21T23:00:00+01:00")
	end := parseTime(t, "2026-11-22T02:00:00+01:00")
	c, err := NewCalendar(gen.Schedule{
		Source: "ui", Enabled: true, Timezone: "Europe/Warsaw",
		Cron: pgtype.Text{String: "0 * * * *", Valid: true}, WindowStart: &start, WindowEnd: &end,
		CreatedAt: start.Add(-2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, now string
		last      time.Time
		due       bool
	}{
		{"before start", "2026-11-21T21:59:59Z", time.Time{}, false},
		{"inclusive start", "2026-11-21T22:00:00Z", time.Time{}, true},
		{"tick after dispatch", "2026-11-21T22:00:40Z", start.Add(3 * time.Second), false},
		{"following hour", "2026-11-21T23:00:30Z", start.Add(3 * time.Second), true},
		{"exclusive end", "2026-11-22T01:00:00Z", time.Time{}, false},
		{"next day", "2026-11-22T22:00:00Z", start, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Due(parseTime(t, tc.now), tc.last); got != tc.due {
				t.Fatalf("due = %t, want %t", got, tc.due)
			}
		})
	}
	at := parseTime(t, "2026-11-22T00:00:00Z")
	if begin, finish, open := c.Window(at); !open || !begin.Equal(start) || !finish.Equal(end) {
		t.Fatalf("overnight window = (%s, %s, %t)", begin, finish, open)
	}
	c.schedule.Enabled = false
	if c.Due(start, time.Time{}) {
		t.Fatal("disabled schedule is due")
	}
}

func TestCalendarDailyWindowSpringForward(t *testing.T) {
	start := parseTime(t, "2026-03-27T01:00:00+01:00")
	end := parseTime(t, "2026-03-27T02:30:00+01:00")
	c, err := NewCalendar(gen.Schedule{
		Source: "ui", Timezone: "Europe/Warsaw",
		Cron: pgtype.Text{String: "* * * * *", Valid: true}, WindowStart: &start, WindowEnd: &end,
	})
	if err != nil {
		t.Fatal(err)
	}
	at := parseTime(t, "2026-03-29T00:45:00Z")
	wantEnd := parseTime(t, "2026-03-29T01:00:00Z")
	if _, finish, open := c.Window(at); !open || !finish.Equal(wantEnd) {
		t.Fatalf("spring window ends %s, open %t, want %s", finish, open, wantEnd)
	}
	if _, _, open := c.Window(wantEnd); open {
		t.Fatal("window stayed open after the spring transition")
	}
}

func TestCalendarDojoOneShot(t *testing.T) {
	start := parseTime(t, "2026-11-21T10:00:00+01:00")
	end := start.Add(time.Hour)
	c, err := NewCalendar(gen.Schedule{Source: "dojo", Enabled: true, WindowStart: &start, WindowEnd: &end})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		now, last time.Time
		due       bool
	}{
		{start.Add(-time.Second), time.Time{}, false},
		{start, time.Time{}, true},
		{start.Add(time.Minute), start, false},
		{end, time.Time{}, false},
		{start.AddDate(0, 0, 1), time.Time{}, false},
	} {
		if got := c.Due(tc.now, tc.last); got != tc.due {
			t.Errorf("at %s with previous %s, due = %t, want %t", tc.now, tc.last, got, tc.due)
		}
	}
	c.schedule.WindowEnd = nil
	if c.Due(start, time.Time{}) {
		t.Fatal("Dojo schedule with no end is due")
	}
}
