//go:build integration

package dojo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
)

// TestIntegrationPlanning runs D5 end-to-end against the shared DefectDojo
// (RAVEN_DOJO_URL) and a fresh throwaway DB:
//   - creates uniquely named "Not Started" engagements under "RAVEN Planning"
//     (one with a valid profile tag, one with an unknown profile tag, one to
//     verify disabling when cancelled/removed with no run);
//   - polls and checks the resulting schedules rows;
//   - cancels the extra engagement, polls again, checks it gets disabled;
//   - inserts a run tied to the valid schedule, transitions running → suspended
//     → done, polls after each step, and asserts Dojo engagement status moves
//     In Progress → Completed with no redundant PATCHes;
//   - deletes ONLY the engagements this test created.
func TestIntegrationPlanning(t *testing.T) {
	base := os.Getenv("RAVEN_DOJO_URL")
	if base == "" {
		t.Skip("RAVEN_DOJO_URL not set")
	}
	pool := dbtest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	orgName := os.Getenv("RAVEN_DOJO_ORGANIZATION")
	if orgName == "" {
		orgName = "RAVEN"
	}
	boot, err := Bootstrap(ctx, BootstrapConfig{
		URL:          base,
		Token:        os.Getenv("RAVEN_DOJO_TOKEN"),
		AdminUser:    os.Getenv("DD_ADMIN_USER"),
		AdminPass:    os.Getenv("DD_ADMIN_PASSWORD"),
		Organization: orgName,
		RetryEvery:   2 * time.Second,
	})
	must(t, err)
	c := boot.Client
	planningID := boot.Planning.ID

	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	slug := "raven-it-d5-" + hex.EncodeToString(rnd)
	t.Logf("slug=%s planning_asset_id=%d", slug, planningID)

	createPlanned := func(name, start, end string, tags []string) *Engagement {
		t.Helper()
		var out Engagement
		err := c.do(ctx, http.MethodPost, "/api/v2/engagements/", nil, map[string]any{
			"product":         planningID,
			"name":            name,
			"engagement_type": "CI/CD",
			"status":          EngagementNotStarted,
			"target_start":    start,
			"target_end":      end,
			"tags":            tags,
		}, &out)
		must(t, err)
		t.Cleanup(func() { deleteObj(t, c, "engagements", out.ID) })
		return &out
	}

	eValid := createPlanned(slug+"-valid", "2026-12-01", "2026-12-03", []string{ProfileTagPrefix + "default", slug})
	eUnknown := createPlanned(slug+"-unknown", "2026-12-05", "2026-12-05", []string{ProfileTagPrefix + "no-such-" + slug, slug})
	eCancel := createPlanned(slug+"-cancel", "2026-12-10", "2026-12-10", []string{ProfileTagPrefix + "default", slug})

	q := gen.New(pool)
	profs, err := q.ListAllProfileNames(ctx)
	must(t, err)
	var defaultProfID int64
	for _, p := range profs {
		if p.Name == "default" {
			defaultProfID = p.ID
		}
	}
	if defaultProfID == 0 {
		t.Fatal("seeded 'default' profile not found")
	}

	poller := &PlanningPoller{Client: c, Pool: pool, PlanningAssetID: planningID}

	// Pass 1: pull Not Started engagements into schedules.
	st, err := poller.PollOnce(ctx)
	must(t, err)
	t.Logf("pass 1: %+v", st)

	warsaw, err := time.LoadLocation(DefaultScheduleTimezone)
	must(t, err)
	wantStart := time.Date(2026, 12, 1, 0, 0, 0, 0, warsaw)
	wantEnd := time.Date(2026, 12, 4, 0, 0, 0, 0, warsaw)

	sValid, err := q.GetScheduleByDojoEngagement(ctx, &eValid.ID)
	must(t, err)
	if sValid.Source != "dojo" || sValid.ProfileID != defaultProfID || !sValid.Enabled || sValid.Cron.Valid || sValid.Timezone != DefaultScheduleTimezone {
		t.Fatalf("valid schedule = %+v", sValid)
	}
	if sValid.WindowStart == nil || sValid.WindowEnd == nil ||
		!sValid.WindowStart.Equal(wantStart) || !sValid.WindowEnd.Equal(wantEnd) {
		t.Fatalf("valid window = %v .. %v, want %v .. %v", sValid.WindowStart, sValid.WindowEnd, wantStart, wantEnd)
	}

	// Unknown profile engagement was skipped (no schedule row).
	if _, err := q.GetScheduleByDojoEngagement(ctx, &eUnknown.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unknown profile schedule err = %v, want ErrNoRows", err)
	}

	// Cancelable engagement exists and is enabled.
	sCancel, err := q.GetScheduleByDojoEngagement(ctx, &eCancel.ID)
	must(t, err)
	if !sCancel.Enabled {
		t.Fatalf("cancelable schedule should start enabled: %+v", sCancel)
	}

	// Pass 2: cancel eCancel in Dojo (no run yet) → schedule gets disabled.
	must(t, c.SetEngagementStatus(ctx, eCancel.ID, "Cancelled"))
	st, err = poller.PollOnce(ctx)
	must(t, err)
	t.Logf("pass 2 (after cancel): %+v", st)
	sCancel, err = q.GetScheduleByDojoEngagement(ctx, &eCancel.ID)
	must(t, err)
	if sCancel.Enabled {
		t.Fatalf("cancelled engagement schedule should be disabled: %+v", sCancel)
	}

	// Pass 3: insert a run for sValid with status='running' → Dojo moves to In Progress.
	var runID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO runs (profile_id, schedule_id, status) VALUES ($1, $2, 'running') RETURNING id`,
		defaultProfID, sValid.ID,
	).Scan(&runID)
	must(t, err)

	st, err = poller.PollOnce(ctx)
	must(t, err)
	t.Logf("pass 3 (running): %+v", st)
	if st.StatusUpdated != 1 || st.StatusFailed != 0 {
		t.Fatalf("pass 3 status stats = %+v", st)
	}
	gotEng, err := c.GetEngagement(ctx, eValid.ID)
	must(t, err)
	if gotEng.Status != EngagementInProgress {
		t.Fatalf("dojo engagement status = %q, want %q", gotEng.Status, EngagementInProgress)
	}
	// Schedule with a run stays enabled even though engagement is no longer Not Started.
	sValid, err = q.GetScheduleByDojoEngagement(ctx, &eValid.ID)
	must(t, err)
	if !sValid.Enabled {
		t.Fatalf("schedule with run should stay enabled: %+v", sValid)
	}

	// Pass 4: unchanged running status → no redundant PATCH.
	st, err = poller.PollOnce(ctx)
	must(t, err)
	if st.StatusUpdated != 0 {
		t.Fatalf("pass 4 (idempotent running): StatusUpdated = %d, want 0", st.StatusUpdated)
	}

	// Pass 5: suspended still maps to In Progress → no redundant PATCH.
	_, err = pool.Exec(ctx, `UPDATE runs SET status = 'suspended' WHERE id = $1`, runID)
	must(t, err)
	st, err = poller.PollOnce(ctx)
	must(t, err)
	if st.StatusUpdated != 0 {
		t.Fatalf("pass 5 (suspended): StatusUpdated = %d, want 0", st.StatusUpdated)
	}

	// Pass 6: run flips to done → Dojo moves to Completed.
	_, err = pool.Exec(ctx, `UPDATE runs SET status = 'done' WHERE id = $1`, runID)
	must(t, err)
	st, err = poller.PollOnce(ctx)
	must(t, err)
	t.Logf("pass 6 (done): %+v", st)
	if st.StatusUpdated != 1 || st.StatusFailed != 0 {
		t.Fatalf("pass 6 status stats = %+v", st)
	}
	gotEng, err = c.GetEngagement(ctx, eValid.ID)
	must(t, err)
	if gotEng.Status != EngagementCompleted {
		t.Fatalf("dojo engagement status = %q, want %q", gotEng.Status, EngagementCompleted)
	}

	// Pass 7: done again → idempotent, no PATCH.
	st, err = poller.PollOnce(ctx)
	must(t, err)
	if st.StatusUpdated != 0 {
		t.Fatalf("pass 7 (idempotent done): StatusUpdated = %d, want 0", st.StatusUpdated)
	}
}
