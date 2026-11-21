//go:build integration

package dojo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

// TestPlanningSkipsAggressiveProfile verifies that D5 never creates a schedule
// for an aggressive profile and records an audit_log entry with aggressive:true.
func TestPlanningSkipsAggressiveProfile(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	var aggProfID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO profiles (name, ports, stages) VALUES ('agg-lab', '80,443', ARRAY['nmap','httpx','nikto']) RETURNING id`,
	).Scan(&aggProfID); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/engagements/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"count":2,"results":[
			{"id":501,"name":"Safe planned","product":9,"status":"Not Started","target_start":"2026-12-01","target_end":"2026-12-02","tags":["raven-profile:default"]},
			{"id":502,"name":"Aggressive planned","product":9,"status":"Not Started","target_start":"2026-12-01","target_end":"2026-12-02","tags":["raven-profile:agg-lab"]}
		]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	poller := &PlanningPoller{Client: testClient(srv.URL, Options{}), Pool: pool, PlanningAssetID: 9}

	st, err := poller.PollOnce(ctx)
	must(t, err)
	if st.Found != 2 || st.Upserted != 1 || st.Skipped != 1 || st.SkippedAggressive != 1 {
		t.Fatalf("stats = %+v, want found=2 upserted=1 skipped=1 skippedAggressive=1", st)
	}

	q := gen.New(pool)
	safeID, aggID := int64(501), int64(502)
	if _, err := q.GetScheduleByDojoEngagement(ctx, &safeID); err != nil {
		t.Fatalf("safe engagement schedule missing: %v", err)
	}
	if _, err := q.GetScheduleByDojoEngagement(ctx, &aggID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("aggressive engagement should not create a schedule, got err=%v", err)
	}

	var diffRaw []byte
	if err := pool.QueryRow(ctx,
		`SELECT diff FROM audit_log WHERE action = 'dojo.planning.skip_aggressive' AND object_id = '502'`,
	).Scan(&diffRaw); err != nil {
		t.Fatalf("expected audit_log row for skipped aggressive engagement: %v", err)
	}
	var diff map[string]any
	if err := json.Unmarshal(diffRaw, &diff); err != nil {
		t.Fatalf("decode audit diff %s: %v", diffRaw, err)
	}
	if v, ok := diff["aggressive"].(bool); !ok || !v {
		t.Fatalf("audit diff = %s, want aggressive:true", diffRaw)
	}
}
