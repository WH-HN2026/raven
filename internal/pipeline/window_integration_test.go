//go:build integration

package pipeline

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scheduler"
)

type windowScanner struct {
	slow, down netip.Addr
	cancelled  chan error
	once       sync.Once
}

func (*windowScanner) Name() string         { return "nmap" }
func (*windowScanner) DojoScanType() string { return "Nmap Scan" }

func (f *windowScanner) Run(ctx context.Context, in scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	if in.IPs[0] == f.slow {
		var interrupted bool
		f.once.Do(func() {
			<-ctx.Done()
			f.cancelled <- ctx.Err()
			interrupted = true
		})
		if interrupted {
			return nil, ctx.Err()
		}
	}
	return &scanner.Result{
		Raw:          []byte("<nmaprun/>"),
		Observations: []scanner.Observation{{Kind: scanner.ObsHost, IP: in.IPs[0], Up: in.IPs[0] != f.down}},
	}, nil
}

type windowFinishedHook struct{ nopHook }

func (windowFinishedHook) AfterRunFinished(ctx context.Context, tx pgx.Tx, runID int64) error {
	_, err := tx.Exec(ctx, `UPDATE runs SET stats = stats || jsonb_build_object(
		'test_finish_hook_calls', COALESCE((stats->>'test_finish_hook_calls')::int, 0) + 1
	) WHERE id = $1`, runID)
	return err
}

func setupWindowPipeline(t *testing.T, pool *pgxpool.Pool, cfg Config) (*Service, scheduler.Scheduler, int64) {
	t.Helper()
	ctx := context.Background()
	cfg.BatchSize, cfg.Workers = 1, 1
	s, err := New(pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})

	var profileID int64
	if err := pool.QueryRow(ctx, "SELECT id FROM profiles WHERE name = 'default'").Scan(&profileID); err != nil {
		t.Fatal(err)
	}
	// Only the fake scanner receives these addresses.
	if _, err := pool.Exec(ctx, `INSERT INTO scope_entries (kind, value, list, profile_id)
		VALUES ('cidr', '172.30.0.16/28', 'include', $1)`, profileID); err != nil {
		t.Fatal(err)
	}
	return s, scheduler.Scheduler{Queries: gen.New(pool), Runs: s}, profileID
}

func TestScheduledRunResumesPendingBatches(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	scan := &windowScanner{
		slow:      netip.MustParseAddr("172.30.0.18"),
		down:      netip.MustParseAddr("172.30.0.19"),
		cancelled: make(chan error, 1),
	}
	service, ticker, profileID := setupWindowPipeline(t, pool, Config{Scanner: scan, Hook: windowFinishedHook{}})
	// The last batch will record the third miss for a previously seen host.
	if _, err := pool.Exec(ctx, "INSERT INTO hosts (ip, state, miss_count) VALUES ($1, 'unstable', 2)", scan.down); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `WITH previous AS (
		INSERT INTO runs (profile_id, status) VALUES ($1, 'done') RETURNING id
	) INSERT INTO run_observations (run_id, ip, up) SELECT id, $2, true FROM previous`, profileID, scan.down); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO targets (kind, value, source) VALUES
		('ip', '172.30.0.17', 'manual'), ('ip', '172.30.0.18', 'manual'), ('ip', '172.30.0.19', 'manual')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO schedules (profile_id, source, cron, timezone, window_start, window_end, created_at)
		VALUES ($1, 'ui', '* * * * *', 'UTC', $2, $3, $4) RETURNING id`,
		profileID, now.Add(-2*time.Minute), now.Add(3*time.Second), now.Add(-3*time.Minute)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := ticker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	run, err := ticker.Queries.GetLatestScheduledRun(ctx, &id)
	if err != nil {
		t.Fatal(err)
	}
	result := waitRun(t, service, run.ID)
	if result.Status != "suspended" || result.ScheduleID == nil || *result.ScheduleID != id || result.BatchesDone != 1 {
		t.Fatalf("suspended run = %+v", result)
	}
	select {
	case err := <-scan.cancelled:
		if err != context.DeadlineExceeded {
			t.Fatalf("scanner cancelled with %v", err)
		}
	default:
		t.Fatal("slow scanner missed the window deadline")
	}
	batches, err := service.ListBatches(ctx, run.ID)
	if err != nil || len(batches) != 3 || batches[0].Status != "done" || batches[1].Status != "pending" || batches[2].Status != "pending" {
		t.Fatalf("batches after deadline = %+v, %v", batches, err)
	}
	if n := count(t, pool, "SELECT count(*) FROM runs WHERE id = $1 AND stats ? 'test_finish_hook_calls'", run.ID); n != 0 {
		t.Fatal("finish hook ran during suspension")
	}
	if err := ticker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if result, err := service.GetRun(ctx, run.ID); err != nil || result.Status != "suspended" {
		t.Fatalf("run resumed outside the window: %+v, %v", result, err)
	}

	// Move the next daily opening to now to exercise the real queue and
	// deadlines without waiting a day in the integration suite.
	now = time.Now().UTC()
	if _, err := pool.Exec(ctx, "UPDATE schedules SET window_start = $2, window_end = $3 WHERE id = $1",
		id, now.Add(-time.Second), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := ticker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	result = waitRun(t, service, run.ID)
	if result.Status != "done" || result.BatchesDone != 3 {
		t.Fatalf("resumed run = %+v", result)
	}
	batches, err = service.ListBatches(ctx, run.ID)
	if err != nil || len(batches) != 3 || batches[0].Attempts != 1 || batches[1].Attempts != 2 || batches[2].Attempts != 1 {
		t.Fatalf("attempts after resumption = %+v, %v", batches, err)
	}
	if n := count(t, pool, "SELECT count(*) FROM runs WHERE id = $1 AND stats->>'test_finish_hook_calls' = '1' AND stats->>'became_inactive' = '1'", run.ID); n != 1 {
		t.Fatal("resumed run did not record exactly one finish hook call for the inactive host")
	}
	if n := count(t, pool, "SELECT count(*) FROM runs WHERE schedule_id = $1", id); n != 1 {
		t.Fatalf("scheduled runs = %d, want 1", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM audit_log WHERE action IN ('runs.suspend', 'runs.resume') AND user_id IS NULL"); n != 2 {
		t.Fatalf("window transition audit entries = %d, want 2", n)
	}
}

func TestDojoScheduleStartsExactlyOnce(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	_, ticker, profileID := setupWindowPipeline(t, pool, Config{Scanner: &windowScanner{}})
	engagementID := int64(123)
	now := time.Now()
	start, end := now.Add(-time.Minute), now.Add(time.Minute)
	schedule, err := ticker.Queries.UpsertDojoSchedule(ctx, gen.UpsertDojoScheduleParams{
		ProfileID: profileID, DojoEngagementID: &engagementID,
		WindowStart: &start, WindowEnd: &end, Timezone: "Europe/Warsaw",
	})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 4)
	for range cap(results) {
		go func() { results <- ticker.RunOnce(ctx) }()
	}
	for range cap(results) {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := ticker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	run, err := ticker.Queries.GetLatestScheduledRun(ctx, &schedule.ID)
	if err != nil || run.ScheduleID == nil || *run.ScheduleID != schedule.ID || run.Status != "done" {
		t.Fatalf("Dojo run = %+v, %v", run, err)
	}
	if n := count(t, pool, "SELECT count(*) FROM runs WHERE schedule_id = $1", schedule.ID); n != 1 {
		t.Fatalf("Dojo scheduled runs = %d, want 1", n)
	}
}
