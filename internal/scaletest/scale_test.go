//go:build scaletest

package scaletest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/httpapi"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/targets"
)

const scaleEncKey = "scale-test-encryption-key-0123456789abcdef"

// freshScaleDB creates an isolated throwaway database on the worktree's local
// Postgres server (RAVEN_DATABASE_URL from scripts/wt-env.sh) and drops it on
// cleanup. It refuses non-loopback hosts or the shared "raven"/"asi" database name.
func freshScaleDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("RAVEN_DATABASE_URL")
	if base == "" {
		t.Fatal("RAVEN_DATABASE_URL not set (run scripts/wt-env.sh first)")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse RAVEN_DATABASE_URL: %v", err)
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		t.Fatalf("refusing scale test against non-loopback DB host %q", host)
	}
	baseDB := strings.TrimPrefix(u.Path, "/")
	if baseDB == "" || baseDB == "raven" || baseDB == "asi" {
		t.Fatalf("refusing scale test when RAVEN_DATABASE_URL points to %q; run scripts/wt-env.sh for a per-worktree DB", baseDB)
	}

	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect Postgres (%s): %v", host, err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "raven_scale_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create scale DB %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u.Path = "/" + name
	pool, err := db.Open(ctx, u.String(), scaleEncKey)
	if err != nil {
		t.Fatalf("open scale DB %s: %v", name, err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate scale DB %s: %v", name, err)
	}
	return pool
}

// TestFakeScannersParseCleanly verifies that our synthetic nmap XML, httpx JSONL,
// and nuclei JSONL are accepted by the real production parsers (used by Dojo push
// and change detection).
func TestFakeScannersParseCleanly(t *testing.T) {
	w := &World{}
	ips := make([]netip.Addr, 0, 64)
	cur := netip.MustParseAddr("10.64.0.0")
	for range 64 {
		ips = append(ips, cur)
		cur = cur.Next()
	}
	nmapRes, err := (&FakeNmap{World: w}).Run(context.Background(), scanner.Input{IPs: ips}, scanner.Options{Ports: "22,80,443,5432,8080", MaxRate: 300})
	if err != nil {
		t.Fatal(err)
	}
	parsedNmap, err := nmap.Parse(nmapRes.Raw)
	if err != nil {
		t.Fatalf("nmap.Parse rejected synthetic XML: %v", err)
	}
	if len(parsedNmap.Observations) == 0 {
		t.Fatal("nmap.Parse returned 0 observations")
	}

	webIn := httpx.BuildInput(scanner.Input{IPs: ips}, nmapRes.Observations)
	httpRes, err := (&FakeHTTPX{World: w}).Run(context.Background(), webIn, scanner.Options{RateLimit: 50})
	if err != nil {
		t.Fatal(err)
	}
	parsedHTTP, err := httpx.Parse(httpRes.Raw)
	if err != nil {
		t.Fatalf("httpx.Parse rejected synthetic JSONL: %v", err)
	}
	if len(parsedHTTP.Observations) == 0 {
		t.Fatal("httpx.Parse returned 0 observations")
	}

	nucIn := nuclei.BuildInput(ips, httpRes.Observations)
	nucRes, err := (&FakeNuclei{World: w}).Run(context.Background(), nucIn, scanner.Options{RateLimit: 50, Tags: []string{"tech", "panel"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nuclei.Parse(nucRes.Raw); err != nil {
		t.Fatalf("nuclei.Parse rejected synthetic JSONL: %v", err)
	}
}

func TestScale16k(t *testing.T) {
	runScaleScenario(t, "10.64.0.0/18", 16384, false)
}

func TestScale65k(t *testing.T) {
	runScaleScenario(t, "10.65.0.0/16", 65536, true)
}

type memSnapshot struct {
	HeapAllocMB  float64
	HeapInuseMB  float64
	SysMB        float64
	TotalAllocMB float64
}

func sampleMem() memSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	const mb = 1024 * 1024
	return memSnapshot{
		HeapAllocMB:  float64(m.HeapAlloc) / mb,
		HeapInuseMB:  float64(m.HeapInuse) / mb,
		SysMB:        float64(m.Sys) / mb,
		TotalAllocMB: float64(m.TotalAlloc) / mb,
	}
}

type memTracker struct {
	stop chan struct{}
	done chan memSnapshot
}

func startMemTracker() *memTracker {
	mt := &memTracker{stop: make(chan struct{}), done: make(chan memSnapshot, 1)}
	go func() {
		var peak memSnapshot
		tk := time.NewTicker(100 * time.Millisecond)
		defer tk.Stop()
		record := func() {
			s := sampleMem()
			if s.HeapAllocMB > peak.HeapAllocMB {
				peak.HeapAllocMB = s.HeapAllocMB
			}
			if s.HeapInuseMB > peak.HeapInuseMB {
				peak.HeapInuseMB = s.HeapInuseMB
			}
			if s.SysMB > peak.SysMB {
				peak.SysMB = s.SysMB
			}
			peak.TotalAllocMB = s.TotalAllocMB
		}
		record()
		for {
			select {
			case <-tk.C:
				record()
			case <-mt.stop:
				record()
				mt.done <- peak
				return
			}
		}
	}()
	return mt
}

func (mt *memTracker) Stop() memSnapshot {
	close(mt.stop)
	return <-mt.done
}

func runScaleScenario(t *testing.T, cidr string, wantHosts int32, assertAPI bool) {
	t.Helper()
	// Quiet noisy per-batch info logs during 256-batch runs; keep warnings/errors.
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	pool := freshScaleDB(t)
	ctx := context.Background()
	q := gen.New(pool)

	// Belt-and-suspenders: fake Dojo runs on loopback only.
	fakeDojo := NewFakeDojo()
	t.Cleanup(fakeDojo.Close)
	dojoURL, err := url.Parse(fakeDojo.Server.URL)
	if err != nil || (dojoURL.Hostname() != "127.0.0.1" && dojoURL.Hostname() != "::1") {
		t.Fatalf("fake Dojo bound to non-loopback address %q", fakeDojo.Server.URL)
	}

	// Verify loopback-only connectivity for the Dojo HTTP client.
	dojoClient := dojo.NewHTTPClientOpts(fakeDojo.Server.URL, "scale-token", dojo.Options{
		Concurrency: 8,
		MaxAttempts: 2,
		Timeout:     30 * time.Second,
	})
	org, err := dojoClient.GetOrCreateOrganization(ctx, "RAVEN")
	if err != nil {
		t.Fatalf("fake dojo org: %v", err)
	}

	pushSvc, err := dojo.NewPushService(pool, map[string]dojo.ParseFunc{
		"nmap": nmap.Parse, "httpx": httpx.Parse, "nuclei": nuclei.Parse,
	})
	if err != nil {
		t.Fatalf("push service: %v", err)
	}
	pushSvc.SetPusher(&dojo.Pusher{Client: dojoClient, OrganizationID: org.ID, Parallel: dojoClient.Concurrency()})
	if err := pushSvc.Start(ctx); err != nil {
		t.Fatalf("start push service: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = pushSvc.Shutdown(c)
	})

	world := &World{
		// Scaled-down realistic delays: ~256 IPs take ~35ms so batch duration_ms > 0
		// and S5 adaptive batching computes real throughput for Run 2.
		NmapPerIP:    50 * time.Microsecond,
		HTTPXPerURL:  20 * time.Microsecond,
		NucleiPerURL: 10 * time.Microsecond,
	}

	pipe, err := pipeline.New(pool, pipeline.Config{
		Scanner:  &FakeNmap{World: world},
		HTTPX:    &FakeHTTPX{World: world},
		Nuclei:   &FakeNuclei{World: world},
		Resolver: LocalOnlyResolver{},
		Hook:     pushSvc,
		Workers:  2,
	})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	if err := pipe.Start(ctx); err != nil {
		t.Fatalf("start pipeline: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = pipe.Shutdown(c)
	})

	// Seed profile, scope, and CIDR target.
	var profileID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO profiles (name, ports, nmap_max_rate, nuclei_rate, nuclei_tags, miss_threshold, target_batch_seconds)
		VALUES ('scale', '22,80,443,5432,6379,8080', 1000, 100, ARRAY['tech','panel'], 2, 600)
		RETURNING id`).Scan(&profileID); err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scope_entries (kind, value, list, profile_id) VALUES ('cidr', $1, 'include', $2)`, cidr, profileID); err != nil {
		t.Fatalf("insert scope: %v", err)
	}
	entry, err := targets.NewEntry(cidr, targets.KindCIDR, []string{"scale"}, "scale test")
	if err != nil {
		t.Fatalf("new target entry: %v", err)
	}
	if _, err := (&targets.Store{Pool: pool}).AddTargets(ctx, nil, "manual", []targets.Entry{entry}); err != nil {
		t.Fatalf("add target: %v", err)
	}

	// ── Run 1 (baseline) ──
	t.Logf("=== %s (%d IPs): Run 1 (baseline) ===", cidr, wantHosts)
	mt1 := startMemTracker()
	tPlan1 := time.Now()
	r1, err := pipe.StartRun(ctx, nil, profileID)
	plan1Dur := time.Since(tPlan1)
	if err != nil {
		t.Fatalf("run 1 StartRun: %v", err)
	}
	if r1.HostsTotal != wantHosts {
		t.Fatalf("run 1 hosts_total = %d, want %d", r1.HostsTotal, wantHosts)
	}

	tExec1 := time.Now()
	r1 = waitRunDone(t, pipe, r1.ID, 15*time.Minute)
	exec1Dur := time.Since(tExec1)
	if r1.Status != "done" {
		t.Fatalf("run 1 ended with status %q (batches done=%d failed=%d)", r1.Status, r1.BatchesDone, r1.BatchesFailed)
	}

	tPush1 := time.Now()
	waitDojoDrain(t, pool, 15*time.Minute)
	push1Drain := time.Since(tPush1)
	peak1 := mt1.Stop()

	dojo1 := fakeDojo.Stats()
	t.Logf("Run 1: plan=%s exec(scan+ingest+lifecycle)=%s dojo_drain_after_scan=%s total=%s batches=%d hosts_up=%d",
		plan1Dur.Round(time.Millisecond), exec1Dur.Round(time.Millisecond), push1Drain.Round(time.Millisecond),
		(plan1Dur + exec1Dur + push1Drain).Round(time.Millisecond), r1.BatchesTotal, r1.HostsUp)
	t.Logf("Run 1 stats: %s", string(r1.Stats))
	t.Logf("Run 1 mem: peak_heap_alloc=%.1fMB peak_heap_inuse=%.1fMB peak_sys=%.1fMB total_alloc=%.1fMB",
		peak1.HeapAllocMB, peak1.HeapInuseMB, peak1.SysMB, peak1.TotalAllocMB)
	t.Logf("Run 1 Dojo: reqs=%d assets=%d engs=%d tests=%d reimports=%d by_type=%v uploaded=%.1fMB",
		dojo1.TotalRequests, dojo1.AssetsCreated, dojo1.EngagementsCreated, dojo1.TestsCreated,
		dojo1.ReimportCalls, dojo1.ReimportByType, float64(dojo1.BytesUploaded)/(1024*1024))
	logDBSize(t, pool, "After Run 1")

	// ── Run 2 (~5% changed hosts: lifecycle re-probe + change detection + adaptive batching) ──
	t.Logf("=== %s (%d IPs): Run 2 (~5%% changed) ===", cidr, wantHosts)
	world.Generation.Store(1)
	mt2 := startMemTracker()
	tPlan2 := time.Now()
	r2, err := pipe.StartRun(ctx, nil, profileID)
	plan2Dur := time.Since(tPlan2)
	if err != nil {
		t.Fatalf("run 2 StartRun: %v", err)
	}
	tExec2 := time.Now()
	r2 = waitRunDone(t, pipe, r2.ID, 15*time.Minute)
	exec2Dur := time.Since(tExec2)
	if r2.Status != "done" {
		t.Fatalf("run 2 ended with status %q (batches done=%d failed=%d)", r2.Status, r2.BatchesDone, r2.BatchesFailed)
	}

	tPush2 := time.Now()
	waitDojoDrain(t, pool, 15*time.Minute)
	push2Drain := time.Since(tPush2)
	peak2 := mt2.Stop()

	dojo2 := fakeDojo.Stats()
	t.Logf("Run 2: plan=%s exec(scan+ingest+reprobe+lifecycle)=%s dojo_drain_after_scan=%s total=%s batches=%d hosts_up=%d reprobe_calls=%d",
		plan2Dur.Round(time.Millisecond), exec2Dur.Round(time.Millisecond), push2Drain.Round(time.Millisecond),
		(plan2Dur + exec2Dur + push2Drain).Round(time.Millisecond), r2.BatchesTotal, r2.HostsUp, world.ReprobeCalls.Load())
	t.Logf("Run 2 stats: %s", string(r2.Stats))
	t.Logf("Run 2 mem: peak_heap_alloc=%.1fMB peak_heap_inuse=%.1fMB peak_sys=%.1fMB total_alloc=%.1fMB",
		peak2.HeapAllocMB, peak2.HeapInuseMB, peak2.SysMB, peak2.TotalAllocMB)
	t.Logf("Run 2 Dojo cumulative: reqs=%d assets=%d reimports=%d by_type=%v uploaded=%.1fMB",
		dojo2.TotalRequests, dojo2.AssetsCreated, dojo2.ReimportCalls, dojo2.ReimportByType,
		float64(dojo2.BytesUploaded)/(1024*1024))
	logDBSize(t, pool, "After Run 2")

	// Verify S5 adaptive batching actually ran on Run 2.
	var r2Stats struct {
		BatchSizing string `json:"batch_sizing"`
		BatchSize   int    `json:"batch_size"`
		Reprobed    int    `json:"reprobed"`
		Recovered   int    `json:"recovered"`
		Unstable    int    `json:"became_unstable"`
	}
	if err := json.Unmarshal(r2.Stats, &r2Stats); err != nil {
		t.Fatalf("parse run 2 stats: %v", err)
	}
	if r2Stats.BatchSizing != "adaptive" {
		t.Errorf("Run 2 batch_sizing = %q, want adaptive", r2Stats.BatchSizing)
	}
	if r2Stats.Reprobed == 0 || r2Stats.Unstable == 0 {
		t.Errorf("Run 2 lifecycle did not exercise re-probe/unstable: %+v", r2Stats)
	}

	// ANALYZE so Postgres planner stats reflect the newly populated tables
	// (autovacuum may not have finished immediately after a bulk test run).
	if _, err := pool.Exec(ctx, "ANALYZE"); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	// ── Measure HTTP API latencies against the real router ──
	authSvc := auth.NewService(q, time.Hour)
	if err := authSvc.EnsureBootstrapAdmin(ctx, "admin", "scale-admin-pass-123"); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	token, _, err := authSvc.Login(ctx, "admin", "scale-admin-pass-123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	cookie := &http.Cookie{Name: auth.CookieName, Value: token}

	router := httpapi.NewRouter(httpapi.Deps{
		Pool: pool, Queries: q, Auth: authSvc, Pipeline: pipe, Dojo: &dojo.Lazy{}, DojoPush: pushSvc,
	})

	// Pick one active IP and one /24 sub-prefix from our CIDR for filtered queries.
	var sampleIP string
	if err := pool.QueryRow(ctx, `SELECT host(ip) FROM hosts WHERE state = 'active' ORDER BY ip LIMIT 1`).Scan(&sampleIP); err != nil {
		t.Fatalf("pick sample IP: %v", err)
	}
	prefix := netip.MustParsePrefix(cidr)
	sub24 := netip.PrefixFrom(prefix.Addr(), 24).String()
	hostQ := fmt.Sprintf("srv-%d-%d-10-", prefix.Addr().As4()[0], prefix.Addr().As4()[1])

	type apiCheck struct {
		name     string
		path     string
		maxLimit time.Duration // 0 = measure only
	}
	budget := time.Duration(0)
	if assertAPI {
		budget = time.Second
	}
	checks := []apiCheck{
		{"hosts page 1", "/api/hosts?limit=50&offset=0", budget},
		{"hosts deep page", "/api/hosts?limit=50&offset=5000", budget},
		{"hosts state=active", "/api/hosts?state=active&limit=50", budget},
		{"hosts state=unstable", "/api/hosts?state=unstable&limit=50", budget},
		{"hosts port=443", "/api/hosts?port=443&limit=50", budget},
		{"hosts tech=Nginx:1.24.0", "/api/hosts?tech=Nginx:1.24.0&limit=50", budget},
		{"hosts q=cidr/24", "/api/hosts?q=" + url.QueryEscape(sub24) + "&limit=50", budget},
		{"hosts q=hostname", "/api/hosts?q=" + url.QueryEscape(hostQ) + "&limit=50", budget},
		{"host detail", "/api/hosts/" + sampleIP, budget},
		{"dashboard", "/api/dashboard", budget},
		{"changes default", "/api/changes", budget},
		{"changes host timeline", "/api/changes/hosts/" + sampleIP, budget},
	}

	t.Logf("=== %s: API latencies ===", cidr)
	for _, c := range checks {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		start := time.Now()
		router.ServeHTTP(rec, req)
		dur := time.Since(start)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s (%s): status=%d body=%s", c.name, c.path, rec.Code, rec.Body.String())
		}
		t.Logf("  %-24s %8s  (%d bytes)", c.name, dur.Round(100*time.Microsecond), rec.Body.Len())
		if c.maxLimit > 0 && dur > c.maxLimit {
			t.Errorf("%s exceeded latency target %s: took %s", c.name, c.maxLimit, dur)
		}
	}

	// Verify /api/changes reported real diffs from the ~5% Run 2 perturbation.
	req := httptest.NewRequest(http.MethodGet, "/api/changes", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var ch struct {
		Summary struct {
			HostsNew        int `json:"hosts_new"`
			HostsGone       int `json:"hosts_gone"`
			ServicesNew     int `json:"services_new"`
			ServicesGone    int `json:"services_gone"`
			ServicesChanged int `json:"services_changed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decode changes: %v", err)
	}
	t.Logf("Changes summary: %+v", ch.Summary)
	if ch.Summary.HostsNew == 0 || ch.Summary.HostsGone == 0 || ch.Summary.ServicesChanged == 0 {
		t.Errorf("expected non-zero diffs in changes summary, got %+v", ch.Summary)
	}
}

func waitRunDone(t *testing.T, s *pipeline.Service, id int64, timeout time.Duration) pipeline.Run {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r, err := s.GetRun(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != "pending" && r.Status != "running" {
			return r
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("run %d timed out after %s", id, timeout)
	return pipeline.Run{}
}

func waitDojoDrain(t *testing.T, pool *pgxpool.Pool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var pending int64
		err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM river_job
			WHERE queue = 'dojo' AND state NOT IN ('completed', 'discarded', 'cancelled')`).Scan(&pending)
		if err != nil {
			t.Fatalf("poll dojo queue: %v", err)
		}
		if pending == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("dojo push queue did not drain within %s", timeout)
}

func logDBSize(t *testing.T, pool *pgxpool.Pool, label string) {
	t.Helper()
	ctx := context.Background()
	var totalBytes int64
	if err := pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&totalBytes); err != nil {
		t.Fatalf("pg_database_size: %v", err)
	}
	rows, err := pool.Query(ctx, `
		SELECT relname, pg_total_relation_size(relid) AS sz, n_live_tup
		FROM pg_stat_user_tables
		ORDER BY sz DESC LIMIT 8`)
	if err != nil {
		t.Fatalf("table sizes: %v", err)
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var name string
		var sz, live int64
		if err := rows.Scan(&name, &sz, &live); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, fmt.Sprintf("%s=%.1fMB(%d)", name, float64(sz)/(1024*1024), live))
	}
	t.Logf("%s DB size: %.1fMB  top tables: %s", label, float64(totalBytes)/(1024*1024), strings.Join(parts, ", "))
}

// Sanity check that our LocalOnlyResolver implements net.Resolver-like lookup
// without touching the network.
var _ targets.Resolver = LocalOnlyResolver{}
var _ = net.IPv4len
