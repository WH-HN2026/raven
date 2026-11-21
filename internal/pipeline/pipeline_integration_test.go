//go:build integration

package pipeline

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/targets"
)

// fakeScanner replays the S2 fixture (real nmap output), restricted to the
// batch's IPs. drop removes services ("ip:port"); block makes Run wait
// until it's closed or ctx is cancelled.
type fakeScanner struct {
	raw       []byte
	mu        sync.Mutex
	drop      map[string]bool
	block     chan struct{}
	cancelled atomic.Int32
	calls     atomic.Int32
}

func (f *fakeScanner) Name() string         { return "nmap" }
func (f *fakeScanner) DojoScanType() string { return "Nmap Scan" }

func (f *fakeScanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	f.calls.Add(1)
	if opt.Ports == "" || opt.MaxRate <= 0 {
		return nil, errors.New("fake: options not passed from the profile")
	}
	f.mu.Lock()
	block, drop := f.block, f.drop
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			f.cancelled.Add(1)
			return nil, ctx.Err()
		}
	}
	res, err := nmap.Parse(f.raw)
	if err != nil {
		return nil, err
	}
	var obs []scanner.Observation
	for _, o := range res.Observations {
		if !slices.Contains(in.IPs, o.IP) {
			continue
		}
		if o.Kind == scanner.ObsService && drop[netip.AddrPortFrom(o.IP, o.Port).String()] {
			continue
		}
		obs = append(obs, o)
	}
	res.Observations = obs
	return res, nil
}

func (f *fakeScanner) set(block chan struct{}, drop map[string]bool) {
	f.mu.Lock()
	f.block, f.drop = block, drop
	f.mu.Unlock()
}

// replayHTTPX presents the real fixture's HTTP response as coming from the
// matching nmap fixture service. No network probes are used by this test.
type replayHTTPX struct {
	raw   []byte
	calls atomic.Int32
}

func (*replayHTTPX) Name() string         { return "httpx" }
func (*replayHTTPX) DojoScanType() string { return "httpx Scan" }

func (f *replayHTTPX) Run(_ context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	f.calls.Add(1)
	if opt.RateLimit != 25 || len(in.IPs) != 1 {
		return nil, errors.New("httpx: expected the per-worker profile rate and only an HTTP host")
	}
	if !slices.Contains(in.URLs, "https://172.31.250.10:443") {
		return &scanner.Result{}, nil
	}
	return httpx.Parse(f.raw)
}

func waitRun(t *testing.T, s *Service, id int64) Run {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		r, err := s.GetRun(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if !isActive(r.Status) {
			return r
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("run %d did not finish", id)
	return Run{}
}

func waitBatchesRunning(t *testing.T, s *Service, id int64, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		bs, err := s.ListBatches(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		running := 0
		for _, b := range bs {
			if b.Status == "running" {
				running++
			}
		}
		if running >= n {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("run %d: %d batches never running", id, n)
}

type hostRow struct {
	FirstSeen, LastSeen time.Time
	State, Owner, Crit  string
	Notes               string
	Tags, Hostnames     []string
	Overrides           string
}

func getHost(t *testing.T, pool *pgxpool.Pool, ip string) hostRow {
	t.Helper()
	var h hostRow
	err := pool.QueryRow(context.Background(), `SELECT first_seen, last_seen, state, owner, criticality,
		COALESCE(raven_dec(notes_enc), ''), user_tags, hostnames, overrides::text FROM hosts WHERE ip = $1`, ip).
		Scan(&h.FirstSeen, &h.LastSeen, &h.State, &h.Owner, &h.Crit, &h.Notes, &h.Tags, &h.Hostnames, &h.Overrides)
	if err != nil {
		t.Fatalf("host %s: %v", ip, err)
	}
	return h
}

func serviceState(t *testing.T, pool *pgxpool.Pool, ip string, port int) (state, overrides string) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT state, overrides::text FROM services WHERE ip = $1 AND port = $2 AND proto = 'tcp'`, ip, port).
		Scan(&state, &overrides)
	if err != nil {
		t.Fatalf("service %s:%d: %v", ip, port, err)
	}
	return state, overrides
}

func count(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// TestPipeline runs the whole pipeline (River jobs, ingest, completion)
// against a real DB with the S2 nmap fixture behind a fake scanner:
// two runs show first_seen kept, last_seen bumped, a port going 'gone'
// (only within the profile's ports), user-owned fields preserved and the
// artifact encrypted; then the one-active-run rule, stop, and an empty scan list.
func TestPipeline(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeScanner{raw: raw}
	httpRaw, err := os.ReadFile("../scanner/httpx/testdata/nginx.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	web, err := httpx.Parse(httpRaw)
	if err != nil {
		t.Fatal(err)
	}
	tlsFixture := web.PerIP(netip.MustParseAddr("172.21.0.2"))
	var tlsRaw []byte
	for _, line := range bytes.SplitAfter(tlsFixture, []byte("\n")) {
		if bytes.Contains(line, []byte(`"input":"https://raven-s7-nginx:443"`)) {
			tlsRaw = bytes.ReplaceAll(line, []byte("172.21.0.2"), []byte("172.31.250.10"))
		}
	}
	httpReplay := &replayHTTPX{raw: tlsRaw}
	s, err := New(pool, Config{Scanner: fake, HTTPX: httpReplay, Resolver: net.DefaultResolver, BatchSize: 2, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(c)
	})

	var pid int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'default'`).Scan(&pid); err != nil {
		t.Fatal("seeded default profile:", err)
	}
	var entries []targets.Entry
	for _, v := range []string{"172.31.250.10", "172.31.250.11", "172.31.250.12", "172.31.250.20"} {
		e, err := targets.NewEntry(v, "", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if _, err := (&targets.Store{Pool: pool}).AddTargets(ctx, nil, "manual", entries); err != nil {
		t.Fatal(err)
	}

	// ── run 1 ──
	r1, err := s.StartRun(ctx, nil, pid)
	if err != nil {
		t.Fatal(err)
	}
	if r1.HostsTotal != 4 || r1.BatchesTotal != 2 {
		t.Fatalf("run 1 = %+v, want 4 hosts in 2 batches", r1)
	}
	r1 = waitRun(t, s, r1.ID)
	if r1.Status != "done" || r1.HostsUp != 3 || r1.BatchesDone != 2 || r1.FinishedAt == nil {
		t.Fatalf("run 1 finished as %+v", r1)
	}
	t.Logf("run 1: %+v stats=%s", r1, r1.Stats)
	bs, err := s.ListBatches(ctx, r1.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bs {
		if b.Status != "done" || b.DurationMs == nil || b.Attempts != 1 || b.HostCount != 2 || b.FinishedAt == nil {
			t.Fatalf("batch %+v", b)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM hosts`); n != 3 {
		t.Fatalf("hosts = %d, want 3 (the down host is not inserted)", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM services WHERE state = 'open'`); n != 6 {
		t.Fatalf("open services = %d, want 6", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM run_observations WHERE run_id = $1 AND port IS NULL`, r1.ID); n != 4 {
		t.Fatalf("host-level observations = %d, want 4", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM run_observations WHERE run_id = $1 AND port IS NULL AND NOT up AND ip = '172.31.250.20'`, r1.ID); n != 1 {
		t.Fatal("down host has no down observation")
	}
	if n := count(t, pool, `SELECT count(*) FROM run_observations WHERE run_id = $1 AND port IS NOT NULL`, r1.ID); n != 6 {
		t.Fatalf("port observations = %d, want 6", n)
	}
	// artifacts: encrypted at rest, decryptable with the key
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'nmap'`, r1.ID); n != 2 {
		t.Fatalf("artifacts = %d, want 2 (one per batch)", n)
	}
	var enc []byte
	var dec string
	if err := pool.QueryRow(ctx, `SELECT content_enc, raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'nmap' LIMIT 1`, r1.ID).Scan(&enc, &dec); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("nmaprun")) || bytes.Contains(enc, []byte("172.31.250")) {
		t.Fatal("artifact content is stored in plaintext")
	}
	if dec != string(raw) {
		t.Fatal("decrypted artifact differs from the raw XML")
	}
	var banner, sshCPE, webCPE string
	if err := pool.QueryRow(ctx, `SELECT raven_dec(banner_enc), cpe FROM services WHERE ip = '172.31.250.11' AND port = 22`).Scan(&banner, &sshCPE); err != nil || banner == "" {
		t.Fatalf("ssh banner not stored encrypted: %q %v", banner, err)
	}
	if sshCPE != "openbsd:openssh:10.0" {
		t.Fatalf("172.31.250.11:22 cpe = %q, want openbsd:openssh:10.0", sshCPE)
	}
	if err := pool.QueryRow(ctx, `SELECT cpe FROM services WHERE ip = '172.31.250.10' AND port = 80`).Scan(&webCPE); err != nil || webCPE != "igor_sysoev:nginx" {
		t.Fatalf("172.31.250.10:80 cpe = %q (err=%v), want igor_sysoev:nginx", webCPE, err)
	}
	if n := httpReplay.calls.Load(); n != 2 {
		t.Errorf("httpx invoked %d times for two HTTP-containing batches", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM http_observations o
		JOIN services s ON s.id = o.service_id
		JOIN run_observations ro ON ro.run_id = o.run_id AND ro.ip = s.ip AND ro.port = s.port
		WHERE o.run_id = $1 AND s.ip = '172.31.250.10' AND s.port = 443 AND ro.up
		  AND o.status = 200 AND o.title = 'RAVEN TLS fixture'
		  AND raven_dec(o.headers_enc)::jsonb->>'X-Environment' = 'staging'
		  AND jsonb_array_length(raven_dec(o.cookies_enc)::jsonb) = 2
		  AND raven_dec(o.tls_cert_enc)::jsonb->>'subject_cn' = 'raven-s7-nginx'
		  AND o.redirects = '["https://raven-s7-nginx/home"]'::jsonb
		  AND o.technologies = '{Nginx:1.30.7}'`, r1.ID); n != 1 {
		t.Errorf("expected one encrypted HTTP observation associated with its run and service, got %d", n)
	}
	if err := pool.QueryRow(ctx, `SELECT raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'httpx'`, r1.ID).Scan(&dec); err != nil || dec != string(tlsRaw) {
		t.Fatalf("missing or incorrect encrypted httpx artifact: %v", err)
	}

	// user edits between runs, and a service on a port outside the profile
	if _, err := pool.Exec(ctx, `UPDATE hosts SET owner = 'it-dept', criticality = 'high', notes_enc = raven_enc('secret note'),
		user_tags = '{prod}', overrides = '{"os":"linux"}' WHERE ip = '172.31.250.10'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE services SET overrides = '{"name":"web"}' WHERE ip = '172.31.250.10' AND port = 80`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO services (ip, port, proto, name) VALUES ('172.31.250.10', 5555, 'tcp', 'custom')`); err != nil {
		t.Fatal(err)
	}
	h1 := getHost(t, pool, "172.31.250.10")

	// ── run 2: 172.31.250.10:443 closed; blocked first to test the one-active-run rule ──
	block := make(chan struct{})
	fake.set(block, map[string]bool{"172.31.250.10:443": true})
	r2, err := s.StartRun(ctx, nil, pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartRun(ctx, nil, pid); !errors.Is(err, ErrConflict) {
		t.Fatalf("second concurrent run: err = %v, want ErrConflict", err)
	}
	close(block)
	r2 = waitRun(t, s, r2.ID)
	if r2.Status != "done" || r2.HostsUp != 3 {
		t.Fatalf("run 2 finished as %+v", r2)
	}
	h2 := getHost(t, pool, "172.31.250.10")
	if !h2.FirstSeen.Equal(h1.FirstSeen) {
		t.Errorf("first_seen changed: %v → %v", h1.FirstSeen, h2.FirstSeen)
	}
	if !h2.LastSeen.After(h1.LastSeen) {
		t.Errorf("last_seen not bumped: %v → %v", h1.LastSeen, h2.LastSeen)
	}
	if h2.Owner != "it-dept" || h2.Crit != "high" || h2.Notes != "secret note" ||
		!slices.Equal(h2.Tags, []string{"prod"}) || h2.Overrides != `{"os": "linux"}` || h2.State != "active" {
		t.Errorf("user-owned host fields changed: %+v", h2)
	}
	if st, _ := serviceState(t, pool, "172.31.250.10", 443); st != "gone" {
		t.Errorf("10:443 state = %s, want gone", st)
	}
	if st, _ := serviceState(t, pool, "172.31.250.10", 5555); st != "open" {
		t.Errorf("10:5555 (outside the profile's ports) state = %s, want open", st)
	}
	if st, ov := serviceState(t, pool, "172.31.250.10", 80); st != "open" || ov != `{"name": "web"}` {
		t.Errorf("10:80 = %s %s, want open with overrides kept", st, ov)
	}
	if n := count(t, pool, `SELECT count(*) FROM run_observations WHERE run_id = $1 AND port IS NOT NULL`, r2.ID); n != 5 {
		t.Errorf("run 2 port observations = %d, want 5", n)
	}

	// ── run 3: stopped while its batches run ──
	block = make(chan struct{})
	defer close(block)
	fake.set(block, nil)
	r3, err := s.StartRun(ctx, nil, pid)
	if err != nil {
		t.Fatal(err)
	}
	waitBatchesRunning(t, s, r3.ID, 2)
	r3, err = s.StopRun(ctx, nil, r3.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r3.Status != "stopped" || r3.FinishedAt == nil {
		t.Fatalf("stopped run = %+v", r3)
	}
	deadline := time.Now().Add(15 * time.Second)
	for fake.cancelled.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if fake.cancelled.Load() < 2 {
		t.Fatalf("running scans were not cancelled (cancelled=%d)", fake.cancelled.Load())
	}
	time.Sleep(500 * time.Millisecond) // let the workers record the cancellation
	bs, err = s.ListBatches(ctx, r3.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bs {
		if b.Status != "stopped" {
			t.Errorf("batch of stopped run: %+v", b)
		}
	}
	if r, _ := s.GetRun(ctx, r3.ID); r.Status != "stopped" {
		t.Errorf("run 3 status after cancel = %s", r.Status)
	}
	if _, err := s.StopRun(ctx, nil, r3.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("stopping a stopped run: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_log WHERE action IN ('runs.start', 'runs.stop')`); n != 4 {
		t.Errorf("audit rows = %d, want 4", n)
	}

	// ── empty scan list → done immediately ──
	var empty int64
	if err := pool.QueryRow(ctx, `INSERT INTO profiles (name) VALUES ('empty') RETURNING id`).Scan(&empty); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scope_entries (kind, value, list, profile_id) VALUES ('ip', '10.99.99.99', 'include', $1)`, empty); err != nil {
		t.Fatal(err)
	}
	r4, err := s.StartRun(ctx, nil, empty)
	if err != nil {
		t.Fatal(err)
	}
	if r4.Status != "done" || r4.BatchesTotal != 0 || r4.HostsTotal != 0 || !bytes.Contains(r4.Stats, []byte("empty scan list")) {
		t.Fatalf("empty run = %+v stats=%s", r4, r4.Stats)
	}

	runs, total, err := s.ListRuns(ctx, &pid, 10, 0, db.ListOrder{})
	if err != nil || total != 3 || runs[0].ID != r3.ID {
		t.Fatalf("ListRuns = %d runs, total %d, err %v", len(runs), total, err)
	}
	if _, err := s.StartRun(ctx, nil, 999999); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown profile: %v", err)
	}
}
