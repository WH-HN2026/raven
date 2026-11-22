//go:build integration

package pipeline

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/targets"
)

type countingNuclei struct {
	nuclei.Scanner
	raw   []byte
	calls atomic.Int32
}

func (f *countingNuclei) Run(_ context.Context, _ scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	f.calls.Add(1)
	if len(f.raw) == 0 {
		return &scanner.Result{Raw: []byte{}}, nil
	}
	return nuclei.Parse(f.raw)
}

type recordingHook struct {
	mu      sync.Mutex
	results []BatchResult
}

func (h *recordingHook) AfterBatch(_ context.Context, b BatchResult) error {
	h.mu.Lock()
	h.results = append(h.results, b)
	h.mu.Unlock()
	return nil
}

func (h *recordingHook) last() BatchResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.results[len(h.results)-1]
}

// TestWorkflowStagesExecution verifies WF1 pipeline stage execution:
//   - Default run records runs.stages={nmap,httpx,nuclei}, invokes all three stages,
//     and populates http_observations + nuclei_matches;
//   - nmap-only run records runs.stages={nmap}, skips httpx and nuclei, passes
//     Stages=[nmap] to the BatchHook, and leaves pre-existing http_observations
//     and prior run nuclei_matches untouched;
//   - [nmap, httpx] run invokes nmap and httpx only, skipping nuclei;
//   - editing a profile's stages mid-run does not alter the already-started run's stages.
func TestWorkflowStagesExecution(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	nmapRaw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
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
			tlsRaw = bytes.ReplaceAll(tlsRaw, []byte("raven-s7-nginx"), []byte("172.31.250.10"))
		}
	}
	nucleiRaw, err := os.ReadFile("../scanner/nuclei/testdata/lab-http.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	firstNuclei := bytes.SplitN(nucleiRaw, []byte("\n"), 2)[0]
	firstNuclei = bytes.ReplaceAll(firstNuclei, []byte("172.30.0.17"), []byte("172.31.250.10"))
	firstNuclei = bytes.ReplaceAll(firstNuclei, []byte(":80"), []byte(":443"))
	firstNuclei = bytes.ReplaceAll(firstNuclei, []byte("http://"), []byte("https://"))

	fakeNmap := &fakeScanner{raw: nmapRaw}
	fakeHTTPX := &replayHTTPX{raw: tlsRaw}
	fakeNuclei := &countingNuclei{raw: firstNuclei}
	hook := &recordingHook{}

	s, err := New(pool, Config{
		Scanner: fakeNmap, HTTPX: fakeHTTPX, Nuclei: fakeNuclei,
		Resolver: net.DefaultResolver, Hook: hook, BatchSize: 4, Workers: 2,
	})
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

	e, err := targets.NewEntry("172.31.250.10", "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&targets.Store{Pool: pool}).AddTargets(ctx, nil, "manual", []targets.Entry{e}); err != nil {
		t.Fatal(err)
	}

	// 1) Default profile run: populates http_observations and nuclei_matches.
	var defaultID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'Default'`).Scan(&defaultID); err != nil {
		t.Fatal(err)
	}
	r1, err := s.StartRun(ctx, nil, defaultID)
	if err != nil {
		t.Fatal(err)
	}
	r1 = waitRun(t, s, r1.ID)
	if r1.Status != "done" || !slices.Equal(r1.Stages, DefaultStages()) {
		t.Fatalf("default run = %+v", r1)
	}
	var dbStages []string
	if err := pool.QueryRow(ctx, `SELECT stages FROM runs WHERE id = $1`, r1.ID).Scan(&dbStages); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dbStages, DefaultStages()) {
		t.Fatalf("r1 DB stages = %v, want %v", dbStages, DefaultStages())
	}
	if fakeHTTPX.calls.Load() != 1 || fakeNuclei.calls.Load() != 1 {
		t.Fatalf("default run calls: httpx=%d nuclei=%d, want 1, 1", fakeHTTPX.calls.Load(), fakeNuclei.calls.Load())
	}
	httpBefore := count(t, pool, `SELECT count(*) FROM http_observations`)
	if httpBefore != 1 {
		t.Fatalf("http_observations after default run = %d, want 1", httpBefore)
	}
	if !slices.Equal(hook.last().Stages, DefaultStages()) {
		t.Fatalf("hook stages for default run = %v", hook.last().Stages)
	}

	// 2) nmap-only profile: records runs.stages={nmap}, skips httpx & nuclei,
	//    and leaves pre-existing http_observations untouched.
	var nmapOnlyID int64
	if err := pool.QueryRow(ctx, `INSERT INTO profiles (name, ports, stages) VALUES ('nmap-only', '22,80,443', ARRAY['nmap']) RETURNING id`).Scan(&nmapOnlyID); err != nil {
		t.Fatal(err)
	}
	r2, err := s.StartRun(ctx, nil, nmapOnlyID)
	if err != nil {
		t.Fatal(err)
	}
	r2 = waitRun(t, s, r2.ID)
	if r2.Status != "done" || !slices.Equal(r2.Stages, []string{StageNmap}) {
		t.Fatalf("nmap-only run = %+v", r2)
	}
	if err := pool.QueryRow(ctx, `SELECT stages FROM runs WHERE id = $1`, r2.ID).Scan(&dbStages); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dbStages, []string{StageNmap}) {
		t.Fatalf("r2 DB stages = %v, want [nmap]", dbStages)
	}
	if fakeHTTPX.calls.Load() != 1 || fakeNuclei.calls.Load() != 1 {
		t.Fatalf("nmap-only run invoked skipped scanners: httpx=%d nuclei=%d, want still 1, 1",
			fakeHTTPX.calls.Load(), fakeNuclei.calls.Load())
	}
	if !slices.Equal(hook.last().Stages, []string{StageNmap}) {
		t.Fatalf("hook stages for nmap-only run = %v, want [nmap]", hook.last().Stages)
	}
	if n := count(t, pool, `SELECT count(*) FROM http_observations`); n != httpBefore {
		t.Fatalf("http_observations count changed from %d to %d after nmap-only run", httpBefore, n)
	}
	if n := count(t, pool, `SELECT count(*) FROM http_observations WHERE run_id = $1`, r2.ID); n != 0 {
		t.Fatalf("nmap-only run wrote %d http_observations, want 0", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner IN ('httpx', 'nuclei')`, r2.ID); n != 0 {
		t.Fatalf("nmap-only run wrote %d web artifacts, want 0", n)
	}

	// 3) [nmap, httpx] profile: runs nmap + httpx, skips nuclei.
	var httpOnlyID int64
	if err := pool.QueryRow(ctx, `INSERT INTO profiles (name, ports, stages) VALUES ('nmap-httpx', '22,80,443', ARRAY['nmap', 'httpx']) RETURNING id`).Scan(&httpOnlyID); err != nil {
		t.Fatal(err)
	}
	r3, err := s.StartRun(ctx, nil, httpOnlyID)
	if err != nil {
		t.Fatal(err)
	}
	r3 = waitRun(t, s, r3.ID)
	if r3.Status != "done" || !slices.Equal(r3.Stages, []string{StageNmap, StageHTTPX}) {
		t.Fatalf("nmap+httpx run = %+v", r3)
	}
	if fakeHTTPX.calls.Load() != 2 || fakeNuclei.calls.Load() != 1 {
		t.Fatalf("nmap+httpx calls: httpx=%d nuclei=%d, want 2, 1", fakeHTTPX.calls.Load(), fakeNuclei.calls.Load())
	}
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'nuclei'`, r3.ID); n != 0 {
		t.Fatalf("nmap+httpx run wrote %d nuclei artifacts, want 0", n)
	}

	// 4) Snapshot invariant: editing profile stages mid-run does not change the running run.
	block := make(chan struct{})
	fakeNmap.set(block, nil)
	r4, err := s.StartRun(ctx, nil, nmapOnlyID)
	if err != nil {
		t.Fatal(err)
	}
	waitBatchesRunning(t, s, r4.ID, 1)
	if _, err := pool.Exec(ctx, `UPDATE profiles SET stages = ARRAY['nmap', 'httpx', 'nuclei'] WHERE id = $1`, nmapOnlyID); err != nil {
		t.Fatal(err)
	}
	close(block)
	r4 = waitRun(t, s, r4.ID)
	if r4.Status != "done" || !slices.Equal(r4.Stages, []string{StageNmap}) {
		t.Fatalf("snapshotted run = %+v, want stages=[nmap]", r4)
	}
	if fakeHTTPX.calls.Load() != 2 || fakeNuclei.calls.Load() != 1 {
		t.Fatalf("mid-run profile edit leaked into running run: httpx=%d nuclei=%d, want 2, 1",
			fakeHTTPX.calls.Load(), fakeNuclei.calls.Load())
	}
}
