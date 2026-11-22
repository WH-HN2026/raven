//go:build integration

package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/zap"
	"github.com/WH-HN2026/raven/internal/targets"
)

type fakeZAPRunner struct {
	calls     atomic.Int32
	raw       []byte
	errCount  int
	fatalErr  error
	lastInput scanner.Input
}

func (*fakeZAPRunner) Name() string         { return StageZAP }
func (*fakeZAPRunner) DojoScanType() string { return "ZAP Scan" }

func (f *fakeZAPRunner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	rep, err := f.RunDetailed(ctx, in, opt)
	if err != nil {
		return nil, err
	}
	return rep.Result, nil
}

func (f *fakeZAPRunner) RunDetailed(_ context.Context, in scanner.Input, _ scanner.Options) (*zap.RunReport, error) {
	f.calls.Add(1)
	f.lastInput = in
	if f.fatalErr != nil {
		return nil, f.fatalErr
	}
	res, err := zap.Parse(f.raw)
	if err != nil {
		return nil, err
	}
	rep := &zap.RunReport{Result: res, Errors: f.errCount}
	if f.errCount > 0 {
		rep.Outcomes = append(rep.Outcomes, zap.URLOutcome{URL: "http://172.31.250.10", Err: errors.New("simulated per-url failure")})
	}
	return rep, nil
}

// TestZAPStageIntegration verifies AG5 pipeline behavior:
//   - ZAP is skipped when not in the profile's stages;
//   - ZAP runs on httpx URLs when enabled, stores its encrypted XML artifact;
//   - Per-URL error does not fail the batch and records zap_errors in run stats.
func TestZAPStageIntegration(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	WithStageAvailable(t, StageZAP)

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

	zapXML := []byte(`<?xml version="1.0"?>
<OWASPZAPReport programName="ZAP" version="2.17.0">
  <site name="https://172.31.250.10" host="172.31.250.10" port="443" ssl="true">
    <alerts>
      <alertitem>
        <pluginid>10020</pluginid>
        <alert>Missing Anti-clickjacking Header</alert>
        <riskcode>2</riskcode>
        <instances><instance><uri>https://172.31.250.10/</uri><method>GET</method></instance></instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>`)

	fakeNmap := &fakeScanner{raw: nmapRaw}
	fakeHTTPX := &replayHTTPX{raw: tlsRaw}
	fakeNuclei := &countingNuclei{}
	fakeZAP := &fakeZAPRunner{raw: zapXML}
	hook := &recordingHook{}

	s, err := New(pool, Config{
		Scanner: fakeNmap, HTTPX: fakeHTTPX, Nuclei: fakeNuclei, ZAP: fakeZAP,
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

	// 1. Default profile skips ZAP completely.
	var defaultID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'Default'`).Scan(&defaultID); err != nil {
		t.Fatal(err)
	}
	r1, err := s.StartRun(ctx, nil, defaultID)
	if err != nil {
		t.Fatal(err)
	}
	r1 = waitRun(t, s, r1.ID)
	if r1.Status != "done" || fakeZAP.calls.Load() != 0 {
		t.Fatalf("default run should skip zap: status=%s calls=%d", r1.Status, fakeZAP.calls.Load())
	}
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'zap'`, r1.ID); n != 0 {
		t.Fatalf("default run stored %d zap artifacts, want 0", n)
	}

	// 2. Aggressive profile with ZAP stores encrypted artifact and passes zap stage to hook.
	var zapProfID int64
	if err := pool.QueryRow(ctx, `INSERT INTO profiles (name, ports, stages) VALUES ('agg-zap', '22,80,443', ARRAY['nmap', 'httpx', 'nuclei', 'zap']) RETURNING id`).Scan(&zapProfID); err != nil {
		t.Fatal(err)
	}
	r2, err := s.StartRun(ctx, nil, zapProfID)
	if err != nil {
		t.Fatal(err)
	}
	r2 = waitRun(t, s, r2.ID)
	if r2.Status != "done" || fakeZAP.calls.Load() != 1 {
		t.Fatalf("zap run: status=%s calls=%d", r2.Status, fakeZAP.calls.Load())
	}
	if !slices.Equal(fakeZAP.lastInput.URLs, []string{"https://172.31.250.10:443"}) {
		t.Fatalf("zap input URLs = %v, want [https://172.31.250.10:443]", fakeZAP.lastInput.URLs)
	}
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'zap'`, r2.ID); n != 1 {
		t.Fatalf("zap run stored %d zap artifacts, want 1", n)
	}
	if !HasStage(hook.last().Stages, StageZAP) {
		t.Fatalf("hook stages %v missing zap", hook.last().Stages)
	}

	// 3. Per-URL error does not fail the batch and records zap_errors in runs.stats.
	fakeZAP.errCount = 1
	r3, err := s.StartRun(ctx, nil, zapProfID)
	if err != nil {
		t.Fatal(err)
	}
	r3 = waitRun(t, s, r3.ID)
	if r3.Status != "done" {
		t.Fatalf("run with per-URL zap error should still finish done, got %s", r3.Status)
	}
	var stats map[string]any
	if err := json.Unmarshal(r3.Stats, &stats); err != nil {
		t.Fatalf("decode run stats %s: %v", r3.Stats, err)
	}
	if got, _ := stats["zap_errors"].(float64); int(got) != 1 {
		t.Fatalf("runs.stats.zap_errors = %v (full stats=%s), want 1", stats["zap_errors"], r3.Stats)
	}
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'zap'`, r3.ID); n != 1 {
		t.Fatalf("partial zap run stored %d zap artifacts, want 1", n)
	}
}
