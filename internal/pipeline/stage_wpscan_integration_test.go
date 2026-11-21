//go:build integration

package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/wpscan"
)

type fakeWPScan struct {
	mu      sync.Mutex
	calls   []string
	failURL map[string]error
	rawByIP map[netip.Addr][]byte
}

func (*fakeWPScan) Name() string         { return "wpscan" }
func (*fakeWPScan) DojoScanType() string { return "Wpscan" }

func (f *fakeWPScan) Run(_ context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	if opt.RateLimit <= 0 {
		return nil, errors.New("fake wpscan: missing rate limit")
	}
	f.mu.Lock()
	f.calls = append(f.calls, in.URLs...)
	f.mu.Unlock()
	if len(in.URLs) != 1 {
		return nil, errors.New("fake wpscan: expected one URL per call")
	}
	u := in.URLs[0]
	if err := f.failURL[u]; err != nil {
		return nil, err
	}
	for ip, raw := range f.rawByIP {
		if strings.Contains(u, ip.String()) {
			return wpscan.Parse(raw)
		}
	}
	return wpscan.Parse(nil)
}

func (f *fakeWPScan) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// TestWPScanStageIntegration verifies the wpscan pipeline stage end-to-end:
//   - Skipped when wpscan is not in profile stages (even if WordPress exists);
//   - Records "skipped: no WordPress" in runs.stats when enabled on non-WP hosts;
//   - Scans ONLY WordPress URLs (skipping Joomla in the same batch), stores the
//     encrypted wpscan artifact, merges WordPress CPE+version for offline CVE
//     matching;
//   - A per-URL failure logs, increments stats["wpscan_errors"], and continues
//     scanning remaining WordPress URLs without failing the batch.
func TestWPScanStageIntegration(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := t.Context()
	q := gen.New(pool)

	var profID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'default'`).Scan(&profID); err != nil {
		t.Fatal(err)
	}
	prof, err := q.GetProfile(ctx, profID)
	if err != nil {
		t.Fatal(err)
	}

	labFixture, err := os.ReadFile("../scanner/wpscan/testdata/lab-wordpress.json")
	if err != nil {
		t.Fatal(err)
	}
	ipWP := netip.MustParseAddr("172.30.0.17")
	ipJoomla := netip.MustParseAddr("172.30.0.18")
	ipWP2 := netip.MustParseAddr("172.30.0.19")

	// Use an older WordPress version on ipWP to also verify offline CVE matching picks it up.
	wpOldRaw := []byte(strings.ReplaceAll(string(labFixture), `"7.1.5"`, `"4.7.5"`))
	wp2Raw := []byte(strings.ReplaceAll(string(labFixture), "172.30.0.17", "172.30.0.19"))

	newBatch := func(stages []string, ips []netip.Addr) (gen.Run, gen.Batch) {
		t.Helper()
		now := time.Now()
		run, err := q.InsertRun(ctx, gen.InsertRunParams{
			ProfileID: prof.ID, Status: "running", StartedAt: &now,
			HostsTotal: int32(len(ips)), Stats: []byte("{}"), Stages: stages,
		})
		if err != nil {
			t.Fatal(err)
		}
		batchID, err := q.InsertBatch(ctx, gen.InsertBatchParams{RunID: run.ID, Seq: 1, Ips: ips})
		if err != nil {
			t.Fatal(err)
		}
		b, err := q.StartBatch(ctx, batchID)
		if err != nil {
			t.Fatal(err)
		}
		return run, b
	}

	readStats := func(runID int64) map[string]any {
		t.Helper()
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT stats FROM runs WHERE id = $1`, runID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("skipped when stage not enabled", func(t *testing.T) {
		fake := &fakeWPScan{rawByIP: map[netip.Addr][]byte{ipWP: wpOldRaw}}
		s, err := New(pool, Config{Scanner: nmap.New(nmap.Config{}), WPScan: fake})
		if err != nil {
			t.Fatal(err)
		}
		stages := DefaultStages()
		run, b := newBatch(stages, []netip.Addr{ipWP})
		nmapRes := &scanner.Result{Raw: []byte("<nmaprun/>"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHost, IP: ipWP, Up: true},
			{Kind: scanner.ObsService, IP: ipWP, Port: 80, Proto: "tcp", Service: "http"},
		}}
		web := &scanner.Result{Raw: []byte("{}"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHTTP, IP: ipWP, Port: 80, URL: "http://172.30.0.17:80",
				HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"WordPress"}}},
		}}
		var wp *wpscanStageResult
		if HasStage(stages, StageWPScan) {
			wp, err = s.scanWPScan(ctx, b, prof, web, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.ingestBatch(ctx, b, prof, nil, nmapRes, web, nil, wp, time.Now()); err != nil {
			t.Fatal(err)
		}
		if len(fake.called()) != 0 {
			t.Fatalf("wpscan called when stage disabled: %v", fake.called())
		}
		if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'wpscan'`, run.ID); n != 0 {
			t.Fatalf("wpscan artifacts = %d, want 0", n)
		}
	})

	t.Run("skipped no WordPress records reason and stores no artifact", func(t *testing.T) {
		fake := &fakeWPScan{}
		s, err := New(pool, Config{Scanner: nmap.New(nmap.Config{}), WPScan: fake})
		if err != nil {
			t.Fatal(err)
		}
		stages := append(DefaultStages(), StageWPScan)
		run, b := newBatch(stages, []netip.Addr{ipJoomla})
		nmapRes := &scanner.Result{Raw: []byte("<nmaprun/>"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHost, IP: ipJoomla, Up: true},
			{Kind: scanner.ObsService, IP: ipJoomla, Port: 80, Proto: "tcp", Service: "http"},
		}}
		web := &scanner.Result{Raw: []byte("{}"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHTTP, IP: ipJoomla, Port: 80, URL: "http://172.30.0.18:80",
				HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"Joomla"}}},
		}}
		wp, err := s.scanWPScan(ctx, b, prof, web, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ingestBatch(ctx, b, prof, nil, nmapRes, web, nil, wp, time.Now()); err != nil {
			t.Fatal(err)
		}
		if len(fake.called()) != 0 {
			t.Fatalf("wpscan called on Joomla-only batch: %v", fake.called())
		}
		if stats := readStats(run.ID); stats["wpscan"] != "skipped: no WordPress" {
			t.Fatalf("stats[wpscan] = %v, want %q", stats["wpscan"], "skipped: no WordPress")
		}
		if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'wpscan'`, run.ID); n != 0 {
			t.Fatalf("wpscan artifacts = %d, want 0", n)
		}
	})

	t.Run("scans WordPress only, stores artifact, feeds offline CVE matching", func(t *testing.T) {
		fake := &fakeWPScan{rawByIP: map[netip.Addr][]byte{ipWP: wpOldRaw}}
		s, err := New(pool, Config{Scanner: nmap.New(nmap.Config{}), WPScan: fake})
		if err != nil {
			t.Fatal(err)
		}
		stages := append(DefaultStages(), StageWPScan)
		run, b := newBatch(stages, []netip.Addr{ipWP, ipJoomla})
		nmapRes := &scanner.Result{Raw: []byte("<nmaprun/>"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHost, IP: ipWP, Up: true},
			{Kind: scanner.ObsService, IP: ipWP, Port: 80, Proto: "tcp", Service: "http"},
			{Kind: scanner.ObsHost, IP: ipJoomla, Up: true},
			{Kind: scanner.ObsService, IP: ipJoomla, Port: 80, Proto: "tcp", Service: "http"},
		}}
		// httpx detected WordPress without a version; wpscan supplies 4.7.5.
		web := &scanner.Result{Raw: []byte("{}"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHTTP, IP: ipWP, Port: 80, URL: "http://172.30.0.17:80",
				HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"WordPress"}}},
			{Kind: scanner.ObsHTTP, IP: ipJoomla, Port: 80, URL: "http://172.30.0.18:80",
				HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"Joomla"}}},
		}}
		wp, err := s.scanWPScan(ctx, b, prof, web, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ingestBatch(ctx, b, prof, nil, nmapRes, web, nil, wp, time.Now()); err != nil {
			t.Fatal(err)
		}
		if got := fake.called(); !slices.Equal(got, []string{"http://172.30.0.17:80"}) {
			t.Fatalf("wpscan called = %v, want only WordPress URL", got)
		}
		stats := readStats(run.ID)
		if stats["wpscan"] != "ok" || jsonInt(stats["wpscan_urls"]) != 1 || jsonInt(stats["wpscan_errors"]) != 0 {
			t.Fatalf("unexpected stats = %+v", stats)
		}
		var artifact string
		if err := pool.QueryRow(ctx, `SELECT raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'wpscan'`, run.ID).Scan(&artifact); err != nil {
			t.Fatalf("read wpscan artifact: %v", err)
		}
		if !strings.Contains(artifact, `"172.30.0.17"`) {
			t.Fatalf("unexpected artifact content: %s", artifact)
		}

		// Offline CVE pass picks up wordpress:wordpress:4.7.5 from wpscan ingest.
		matcher, err := cve.Default()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cve.RunPass(ctx, pool, matcher, time.Now()); err != nil {
			t.Fatalf("cve.RunPass: %v", err)
		}
		matches, err := cve.List(ctx, pool, ipWP)
		if err != nil {
			t.Fatal(err)
		}
		var matchedWP bool
		for _, m := range matches {
			if m.CPE == "wordpress:wordpress" && m.Version == "4.7.5" && len(m.Hits) > 0 {
				matchedWP = true
			}
		}
		if !matchedWP {
			t.Fatalf("expected offline CVE match for WordPress 4.7.5 on %s, got %+v", ipWP, matches)
		}
	})

	t.Run("per-URL error does not fail batch and records wpscan_errors", func(t *testing.T) {
		fake := &fakeWPScan{
			failURL: map[string]error{"http://172.30.0.17:80": errors.New("connection reset")},
			rawByIP: map[netip.Addr][]byte{ipWP2: wp2Raw},
		}
		s, err := New(pool, Config{Scanner: nmap.New(nmap.Config{}), WPScan: fake})
		if err != nil {
			t.Fatal(err)
		}
		stages := append(DefaultStages(), StageWPScan)
		run, b := newBatch(stages, []netip.Addr{ipWP, ipWP2})
		nmapRes := &scanner.Result{Raw: []byte("<nmaprun/>"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHost, IP: ipWP, Up: true},
			{Kind: scanner.ObsService, IP: ipWP, Port: 80, Proto: "tcp", Service: "http"},
			{Kind: scanner.ObsHost, IP: ipWP2, Up: true},
			{Kind: scanner.ObsService, IP: ipWP2, Port: 80, Proto: "tcp", Service: "http"},
		}}
		web := &scanner.Result{Raw: []byte("{}"), Observations: []scanner.Observation{
			{Kind: scanner.ObsHTTP, IP: ipWP, Port: 80, URL: "http://172.30.0.17:80",
				HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"WordPress"}}},
			{Kind: scanner.ObsHTTP, IP: ipWP2, Port: 80, URL: "http://172.30.0.19:80",
				HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"WordPress"}}},
		}}
		wp, err := s.scanWPScan(ctx, b, prof, web, nil)
		if err != nil {
			t.Fatalf("per-URL failure should not return error: %v", err)
		}
		if _, err := s.ingestBatch(ctx, b, prof, nil, nmapRes, web, nil, wp, time.Now()); err != nil {
			t.Fatal(err)
		}
		stats := readStats(run.ID)
		if jsonInt(stats["wpscan_errors"]) != 1 || jsonInt(stats["wpscan_urls"]) != 1 {
			t.Fatalf("stats = %+v, want wpscan_errors=1 wpscan_urls=1", stats)
		}
		if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'wpscan'`, run.ID); n != 1 {
			t.Fatalf("wpscan artifacts = %d, want 1 (from second URL)", n)
		}
	})
}
