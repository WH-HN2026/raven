//go:build integration

package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/targets"
)

type fakeNucleiActive struct {
	mu      sync.Mutex
	calls   []string
	failURL string
	byURL   map[string][]byte
}

func (*fakeNucleiActive) Name() string         { return StageNucleiActive }
func (*fakeNucleiActive) DojoScanType() string { return "Nuclei Scan" }

func (f *fakeNucleiActive) Run(_ context.Context, in scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(in.URLs) != 1 {
		return nil, errors.New("expected one URL per invocation")
	}
	u := in.URLs[0]
	f.calls = append(f.calls, u)
	if u == f.failURL {
		return nil, errors.New("simulated nuclei_active error")
	}
	raw := f.byURL[u]
	if raw == nil {
		raw = []byte{}
	}
	return nuclei.Parse(raw)
}

func (f *fakeNucleiActive) calledURLs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

type twoHostScanner struct {
	name     string
	scanType string
	obs      []scanner.Observation
	raw      []byte
}

func (s *twoHostScanner) Name() string         { return s.name }
func (s *twoHostScanner) DojoScanType() string { return s.scanType }
func (s *twoHostScanner) Run(_ context.Context, _ scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{Raw: s.raw, Observations: s.obs}, nil
}

// TestNucleiActiveStageIntegration verifies:
//   - nuclei_active is skipped when absent from stages (zero calls, no artifact);
//   - nuclei_active runs when enabled, storing an encrypted artifact and nuclei_active_errors=0;
//   - a per-URL failure does not fail the batch: the error is recorded in
//     runs.stats.nuclei_active_errors and the remaining URL's output is stored.
func TestNucleiActiveStageIntegration(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	ip1 := netip.MustParseAddr("172.30.0.17")
	ip2 := netip.MustParseAddr("172.30.0.21")

	fixtureRaw, err := os.ReadFile("../scanner/nuclei/testdata/lab-active.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	parsedFixture, err := nuclei.Parse(fixtureRaw)
	if err != nil {
		t.Fatal(err)
	}

	nmapFake := &twoHostScanner{
		name: "nmap", scanType: "Nmap Scan", raw: []byte("<nmaprun/>"),
		obs: []scanner.Observation{
			{Kind: scanner.ObsHost, IP: ip1, Up: true},
			{Kind: scanner.ObsService, IP: ip1, Port: 80, Proto: "tcp", Service: "http"},
			{Kind: scanner.ObsHost, IP: ip2, Up: true},
			{Kind: scanner.ObsService, IP: ip2, Port: 8080, Proto: "tcp", Service: "http"},
		},
	}
	httpxFake := &twoHostScanner{
		name: "httpx", scanType: "httpx Scan", raw: []byte("{}"),
		obs: []scanner.Observation{
			{Kind: scanner.ObsHTTP, IP: ip1, Port: 80, URL: "http://172.30.0.17:80", HTTP: &scanner.HTTPInfo{Status: 200}},
			{Kind: scanner.ObsHTTP, IP: ip2, Port: 8080, URL: "http://172.30.0.21:8080", HTTP: &scanner.HTTPInfo{Status: 200}},
		},
	}
	nucleiFake := &countingNuclei{raw: nil}
	activeFake := &fakeNucleiActive{
		byURL: map[string][]byte{
			"http://172.30.0.17:80":   parsedFixture.PerIP(ip1),
			"http://172.30.0.21:8080": parsedFixture.PerIP(ip2),
		},
	}

	s, err := New(pool, Config{
		Scanner: nmapFake, HTTPX: httpxFake, Nuclei: nucleiFake, NucleiActive: activeFake,
		Resolver: net.DefaultResolver, BatchSize: 4, Workers: 1,
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

	for _, rawIP := range []string{"172.30.0.17", "172.30.0.21"} {
		e, err := targets.NewEntry(rawIP, "", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&targets.Store{Pool: pool}).AddTargets(ctx, nil, "manual", []targets.Entry{e}); err != nil {
			t.Fatal(err)
		}
	}

	// 1) Default profile: nuclei_active must be skipped.
	var defaultID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'Default'`).Scan(&defaultID); err != nil {
		t.Fatal(err)
	}
	r1, err := s.StartRun(ctx, nil, defaultID)
	if err != nil {
		t.Fatal(err)
	}
	r1 = waitRun(t, s, r1.ID)
	if r1.Status != "done" {
		t.Fatalf("default run = %+v", r1)
	}
	if got := activeFake.calledURLs(); len(got) != 0 {
		t.Fatalf("nuclei_active ran on default profile: %v", got)
	}
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'nuclei_active'`, r1.ID); n != 0 {
		t.Fatalf("default run wrote %d nuclei_active artifacts, want 0", n)
	}

	// 2) Aggressive profile (Default + nuclei_active), both URLs succeed.
	WithStageAvailable(t, StageNucleiActive)
	var aggID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO profiles (name, ports, stages) VALUES ('agg-nuclei-active', '80,8080', ARRAY['nmap','httpx','nuclei','nuclei_active']) RETURNING id`,
	).Scan(&aggID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO scope_entries (kind, value, list, profile_id) VALUES ('cidr', '172.30.0.0/24', 'include', $1)`, aggID,
	); err != nil {
		t.Fatal(err)
	}

	r2, err := s.StartRun(ctx, nil, aggID)
	if err != nil {
		t.Fatal(err)
	}
	r2 = waitRun(t, s, r2.ID)
	if r2.Status != "done" || !r2.Aggressive {
		t.Fatalf("aggressive run = %+v", r2)
	}
	if got := activeFake.calledURLs(); !slices.Equal(got, []string{"http://172.30.0.17:80", "http://172.30.0.21:8080"}) {
		t.Fatalf("nuclei_active URLs = %v", got)
	}
	var artifact string
	if err := pool.QueryRow(ctx, `SELECT raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'nuclei_active'`, r2.ID).Scan(&artifact); err != nil {
		t.Fatalf("read nuclei_active artifact: %v", err)
	}
	parsedArt, err := nuclei.Parse([]byte(artifact))
	if err != nil || len(parsedArt.Observations) != 3 {
		t.Fatalf("parsed artifact = %d obs, err=%v", len(parsedArt.Observations), err)
	}
	var stats map[string]any
	if err := json.Unmarshal(r2.Stats, &stats); err != nil {
		t.Fatal(err)
	}
	if got, ok := stats["nuclei_active_errors"].(float64); !ok || got != 0 {
		t.Fatalf("run stats nuclei_active_errors = %v, want 0 (stats=%s)", stats["nuclei_active_errors"], r2.Stats)
	}

	// 3) Per-URL error does not fail the batch; records nuclei_active_errors=1 and stores the other URL's output.
	activeFake.failURL = "http://172.30.0.21:8080"
	r3, err := s.StartRun(ctx, nil, aggID)
	if err != nil {
		t.Fatal(err)
	}
	r3 = waitRun(t, s, r3.ID)
	if r3.Status != "done" {
		t.Fatalf("partial-error run status = %q, want done", r3.Status)
	}
	var art3 string
	if err := pool.QueryRow(ctx, `SELECT raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'nuclei_active'`, r3.ID).Scan(&art3); err != nil {
		t.Fatalf("read partial nuclei_active artifact: %v", err)
	}
	parsedArt3, err := nuclei.Parse([]byte(art3))
	if err != nil || len(parsedArt3.Observations) != 1 || parsedArt3.Observations[0].IP != ip1 {
		t.Fatalf("expected 1 observation from surviving URL, got %+v, err=%v", parsedArt3, err)
	}
	stats = nil
	if err := json.Unmarshal(r3.Stats, &stats); err != nil {
		t.Fatal(err)
	}
	if got, ok := stats["nuclei_active_errors"].(float64); !ok || got != 1 {
		t.Fatalf("run stats nuclei_active_errors = %v, want 1 (stats=%s)", stats["nuclei_active_errors"], r3.Stats)
	}
}
