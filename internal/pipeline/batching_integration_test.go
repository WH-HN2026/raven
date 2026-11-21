//go:build integration

package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// latencyNmap simulates a scanner with a known per-IP wall time, records
// concurrency and options, and reports the first IP in the batch as an HTTP
// service so httpx and nuclei stages also execute and have their rates checked.
type latencyNmap struct {
	perIP time.Duration
	fixed time.Duration

	inFlight    atomic.Int32
	maxObserved atomic.Int32

	mu       sync.Mutex
	maxRates []int
}

func (*latencyNmap) Name() string         { return "nmap" }
func (*latencyNmap) DojoScanType() string { return "Nmap Scan" }

func (l *latencyNmap) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	cur := l.inFlight.Add(1)
	for {
		prev := l.maxObserved.Load()
		if cur <= prev || l.maxObserved.CompareAndSwap(prev, cur) {
			break
		}
	}
	defer l.inFlight.Add(-1)

	l.mu.Lock()
	l.maxRates = append(l.maxRates, opt.MaxRate)
	l.mu.Unlock()

	d := l.fixed + time.Duration(len(in.IPs))*l.perIP
	if d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	var obs []scanner.Observation
	if len(in.IPs) > 0 {
		ip := in.IPs[0]
		obs = []scanner.Observation{
			{Kind: scanner.ObsHost, IP: ip, Up: true},
			{Kind: scanner.ObsService, IP: ip, Port: 80, Proto: "tcp", Service: "http"},
		}
	}
	return &scanner.Result{Raw: []byte("<nmaprun/>"), Observations: obs}, nil
}

type rateRecordingScanner struct {
	name     string
	scanType string

	mu    sync.Mutex
	rates []int
}

func (r *rateRecordingScanner) Name() string         { return r.name }
func (r *rateRecordingScanner) DojoScanType() string { return r.scanType }

func (r *rateRecordingScanner) Run(_ context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	r.mu.Lock()
	r.rates = append(r.rates, opt.RateLimit)
	r.mu.Unlock()

	var obs []scanner.Observation
	if r.name == "httpx" && len(in.IPs) > 0 {
		ip := in.IPs[0]
		obs = []scanner.Observation{{
			Kind: scanner.ObsHTTP, IP: ip, Port: 80,
			URL:  fmt.Sprintf("http://%s:80", ip),
			HTTP: &scanner.HTTPInfo{Status: 200, Title: "ok"},
		}}
	}
	return &scanner.Result{Raw: []byte("{}\n"), Observations: obs}, nil
}

func TestAdaptiveBatchingConvergence(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	var pid, otherPID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO profiles (name, ports, nmap_max_rate, nuclei_rate, nuclei_tags, target_batch_seconds)
		VALUES ('adaptive-s5', '80', 120, 30, ARRAY['tech'], 1) RETURNING id`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO profiles (name, ports, nmap_max_rate, nuclei_rate, target_batch_seconds)
		VALUES ('fresh-other', '80', 120, 30, 1) RETURNING id`).Scan(&otherPID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{pid, otherPID} {
		if _, err := pool.Exec(ctx, `INSERT INTO scope_entries (kind, value, list, profile_id) VALUES ('cidr', '172.30.0.0/24', 'include', $1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO targets (kind, value, source) VALUES ('cidr', '172.30.0.0/24', 'manual')`); err != nil {
		t.Fatal(err)
	}

	// 10ms/IP = 100 hosts/s. With target_batch_seconds = 1, batches should converge near 100 IPs.
	fakeNmap := &latencyNmap{perIP: 10 * time.Millisecond}
	fakeHTTPX := &rateRecordingScanner{name: "httpx", scanType: "httpx Scan"}
	fakeNuclei := &rateRecordingScanner{name: "nuclei", scanType: "Nuclei Scan"}

	// BatchSize: 0 enables adaptive sizing; Workers: 2 caps concurrency and halves per-worker rates.
	s, err := New(pool, Config{
		Scanner: fakeNmap,
		HTTPX:   fakeHTTPX,
		Nuclei:  fakeNuclei,
		Workers: 2,
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

	type runStats struct {
		BatchSize           int     `json:"batch_size"`
		BatchSizes          []int   `json:"batch_sizes"`
		BatchSizing         string  `json:"batch_sizing"`
		TargetBatchSeconds  int     `json:"target_batch_seconds"`
		MeasuredSecPerIP    float64 `json:"measured_sec_per_ip"`
		BatchHistorySamples int     `json:"batch_history_samples"`
		MaxWorkers          int     `json:"max_workers"`
		EffectiveNmapRate   int     `json:"effective_nmap_max_rate"`
		EffectiveNucleiRate int     `json:"effective_nuclei_rate"`
	}
	parseStats := func(raw json.RawMessage) runStats {
		t.Helper()
		var st runStats
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatalf("unmarshal run stats %s: %v", raw, err)
		}
		return st
	}

	// Run 1: no history -> DefaultBatchSize (256), 256 IPs fit in 1 batch (~2.56s).
	r1, err := s.StartRun(ctx, nil, pid)
	if err != nil {
		t.Fatal(err)
	}
	r1 = waitRun(t, s, r1.ID)
	if r1.Status != "done" || r1.BatchesTotal != 1 {
		t.Fatalf("run 1 = %+v, want done with 1 batch", r1)
	}
	st1 := parseStats(r1.Stats)
	if st1.BatchSizing != "default" || st1.BatchSize != DefaultBatchSize || st1.BatchHistorySamples != 0 {
		t.Fatalf("run 1 stats = %+v, want default size %d", st1, DefaultBatchSize)
	}
	if len(st1.BatchSizes) != 1 || st1.BatchSizes[0] != 256 {
		t.Fatalf("run 1 batch_sizes = %v, want [256]", st1.BatchSizes)
	}
	if st1.MaxWorkers != 2 || st1.EffectiveNmapRate != 60 || st1.EffectiveNucleiRate != 15 {
		t.Fatalf("run 1 rate/worker stats = %+v, want workers=2 nmap=60 nuclei=15", st1)
	}

	// Run 2: measures Run 1 (~10ms/IP) and adapts toward ~100 IPs per batch (~1s target).
	r2, err := s.StartRun(ctx, nil, pid)
	if err != nil {
		t.Fatal(err)
	}
	r2 = waitRun(t, s, r2.ID)
	if r2.Status != "done" {
		t.Fatalf("run 2 = %+v, want done", r2)
	}
	st2 := parseStats(r2.Stats)
	if st2.BatchSizing != "adaptive" || st2.BatchHistorySamples != 1 || st2.MeasuredSecPerIP <= 0 {
		t.Fatalf("run 2 stats = %+v, want adaptive with 1 sample", st2)
	}
	if st2.BatchSize < 65 || st2.BatchSize > 115 {
		t.Fatalf("run 2 adapted batch_size = %d (sec/ip=%f), want near 100 [65..115]", st2.BatchSize, st2.MeasuredSecPerIP)
	}
	if len(st2.BatchSizes) < 3 {
		t.Fatalf("run 2 batch_sizes = %v, want >= 3 batches for 254 IPs", st2.BatchSizes)
	}
	bs2, err := s.ListBatches(ctx, r2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bs2[0].DurationMs == nil || *bs2[0].DurationMs < 600 || *bs2[0].DurationMs > 1800 {
		t.Fatalf("run 2 first full batch duration_ms = %v, want near 1000ms", bs2[0].DurationMs)
	}
	t.Logf("run 2: size=%d batches=%v first_dur_ms=%d sec_per_ip=%.4f", st2.BatchSize, st2.BatchSizes, *bs2[0].DurationMs, st2.MeasuredSecPerIP)

	// Run 3: stays converged near target_batch_seconds with history from runs 1 & 2.
	r3, err := s.StartRun(ctx, nil, pid)
	if err != nil {
		t.Fatal(err)
	}
	r3 = waitRun(t, s, r3.ID)
	if r3.Status != "done" {
		t.Fatalf("run 3 = %+v, want done", r3)
	}
	st3 := parseStats(r3.Stats)
	if st3.BatchSizing != "adaptive" || st3.BatchHistorySamples != 1+len(bs2) {
		t.Fatalf("run 3 stats = %+v, want adaptive with %d samples", st3, 1+len(bs2))
	}
	if st3.BatchSize < 65 || st3.BatchSize > 115 {
		t.Fatalf("run 3 adapted batch_size = %d (sec/ip=%f), want near 100 [65..115]", st3.BatchSize, st3.MeasuredSecPerIP)
	}
	t.Logf("run 3: size=%d batches=%v sec_per_ip=%.4f", st3.BatchSize, st3.BatchSizes, st3.MeasuredSecPerIP)

	// History is per-profile: otherPID has no finished batches yet, so it uses default sizing.
	rOther, err := s.StartRun(ctx, nil, otherPID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StopRun(ctx, nil, rOther.ID); err != nil {
		t.Fatal(err)
	}
	stOther := parseStats(rOther.Stats)
	if stOther.BatchSizing != "default" || stOther.BatchSize != DefaultBatchSize {
		t.Fatalf("other profile stats = %+v, want default %d", stOther, DefaultBatchSize)
	}

	// Verify per-profile rate limits divided across the global worker cap reached every scanner.
	fakeNmap.mu.Lock()
	nmapRates := append([]int(nil), fakeNmap.maxRates...)
	fakeNmap.mu.Unlock()
	if len(nmapRates) == 0 {
		t.Fatal("nmap never ran")
	}
	for _, r := range nmapRates {
		if r != 60 {
			t.Fatalf("nmap received MaxRate=%d, want 60 (120 / 2 workers)", r)
		}
	}
	fakeHTTPX.mu.Lock()
	httpxRates := append([]int(nil), fakeHTTPX.rates...)
	fakeHTTPX.mu.Unlock()
	if len(httpxRates) == 0 {
		t.Fatal("httpx never ran")
	}
	for _, r := range httpxRates {
		if r != 15 {
			t.Fatalf("httpx received RateLimit=%d, want 15 (30 / 2 workers)", r)
		}
	}
	fakeNuclei.mu.Lock()
	nucleiRates := append([]int(nil), fakeNuclei.rates...)
	fakeNuclei.mu.Unlock()
	if len(nucleiRates) == 0 {
		t.Fatal("nuclei never ran")
	}
	for _, r := range nucleiRates {
		if r != 15 {
			t.Fatalf("nuclei received RateLimit=%d, want 15 (30 / 2 workers)", r)
		}
	}
}

func TestConcurrencyCap(t *testing.T) {
	for _, capN := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("workers=%d", capN), func(t *testing.T) {
			pool := dbtest.Fresh(t)
			ctx := context.Background()

			var pid int64
			if err := pool.QueryRow(ctx, `
				INSERT INTO profiles (name, ports, nmap_max_rate, nuclei_rate)
				VALUES ('cap-test', '80', 100, 30) RETURNING id`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO scope_entries (kind, value, list, profile_id) VALUES ('cidr', '172.30.0.0/27', 'include', $1)`, pid); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO targets (kind, value, source) VALUES ('cidr', '172.30.0.0/27', 'manual')`); err != nil {
				t.Fatal(err)
			}

			// 32 IPs / BatchSize 5 = 7 batches, each taking 150ms.
			fakeNmap := &latencyNmap{fixed: 150 * time.Millisecond}
			fakeHTTPX := &rateRecordingScanner{name: "httpx", scanType: "httpx Scan"}
			fakeNuclei := &rateRecordingScanner{name: "nuclei", scanType: "Nuclei Scan"}

			s, err := New(pool, Config{
				Scanner:   fakeNmap,
				HTTPX:     fakeHTTPX,
				Nuclei:    fakeNuclei,
				BatchSize: 5,
				Workers:   capN,
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

			r, err := s.StartRun(ctx, nil, pid)
			if err != nil {
				t.Fatal(err)
			}
			if r.BatchesTotal != 7 {
				t.Fatalf("batches = %d, want 7", r.BatchesTotal)
			}
			r = waitRun(t, s, r.ID)
			if r.Status != "done" || r.BatchesDone != 7 {
				t.Fatalf("run = %+v, want done with 7 batches", r)
			}

			maxSeen := int(fakeNmap.maxObserved.Load())
			if maxSeen > capN {
				t.Fatalf("max concurrent batches = %d, exceeded cap %d", maxSeen, capN)
			}
			if maxSeen != capN {
				t.Fatalf("max concurrent batches = %d, expected to reach cap %d", maxSeen, capN)
			}

			wantNmapRate := PerWorkerRate(100, capN)
			fakeNmap.mu.Lock()
			defer fakeNmap.mu.Unlock()
			for _, rate := range fakeNmap.maxRates {
				if rate != wantNmapRate {
					t.Fatalf("nmap MaxRate = %d, want %d for %d workers", rate, wantNmapRate, capN)
				}
				if rate*capN > 100 {
					t.Fatalf("aggregate rate %d * %d = %d exceeds profile nmap_max_rate 100", rate, capN, rate*capN)
				}
			}
		})
	}
}
