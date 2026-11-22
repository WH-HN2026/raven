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
	"sync/atomic"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nikto"
	"github.com/WH-HN2026/raven/internal/targets"
)

type fakeNikto struct {
	mu      sync.Mutex
	calls   atomic.Int32
	urls    []string
	failURL string
}

func (f *fakeNikto) Name() string         { return StageNikto }
func (f *fakeNikto) DojoScanType() string { return "Nikto Scan" }

func (f *fakeNikto) Run(_ context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	f.calls.Add(1)
	if opt.RateLimit < 1 {
		return nil, errors.New("fakeNikto: rate limit must be positive")
	}
	if len(in.URLs) != 1 {
		return nil, errors.New("fakeNikto: expected one URL per call")
	}
	u := in.URLs[0]
	f.mu.Lock()
	f.urls = append(f.urls, u)
	fail := f.failURL
	f.mu.Unlock()
	if u == fail {
		return nil, errors.New("simulated nikto failure on " + u)
	}
	host := in.IPs[0].String()
	// Derive IP from URL so multi-IP batches produce matching reports.
	for _, ip := range in.IPs {
		if u == "http://"+ip.String()+":80" || u == "http://"+ip.String()+":8080" || u == "https://"+ip.String()+":443" {
			host = ip.String()
			break
		}
	}
	raw := []byte(`[{"host":"` + host + `","ip":"` + host + `","port":"80","vulnerabilities":[{"id":"999103","method":"GET","url":"/","msg":"Missing X-Content-Type-Options on ` + host + `"}]}]`)
	return nikto.Parse(raw)
}

func TestNiktoStageIntegration(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()

	ip1 := netip.MustParseAddr("172.30.0.19")
	ip2 := netip.MustParseAddr("172.30.0.20")

	nmapRaw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	// Replace lab fixture IPs with ip1 and ip2 both serving HTTP:80.
	fakeNmap := &fakeScanner{raw: nmapRaw}
	fakeHTTPX := &staticHTTPX{
		raw: []byte(
			`{"timestamp":"2026-11-21T20:00:00Z","input":"http://172.30.0.19:80","url":"http://172.30.0.19:80","host_ip":"172.30.0.19","status_code":200,"title":"nginx"}` + "\n" +
				`{"timestamp":"2026-11-21T20:00:00Z","input":"http://172.30.0.20:80","url":"http://172.30.0.20:80","host_ip":"172.30.0.20","status_code":200,"title":"staging"}` + "\n",
		),
	}
	fakeNmapTwo := &staticNmap{ips: []netip.Addr{ip1, ip2}}
	_ = fakeNmap
	fn := &fakeNikto{}
	hook := &recordingHook{}

	s, err := New(pool, Config{
		Scanner: fakeNmapTwo, HTTPX: fakeHTTPX, Nuclei: &countingNuclei{}, Nikto: fn,
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

	for _, addr := range []string{ip1.String(), ip2.String()} {
		e, err := targets.NewEntry(addr, "", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&targets.Store{Pool: pool}).AddTargets(ctx, nil, "manual", []targets.Entry{e}); err != nil {
			t.Fatal(err)
		}
	}

	// 1) Default profile (no nikto stage): nikto must NOT run and no artifact stored.
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
	if fn.calls.Load() != 0 {
		t.Fatalf("nikto called %d times during default run, want 0", fn.calls.Load())
	}
	if n := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'nikto'`, r1.ID); n != 0 {
		t.Fatalf("default run wrote %d nikto artifacts, want 0", n)
	}

	// 2) Aggressive profile with nikto: both URLs succeed, artifact stored, nikto_errors=0.
	var aggID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO profiles (name, ports, stages)
		VALUES ('agg-nikto-it', '80', ARRAY['nmap', 'httpx', 'nikto'])
		RETURNING id`).Scan(&aggID); err != nil {
		t.Fatal(err)
	}
	r2, err := s.StartRun(ctx, nil, aggID)
	if err != nil {
		t.Fatal(err)
	}
	r2 = waitRun(t, s, r2.ID)
	if r2.Status != "done" || !slices.Equal(r2.Stages, []string{StageNmap, StageHTTPX, StageNikto}) {
		t.Fatalf("nikto run = %+v", r2)
	}
	if fn.calls.Load() != 2 {
		t.Fatalf("nikto calls = %d, want 2", fn.calls.Load())
	}
	var rawArtifact string
	if err := pool.QueryRow(ctx, `SELECT raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'nikto'`, r2.ID).Scan(&rawArtifact); err != nil {
		t.Fatalf("load nikto artifact: %v", err)
	}
	parsed, err := nikto.Parse([]byte(rawArtifact))
	if err != nil || len(parsed.PerIP(ip1)) == 0 || len(parsed.PerIP(ip2)) == 0 {
		t.Fatalf("parsed nikto artifact = %+v, err=%v", parsed, err)
	}
	var stats2 map[string]any
	if err := json.Unmarshal(r2.Stats, &stats2); err != nil {
		t.Fatal(err)
	}
	if stats2["nikto_errors"] != float64(0) || stats2["nikto_urls"] != float64(2) {
		t.Fatalf("r2 stats = %s, want nikto_errors=0 nikto_urls=2", r2.Stats)
	}

	// 3) Per-URL error does NOT fail the batch: ip1 fails, ip2 succeeds, nikto_errors=1,
	//    artifact keeps ip2 and omits failed ip1.
	fn.mu.Lock()
	fn.failURL = "http://172.30.0.19:80"
	fn.mu.Unlock()
	r3, err := s.StartRun(ctx, nil, aggID)
	if err != nil {
		t.Fatal(err)
	}
	r3 = waitRun(t, s, r3.ID)
	if r3.Status != "done" {
		t.Fatalf("partial-error nikto run status = %s, want done", r3.Status)
	}
	var stats3 map[string]any
	if err := json.Unmarshal(r3.Stats, &stats3); err != nil {
		t.Fatal(err)
	}
	if stats3["nikto_errors"] != float64(1) || stats3["nikto_urls"] != float64(2) {
		t.Fatalf("r3 stats = %s, want nikto_errors=1 nikto_urls=2", r3.Stats)
	}
	if err := pool.QueryRow(ctx, `SELECT raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'nikto'`, r3.ID).Scan(&rawArtifact); err != nil {
		t.Fatalf("load partial nikto artifact: %v", err)
	}
	parsed3, err := nikto.Parse([]byte(rawArtifact))
	if err != nil {
		t.Fatal(err)
	}
	if parsed3.PerIP(ip1) != nil || len(parsed3.PerIP(ip2)) == 0 {
		t.Fatalf("partial nikto artifact should omit failed %s and include %s", ip1, ip2)
	}
}

type staticNmap struct {
	ips []netip.Addr
}

func (*staticNmap) Name() string         { return StageNmap }
func (*staticNmap) DojoScanType() string { return "Nmap Scan" }
func (s *staticNmap) Run(_ context.Context, _ scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	obs := make([]scanner.Observation, 0, len(s.ips)*2)
	for _, ip := range s.ips {
		obs = append(obs,
			scanner.Observation{Kind: scanner.ObsHost, IP: ip, Up: true},
			scanner.Observation{Kind: scanner.ObsService, IP: ip, Port: 80, Proto: "tcp", Service: "http"},
		)
	}
	return &scanner.Result{Raw: []byte("<nmaprun/>"), Observations: obs}, nil
}

type staticHTTPX struct {
	raw []byte
}

func (*staticHTTPX) Name() string         { return StageHTTPX }
func (*staticHTTPX) DojoScanType() string { return "httpx Scan" }
func (s *staticHTTPX) Run(_ context.Context, _ scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	return httpx.Parse(s.raw)
}
