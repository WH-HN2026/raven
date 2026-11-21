//go:build integration

package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
)

type lifecycleTestScanner func(context.Context, scanner.Input, scanner.Options) (*scanner.Result, error)

func (lifecycleTestScanner) Name() string         { return "nmap" }
func (lifecycleTestScanner) DojoScanType() string { return "Nmap Scan" }

func (f lifecycleTestScanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	return f(ctx, in, opt)
}

type lifecycleFixture struct {
	up, retryUp    []string
	reprobeStarted chan struct{}
	cancelled      chan struct{}
	mu             sync.Mutex
	reprobed       []string
}

func TestHostLifecycle(t *testing.T) {
	const flap, recovers, unknown = "172.30.0.27", "172.30.0.28", "172.30.0.29"
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	var profileID, otherProfileID int64
	for name, id := range map[string]*int64{"s6": &profileID, "other": &otherProfileID} {
		if err := pool.QueryRow(ctx, `INSERT INTO profiles (name, ports, nmap_max_rate)
			VALUES ($1, '22,2222', 40) RETURNING id`, name).Scan(id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO scope_entries (kind, value, list, profile_id)
			VALUES ('cidr', '172.30.0.24/29', 'include', $1)`, *id); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{flap, recovers, unknown} {
		if _, err := pool.Exec(ctx, `INSERT INTO targets (kind, value, source) VALUES ('ip', $1, 'manual')`, ip); err != nil {
			t.Fatal(err)
		}
	}

	var current atomic.Pointer[lifecycleFixture]
	fake := lifecycleTestScanner(func(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
		if opt.MaxRate != 20 || len(in.IPs) != 1 {
			return nil, fmt.Errorf("unexpected scanner input %v and options %+v", in.IPs, opt)
		}
		fixture := current.Load()
		ip := in.IPs[0]
		up := fixture.up
		switch opt.Ports {
		case "22,2222":
		case "2222":
			fixture.mu.Lock()
			fixture.reprobed = append(fixture.reprobed, ip.String())
			fixture.mu.Unlock()
			up = fixture.retryUp
			if fixture.reprobeStarted != nil {
				close(fixture.reprobeStarted)
				<-ctx.Done()
				close(fixture.cancelled)
				return nil, ctx.Err()
			}
		default:
			return nil, fmt.Errorf("unexpected port spec %q", opt.Ports)
		}
		if !slices.Contains(up, ip.String()) {
			return &scanner.Result{}, nil
		}
		return &scanner.Result{Observations: []scanner.Observation{
			{IP: ip, Kind: scanner.ObsHost, Up: true},
			{IP: ip, Kind: scanner.ObsService, Port: 2222, Proto: "tcp", Service: "ssh"},
		}}, nil
	})
	s, err := New(pool, Config{Scanner: fake, BatchSize: 1, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdown); err != nil {
			t.Error(err)
		}
	})

	type stats struct {
		Reprobed       int      `json:"reprobed"`
		Recovered      int      `json:"recovered"`
		BecameUnstable int      `json:"became_unstable"`
		BecameInactive int      `json:"became_inactive"`
		InactiveIPs    []string `json:"inactive_ips"`
	}
	run := func(pID int64, up, retryUp, wantProbes []string, wantHostsUp int32, want stats) Run {
		t.Helper()
		fixture := &lifecycleFixture{up: up, retryUp: retryUp}
		current.Store(fixture)
		r, err := s.StartRun(ctx, nil, pID)
		if err != nil {
			t.Fatal(err)
		}
		r = waitRun(t, s, r.ID)
		if r.Status != "done" || r.HostsUp != wantHostsUp {
			t.Fatalf("run %d status/hosts_up = %s/%d, want done/%d", r.ID, r.Status, r.HostsUp, wantHostsUp)
		}
		var got stats
		if err := json.Unmarshal(r.Stats, &got); err != nil {
			t.Fatal(err)
		}
		if got.Reprobed != want.Reprobed || got.Recovered != want.Recovered ||
			got.BecameUnstable != want.BecameUnstable || got.BecameInactive != want.BecameInactive ||
			!slices.Equal(got.InactiveIPs, want.InactiveIPs) {
			t.Fatalf("run %d lifecycle stats = %+v, want %+v", r.ID, got, want)
		}
		fixture.mu.Lock()
		probes := slices.Clone(fixture.reprobed)
		fixture.mu.Unlock()
		slices.Sort(probes)
		if !slices.Equal(probes, wantProbes) {
			t.Fatalf("run %d re-probed %v, want %v", r.ID, probes, wantProbes)
		}
		return r
	}
	checkHost := func(ip, wantState string, wantMisses int) time.Time {
		t.Helper()
		var state string
		var misses int
		var seen time.Time
		if err := pool.QueryRow(ctx, `SELECT state, miss_count, last_seen FROM hosts WHERE ip = $1`,
			netip.MustParseAddr(ip)).Scan(&state, &misses, &seen); err != nil {
			t.Fatal(err)
		}
		if state != wantState || misses != wantMisses {
			t.Fatalf("host %s state and misses = %s/%d, want %s/%d", ip, state, misses, wantState, wantMisses)
		}
		return seen
	}

	both := []string{flap, recovers}
	run(profileID, both, nil, nil, 2, stats{})
	firstSeen := checkHost(flap, "active", 0)
	recoversSeen := checkHost(recovers, "active", 0)
	if _, err := pool.Exec(ctx, `UPDATE hosts SET owner = 'ops', overrides = '{"hostnames":["user"]}' WHERE ip = '172.30.0.27'`); err != nil {
		t.Fatal(err)
	}

	run(otherProfileID, nil, nil, nil, 0, stats{})
	checkHost(flap, "active", 0)

	second := run(profileID, nil, []string{recovers}, both, 1, stats{Reprobed: 2, Recovered: 1, BecameUnstable: 1})
	if !checkHost(flap, "unstable", 1).Equal(firstSeen) {
		t.Error("last_seen changed on a miss")
	}
	if !checkHost(recovers, "active", 0).After(recoversSeen) {
		t.Error("re-probe recovery did not advance last_seen")
	}
	if n := count(t, pool, `SELECT count(*) FROM run_observations
		WHERE run_id = $1 AND ip = '172.30.0.28' AND port IS NULL AND up`, second.ID); n != 1 {
		t.Error("recovered host has no up observation")
	}
	if n := count(t, pool, `SELECT count(*) FROM run_observations WHERE run_id = $1 AND port IS NOT NULL`, second.ID); n != 0 {
		t.Error("single-port re-probe wrote service observations")
	}

	run(profileID, []string{recovers}, nil, nil, 1, stats{})
	checkHost(flap, "unstable", 2)
	run(profileID, []string{recovers}, nil, nil, 1, stats{BecameInactive: 1, InactiveIPs: []string{flap}})
	checkHost(flap, "inactive", 3)
	run(profileID, []string{recovers}, nil, nil, 1, stats{})
	checkHost(flap, "inactive", 4)
	run(profileID, both, nil, nil, 2, stats{})
	checkHost(flap, "active", 0)

	// Stop while the final batch is re-probing. The job must release the run
	// lock and keep the batch cancellable until the lifecycle changes commit.
	fixture := &lifecycleFixture{
		up: []string{recovers}, reprobeStarted: make(chan struct{}), cancelled: make(chan struct{}),
	}
	current.Store(fixture)
	stopping, err := s.StartRun(ctx, nil, profileID)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-fixture.reprobeStarted:
	case <-time.After(15 * time.Second):
		t.Fatal("re-probe did not start")
	}
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stopped, err := s.StopRun(stopCtx, nil, stopping.ID)
	if err != nil || stopped.Status != "stopped" {
		t.Fatalf("stop during re-probe: status = %q, err = %v", stopped.Status, err)
	}
	select {
	case <-fixture.cancelled:
	case <-time.After(15 * time.Second):
		t.Fatal("re-probe was not cancelled")
	}
	checkHost(flap, "active", 0)
	if n := count(t, pool, `SELECT count(*) FROM hosts
		WHERE ip = '172.30.0.27' AND owner = 'ops' AND overrides = '{"hostnames":["user"]}'`); n != 1 {
		t.Error("lifecycle changed user-owned fields")
	}
	if n := count(t, pool, `SELECT count(*) FROM hosts WHERE ip = '172.30.0.29'`); n != 0 {
		t.Error("created a host which never responded")
	}
}
