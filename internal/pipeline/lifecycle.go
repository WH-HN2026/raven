package pipeline

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
)

type lifecycleStats struct {
	reprobed       int
	recovered      []netip.Addr
	becameUnstable int
	inactiveIPs    []string
}

func (l lifecycleStats) runStats() map[string]any {
	return map[string]any{
		"reprobed":        l.reprobed,
		"recovered":       len(l.recovered),
		"became_unstable": l.becameUnstable,
		"became_inactive": len(l.inactiveIPs),
		"inactive_ips":    nonNil(l.inactiveIPs),
	}
}

func nextHostState(state string, misses, threshold int32, up bool) (string, int32) {
	if up {
		return "active", 0
	}
	if misses < math.MaxInt32 {
		misses++
	}
	if state == "inactive" || misses >= threshold {
		return "inactive", misses
	}
	return "unstable", misses
}

func listReprobeIPs(ctx context.Context, q *gen.Queries, run gen.Run, plan Plan) ([]netip.Addr, error) {
	var down []netip.Addr
	for _, observation := range plan.Observations {
		if observation.HostLevel && !observation.Up {
			down = append(down, observation.IP)
		}
	}
	ips, err := q.ListRunReprobeIPs(ctx, gen.ListRunReprobeIPsParams{
		RunID: run.ID, ProfileID: run.ProfileID, LastBatchDown: down,
	})
	if err != nil {
		return nil, fmt.Errorf("list re-probe IPs of run %d: %w", run.ID, err)
	}
	return ips, nil
}

// reprobeHosts runs outside the transaction so a stop can cancel the last
// batch's job. The regular nmap scanner does its usual host discovery with
// the profile's max rate and checks one TCP port per IP. Prefer a known open
// port in the profile, falling back to its first port.
func (s *Service) reprobeHosts(ctx context.Context, ips []netip.Addr, prof gen.Profile, ports PortSet) (lifecycleStats, error) {
	services, err := gen.New(s.pool).ListOpenServicesOf(ctx, ips)
	if err != nil {
		return lifecycleStats{}, fmt.Errorf("list open services for re-probe: %w", err)
	}
	known := make(map[netip.Addr]uint16, len(ips))
	for _, service := range services {
		port := uint16(service.Port)
		if service.Proto == "tcp" && ports.Contains(port) && (known[service.Ip] == 0 || port < known[service.Ip]) {
			known[service.Ip] = port
		}
	}
	byPort := make(map[uint16][]netip.Addr)
	for _, ip := range ips {
		port := known[ip]
		if port == 0 {
			port = ports[0][0]
		}
		byPort[port] = append(byPort[port], ip)
	}

	stats := lifecycleStats{reprobed: len(ips)}
	for _, port := range slices.Sorted(maps.Keys(byPort)) {
		for _, batch := range SplitBatches(byPort[port], s.cfg.BatchSize) {
			res, err := s.cfg.Scanner.Run(ctx, scanner.Input{IPs: batch},
				scanner.Options{Ports: strconv.Itoa(int(port)), MaxRate: s.nmapRate(prof)})
			if err != nil {
				return lifecycleStats{}, fmt.Errorf("re-probe hosts on port %d: %w", port, err)
			}
			stats.recovered = append(stats.recovered, BuildPlan(batch, nil, res.Observations).Up...)
		}
	}
	return stats, nil
}

// apply writes reachability only for re-probe recoveries. A single-port check
// supplies no complete service inventory, so service rows and artifacts stay
// with the regular batch scan. The up observation keeps the run's host count
// and history consistent. Misses and transitions commit with the run status.
func (l *lifecycleStats) apply(ctx context.Context, q *gen.Queries, run gen.Run, threshold int32, seen time.Time) error {
	if n := len(l.recovered); n > 0 {
		ports, ups := make([]int32, n), make([]bool, n)
		for i := range l.recovered {
			ports[i], ups[i] = -1, true
		}
		if err := q.InsertRunObservations(ctx, gen.InsertRunObservationsParams{
			RunID: run.ID, Ips: l.recovered, Ports: ports, Ups: ups, ServiceFps: make([]string, n), ObservedAt: seen,
		}); err != nil {
			return fmt.Errorf("record re-probe recoveries of run %d: %w", run.ID, err)
		}
	}

	hosts, err := q.ListRunLifecycleHosts(ctx, gen.ListRunLifecycleHostsParams{
		RunID: run.ID, ProfileID: run.ProfileID, Recovered: l.recovered,
	})
	if err != nil {
		return fmt.Errorf("list lifecycle hosts of run %d: %w", run.ID, err)
	}
	if len(hosts) == 0 {
		return nil
	}
	updates := gen.UpdateHostLifecycleParams{Seen: seen}
	for _, h := range hosts {
		state, misses := nextHostState(h.State, h.MissCount, threshold, h.Up)
		if state != h.State {
			switch state {
			case "unstable":
				l.becameUnstable++
			case "inactive":
				l.inactiveIPs = append(l.inactiveIPs, h.Ip.String())
			}
		}
		updates.Ips = append(updates.Ips, h.Ip)
		updates.States = append(updates.States, state)
		updates.MissCounts = append(updates.MissCounts, misses)
		updates.Ups = append(updates.Ups, h.Up)
	}
	if err := q.UpdateHostLifecycle(ctx, updates); err != nil {
		return fmt.Errorf("update lifecycle hosts of run %d: %w", run.ID, err)
	}
	return nil
}
