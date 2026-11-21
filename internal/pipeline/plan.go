package pipeline

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

// BatchSize is the fixed number of IPs per batch (S5 makes it adaptive).
const BatchSize = 256

// SplitBatches cuts ips into consecutive chunks of at most size IPs.
func SplitBatches(ips []netip.Addr, size int) [][]netip.Addr {
	if size < 1 {
		size = BatchSize
	}
	var out [][]netip.Addr
	for len(ips) > 0 {
		n := min(size, len(ips))
		out = append(out, ips[:n:n])
		ips = ips[n:]
	}
	return out
}

// PortSet is a parsed nmap port spec ("22,80,8000-8100").
type PortSet [][2]uint16

// ParsePorts validates spec with the nmap allowlist rules and parses it.
func ParsePorts(spec string) (PortSet, error) {
	if err := nmap.CheckPorts(spec); err != nil {
		return nil, fmt.Errorf("profile ports: %w", err)
	}
	var ps PortSet
	for part := range strings.SplitSeq(spec, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			hi = lo
		}
		l, _ := strconv.ParseUint(lo, 10, 16)
		h, _ := strconv.ParseUint(hi, 10, 16)
		ps = append(ps, [2]uint16{uint16(l), uint16(h)})
	}
	return ps, nil
}

func (ps PortSet) Contains(p uint16) bool {
	for _, r := range ps {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}

// HostRow is an up host to upsert.
type HostRow struct {
	IP        netip.Addr
	Hostnames []string
}

// ServiceRow is an open service to upsert.
type ServiceRow struct {
	IP                                         netip.Addr
	Port                                       uint16
	Proto                                      string
	Name, Product, Version, CPE, Banner, Title string
}

func (s ServiceRow) key() svcKey { return svcKey{s.IP, s.Port, s.Proto} }

type svcKey struct {
	ip    netip.Addr
	port  uint16
	proto string
}

// ObsRow is one run_observations row; Port 0 with HostLevel = host up/down.
type ObsRow struct {
	IP        netip.Addr
	Port      uint16
	HostLevel bool
	Up        bool
}

// Plan is what one batch writes into our DB, computed without the DB.
type Plan struct {
	Up           []netip.Addr // IPs that responded, sorted
	Hosts        []HostRow    // one per up IP
	Services     []ServiceRow // open ports of up IPs
	Observations []ObsRow     // host-level for every batch IP, port-level for open ports
}

// BuildPlan maps scanner observations of one batch onto rows:
//   - every batch IP gets a host-level observation; IPs the scanner didn't
//     report at all count as down;
//   - up hosts get upserted with their known host names (scan list + scanner);
//   - open ports of up hosts become services and port-level observations.
//
// Observations for IPs outside the batch are ignored.
func BuildPlan(ips []netip.Addr, hostnames map[netip.Addr][]string, obs []scanner.Observation) Plan {
	inBatch := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		inBatch[ip.Unmap()] = true
	}
	up := map[netip.Addr]bool{}
	names := map[netip.Addr][]string{}
	for _, o := range obs {
		ip := o.IP.Unmap()
		if o.Kind == scanner.ObsHost && inBatch[ip] && o.Up {
			up[ip] = true
		}
		if o.Hostname != "" {
			names[ip] = append(names[ip], o.Hostname)
		}
	}

	var p Plan
	for ip := range up {
		p.Up = append(p.Up, ip)
	}
	slices.SortFunc(p.Up, netip.Addr.Compare)
	for _, ip := range p.Up {
		hn := append(slices.Clone(hostnames[ip]), names[ip]...)
		slices.Sort(hn)
		p.Hosts = append(p.Hosts, HostRow{IP: ip, Hostnames: slices.Compact(hn)})
	}

	httpTitles := map[svcKey]string{}
	for _, o := range obs {
		ip := o.IP.Unmap()
		if o.Kind == scanner.ObsHTTP && up[ip] && o.HTTP != nil && o.HTTP.Title != "" {
			httpTitles[svcKey{ip, o.Port, cmp.Or(o.Proto, "tcp")}] = o.HTTP.Title
		}
	}

	seen := map[svcKey]bool{}
	for _, o := range obs {
		ip := o.IP.Unmap()
		if o.Kind != scanner.ObsService || !up[ip] {
			continue
		}
		proto := cmp.Or(o.Proto, "tcp")
		s := ServiceRow{IP: ip, Port: o.Port, Proto: proto,
			Name: o.Service, Product: o.Product, Version: o.Version, CPE: o.CPE, Banner: o.Banner,
			Title: httpTitles[svcKey{ip, o.Port, proto}]}
		if seen[s.key()] {
			continue
		}
		seen[s.key()] = true
		p.Services = append(p.Services, s)
	}
	slices.SortFunc(p.Services, func(a, b ServiceRow) int {
		return cmp.Or(a.IP.Compare(b.IP), cmp.Compare(a.Port, b.Port), cmp.Compare(a.Proto, b.Proto))
	})

	for _, ip := range ips {
		ip = ip.Unmap()
		p.Observations = append(p.Observations, ObsRow{IP: ip, HostLevel: true, Up: up[ip]})
	}
	for _, s := range p.Services {
		p.Observations = append(p.Observations, ObsRow{IP: s.IP, Port: s.Port, Up: true})
	}
	return p
}

// OpenService is a service row that is currently 'open' in our DB.
type OpenService struct {
	ID    int64
	IP    netip.Addr
	Port  uint16
	Proto string
}

// GoneServices returns the ids of services that were open before but are
// not open in this scan: only for hosts that responded (a down host keeps
// its services; that's S6's miss counting), only TCP (we don't scan UDP),
// and only ports in the profile's port list (a port this profile doesn't
// scan says nothing about it).
func GoneServices(p Plan, before []OpenService, ports PortSet) []int64 {
	up := map[netip.Addr]bool{}
	for _, ip := range p.Up {
		up[ip] = true
	}
	open := map[svcKey]bool{}
	for _, s := range p.Services {
		open[s.key()] = true
	}
	var gone []int64
	for _, s := range before {
		ip := s.IP.Unmap()
		if !up[ip] || s.Proto != "tcp" || !ports.Contains(s.Port) || open[svcKey{ip, s.Port, s.Proto}] {
			continue
		}
		gone = append(gone, s.ID)
	}
	return gone
}

// BatchCounts is the per-run tally of batch states.
type BatchCounts struct {
	Unfinished, Failed int64
}

// RunOutcome decides the run's final status once its batches are counted:
// finished is false while any batch is pending or running.
func RunOutcome(c BatchCounts) (status string, finished bool) {
	if c.Unfinished > 0 {
		return "", false
	}
	if c.Failed > 0 {
		return "failed", true
	}
	return "done", true
}
