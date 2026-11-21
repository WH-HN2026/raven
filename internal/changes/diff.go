// Package changes compares scan runs (task C1): which hosts and services
// appeared, disappeared or changed their fingerprint between two runs, and
// a per-host up/down timeline over the last runs.
//
// Per-run state comes from three places, none of which needs a change in
// the pipeline:
//   - run_observations: host up/down and the open ports of every run;
//   - the run's nmap artifacts (encrypted raw XML, re-parsed with
//     nmap.Parse): service name / product / version and the http-title;
//   - http_observations of the run: page title and technologies.
//
// The services table holds only the current fingerprint, so it can't be
// used to compare two past runs.
package changes

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// SvcKey identifies a service within a run. run_observations has no proto
// column; we scan TCP only.
type SvcKey struct {
	IP   netip.Addr
	Port uint16
}

// Fingerprint is what a service looked like in one run.
type Fingerprint struct {
	Name         string   `json:"name"`
	Product      string   `json:"product"`
	Version      string   `json:"version"`
	Title        string   `json:"title"`
	Technologies []string `json:"technologies"`
}

// Service is one open port in a run's snapshot.
type Service struct {
	Proto string
	FP    Fingerprint
	// HasNmap: the run's nmap output described this service (name,
	// product, version and the nmap title are known).
	HasNmap bool
	// HasHTTP: the run has http_observations for it (title, technologies).
	HasHTTP bool

	nmapTitle, httpTitle string
}

// Snapshot is the observed state of one run.
type Snapshot struct {
	Hosts    map[netip.Addr]bool // observed IPs: true = up
	Services map[SvcKey]*Service // open ports of up hosts
}

// ObsRow is a run_observations row; Port -1 = host-level.
type ObsRow struct {
	IP   netip.Addr
	Port int32
	Up   bool
}

// HTTPRow is one http_observation of the run (rows of a service ordered by URL).
type HTTPRow struct {
	IP           netip.Addr
	Port         uint16
	Title        string
	Technologies []string
}

// BuildSnapshot assembles a run's state. nmapObs are the parsed nmap
// observations of the run's artifacts in order (a later batch wins).
func BuildSnapshot(obs []ObsRow, nmapObs []scanner.Observation, http []HTTPRow) Snapshot {
	s := Snapshot{Hosts: map[netip.Addr]bool{}, Services: map[SvcKey]*Service{}}
	for _, o := range obs {
		if o.Port < 0 {
			s.Hosts[o.IP.Unmap()] = o.Up
		}
	}
	for _, o := range obs {
		ip := o.IP.Unmap()
		if o.Port >= 0 && o.Up && s.Hosts[ip] {
			s.Services[SvcKey{ip, uint16(o.Port)}] = &Service{Proto: "tcp"}
		}
	}
	for _, o := range nmapObs {
		sv := s.Services[SvcKey{o.IP.Unmap(), o.Port}]
		if sv == nil {
			continue
		}
		switch o.Kind {
		case scanner.ObsService:
			sv.Proto = cmp.Or(o.Proto, sv.Proto)
			sv.FP.Name, sv.FP.Product, sv.FP.Version = o.Service, o.Product, o.Version
			sv.HasNmap = true
		case scanner.ObsHTTP:
			if o.HTTP != nil {
				sv.nmapTitle = o.HTTP.Title
			}
		}
	}
	for _, h := range http {
		sv := s.Services[SvcKey{h.IP.Unmap(), h.Port}]
		if sv == nil {
			continue
		}
		sv.HasHTTP = true
		sv.httpTitle = cmp.Or(sv.httpTitle, h.Title)
		sv.FP.Technologies = append(sv.FP.Technologies, h.Technologies...)
	}
	for _, sv := range s.Services {
		sv.FP.Title = sv.nmapTitle
		if sv.HasHTTP {
			sv.FP.Title = sv.httpTitle // httpx wins over nmap's http-title
		}
		slices.Sort(sv.FP.Technologies)
		sv.FP.Technologies = slices.Compact(sv.FP.Technologies)
		if sv.FP.Technologies == nil {
			sv.FP.Technologies = []string{}
		}
	}
	return s
}

// HostChange is a host that came up or went down between the runs.
type HostChange struct {
	IP netip.Addr `json:"ip"`
	// OtherRun is the host's state in the run where it wasn't up:
	// "down", or "not_scanned" (only for new hosts).
	OtherRun string `json:"other_run"`
	// Ports are its open ports in the run where it was up.
	Ports []uint16 `json:"ports"`
}

// ServiceChange is a new, gone or changed service. Before is nil for new
// services, After for gone ones; Fields lists what changed.
type ServiceChange struct {
	IP     netip.Addr   `json:"ip"`
	Port   uint16       `json:"port"`
	Proto  string       `json:"proto"`
	Before *Fingerprint `json:"before"`
	After  *Fingerprint `json:"after"`
	Fields []string     `json:"fields"`
}

// Result is the full diff of two snapshots, sorted by IP and port.
type Result struct {
	HostsNew        []HostChange
	HostsGone       []HostChange
	ServicesNew     []ServiceChange
	ServicesGone    []ServiceChange
	ServicesChanged []ServiceChange
}

// Diff compares run a (from) with run b (to):
//   - host new: up in b, not up in a (down or not scanned);
//   - host gone: up in a, observed down in b (not scanned in b says nothing);
//   - services are compared only on hosts up in both runs, so a host going
//     down doesn't make its services "gone" (they're listed on the host);
//   - changed: name / product / version / title / technologies differ;
//     a field is compared only if both runs have a source for it.
func Diff(a, b Snapshot) Result {
	r := Result{
		HostsNew: []HostChange{}, HostsGone: []HostChange{},
		ServicesNew: []ServiceChange{}, ServicesGone: []ServiceChange{}, ServicesChanged: []ServiceChange{},
	}
	for ip, up := range b.Hosts {
		if !up || a.Hosts[ip] {
			continue
		}
		other := "down"
		if _, seen := a.Hosts[ip]; !seen {
			other = "not_scanned"
		}
		r.HostsNew = append(r.HostsNew, HostChange{IP: ip, OtherRun: other, Ports: b.ports(ip)})
	}
	for ip, up := range a.Hosts {
		if up && !b.Hosts[ip] {
			if _, seen := b.Hosts[ip]; seen {
				r.HostsGone = append(r.HostsGone, HostChange{IP: ip, OtherRun: "down", Ports: a.ports(ip)})
			}
		}
	}
	for k, sb := range b.Services {
		if !a.Hosts[k.IP] {
			continue
		}
		sa := a.Services[k]
		if sa == nil {
			fp := sb.FP
			r.ServicesNew = append(r.ServicesNew, ServiceChange{IP: k.IP, Port: k.Port, Proto: sb.Proto, After: &fp, Fields: []string{}})
			continue
		}
		if f := changedFields(sa, sb); len(f) > 0 {
			before, after := sa.FP, sb.FP
			r.ServicesChanged = append(r.ServicesChanged, ServiceChange{
				IP: k.IP, Port: k.Port, Proto: sb.Proto, Before: &before, After: &after, Fields: f,
			})
		}
	}
	for k, sa := range a.Services {
		if b.Hosts[k.IP] && b.Services[k] == nil {
			fp := sa.FP
			r.ServicesGone = append(r.ServicesGone, ServiceChange{IP: k.IP, Port: k.Port, Proto: sa.Proto, Before: &fp, Fields: []string{}})
		}
	}
	byIP := func(x, y HostChange) int { return x.IP.Compare(y.IP) }
	bySvc := func(x, y ServiceChange) int { return cmp.Or(x.IP.Compare(y.IP), cmp.Compare(x.Port, y.Port)) }
	slices.SortFunc(r.HostsNew, byIP)
	slices.SortFunc(r.HostsGone, byIP)
	slices.SortFunc(r.ServicesNew, bySvc)
	slices.SortFunc(r.ServicesGone, bySvc)
	slices.SortFunc(r.ServicesChanged, bySvc)
	return r
}

func (s Snapshot) ports(ip netip.Addr) []uint16 {
	out := []uint16{}
	for k := range s.Services {
		if k.IP == ip {
			out = append(out, k.Port)
		}
	}
	slices.Sort(out)
	return out
}

func changedFields(a, b *Service) []string {
	var f []string
	if a.HasNmap && b.HasNmap {
		if a.FP.Name != b.FP.Name {
			f = append(f, "name")
		}
		if a.FP.Product != b.FP.Product {
			f = append(f, "product")
		}
		if a.FP.Version != b.FP.Version {
			f = append(f, "version")
		}
	}
	if (a.HasNmap || a.HasHTTP) && (b.HasNmap || b.HasHTTP) && a.FP.Title != b.FP.Title {
		f = append(f, "title")
	}
	if a.HasHTTP && b.HasHTTP && !slices.Equal(a.FP.Technologies, b.FP.Technologies) {
		f = append(f, "technologies")
	}
	return f
}
