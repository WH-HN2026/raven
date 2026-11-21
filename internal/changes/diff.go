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

	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
)

// Change fields that are states rather than fingerprint differences (V7).
const (
	FieldSlow             = "slow"
	FieldHTTPUnresponsive = "http_unresponsive"
)

// ms returns a response time, -1 when unknown.
func ms(v *int) int {
	if v == nil {
		return -1
	}
	return *v
}

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
	// ResponseMS is the slowest URL's httpx response time; nil = no HTTP
	// answer or unknown. Not compared as a field: see "slow".
	ResponseMS *int `json:"response_ms,omitempty"`
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
	Stages   []string            // stages executed in this run; nil/empty = Default
	Hosts    map[netip.Addr]bool // observed IPs: true = up
	Services map[SvcKey]*Service // open ports of up hosts
}

// ServiceFP is the persisted per-run service fingerprint stored on
// run_observations.service_fp so diffs don't have to decrypt and XML-parse
// every nmap artifact on every request.
type ServiceFP struct {
	Proto   string `json:"proto,omitempty"`
	Name    string `json:"name,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
}

// ObsRow is a run_observations row; Port -1 = host-level.
type ObsRow struct {
	IP   netip.Addr
	Port int32
	Up   bool
	FP   *ServiceFP // non-nil when run_observations.service_fp was recorded
}

// HTTPRow is one http_observation of the run (rows of a service ordered by URL).
type HTTPRow struct {
	IP           netip.Addr
	Port         uint16
	Title        string
	Technologies []string
	ResponseMS   *int // nil = unknown
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
			sv := &Service{Proto: "tcp"}
			if o.FP != nil {
				sv.Proto = cmp.Or(o.FP.Proto, "tcp")
				sv.FP.Name = o.FP.Name
				sv.FP.Product = o.FP.Product
				sv.FP.Version = o.FP.Version
				sv.nmapTitle = o.FP.Title
				sv.HasNmap = true
			}
			s.Services[SvcKey{ip, uint16(o.Port)}] = sv
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
		if h.ResponseMS != nil && (sv.FP.ResponseMS == nil || *h.ResponseMS > *sv.FP.ResponseMS) {
			ms := *h.ResponseMS
			sv.FP.ResponseMS = &ms
		}
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
//     a field is compared only if both runs have a source for it;
//   - changed with "slow" (V7): b's response time is slow (httpx.Slow,
//     against a's) and a's wasn't above the fixed threshold;
//   - changed with "http_unresponsive" (V7): httpx answered in a, the port
//     is still open in b, but httpx got no answer in b.
func Diff(a, b Snapshot) Result {
	shared := pipeline.SharedStages(a.Stages, b.Stages)
	compareHTTP := pipeline.HasStage(shared, pipeline.StageHTTPX)
	r := Result{
		HostsNew: []HostChange{}, HostsGone: []HostChange{},
		ServicesNew: []ServiceChange{}, ServicesGone: []ServiceChange{}, ServicesChanged: []ServiceChange{},
	}
	newIPs := map[netip.Addr]bool{}
	for ip, up := range b.Hosts {
		if !up || a.Hosts[ip] {
			continue
		}
		other := "down"
		if _, seen := a.Hosts[ip]; !seen {
			other = "not_scanned"
		}
		newIPs[ip] = true
		r.HostsNew = append(r.HostsNew, HostChange{IP: ip, OtherRun: other, Ports: []uint16{}})
	}
	if len(newIPs) > 0 {
		ports := b.portsFor(newIPs)
		for i := range r.HostsNew {
			if ps := ports[r.HostsNew[i].IP]; len(ps) > 0 {
				r.HostsNew[i].Ports = ps
			}
		}
	}
	goneIPs := map[netip.Addr]bool{}
	for ip, up := range a.Hosts {
		if up && !b.Hosts[ip] {
			if _, seen := b.Hosts[ip]; seen {
				goneIPs[ip] = true
				r.HostsGone = append(r.HostsGone, HostChange{IP: ip, OtherRun: "down", Ports: []uint16{}})
			}
		}
	}
	if len(goneIPs) > 0 {
		ports := a.portsFor(goneIPs)
		for i := range r.HostsGone {
			if ps := ports[r.HostsGone[i].IP]; len(ps) > 0 {
				r.HostsGone[i].Ports = ps
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
		if f := changedFields(sa, sb, compareHTTP); len(f) > 0 {
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

// portsFor collects sorted open ports for each IP in want in a single pass
// over s.Services, avoiding O(changed_hosts * total_services) scans at scale.
func (s Snapshot) portsFor(want map[netip.Addr]bool) map[netip.Addr][]uint16 {
	out := make(map[netip.Addr][]uint16, len(want))
	for k := range s.Services {
		if want[k.IP] {
			out[k.IP] = append(out[k.IP], k.Port)
		}
	}
	for _, ps := range out {
		slices.Sort(ps)
	}
	return out
}

func changedFields(a, b *Service, compareHTTP bool) []string {
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
	if compareHTTP && (a.HasNmap || a.HasHTTP) && (b.HasNmap || b.HasHTTP) && a.FP.Title != b.FP.Title {
		f = append(f, "title")
	}
	if compareHTTP && a.HasHTTP && b.HasHTTP && !slices.Equal(a.FP.Technologies, b.FP.Technologies) {
		f = append(f, "technologies")
	}
	if compareHTTP && a.HasHTTP && b.HasHTTP && httpx.Slow(ms(b.FP.ResponseMS), ms(a.FP.ResponseMS)) &&
		ms(a.FP.ResponseMS) < httpx.SlowMS {
		f = append(f, FieldSlow)
	}
	if compareHTTP && a.HasHTTP && !b.HasHTTP {
		f = append(f, FieldHTTPUnresponsive)
	}
	return f
}
