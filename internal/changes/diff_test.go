package changes

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nmap"
)

var (
	ipA = netip.MustParseAddr("10.0.0.1")
	ipB = netip.MustParseAddr("10.0.0.2")
)

// snap builds a snapshot: hosts maps IP → up, svcs maps key → fingerprint
// (nmap-sourced unless http is set).
type svc struct {
	ip   netip.Addr
	port uint16
	fp   Fingerprint
	http bool // fingerprint has an httpx source (title + technologies)
	bare bool // no fingerprint source at all
}

func snap(hosts map[netip.Addr]bool, svcs ...svc) Snapshot {
	s := Snapshot{Hosts: hosts, Services: map[SvcKey]*Service{}}
	for _, v := range svcs {
		fp := v.fp
		if fp.Technologies == nil {
			fp.Technologies = []string{}
		}
		s.Services[SvcKey{v.ip, v.port}] = &Service{Proto: "tcp", FP: fp, HasNmap: !v.bare, HasHTTP: v.http}
	}
	return s
}

type summary struct {
	hostsNew, hostsGone, svcNew, svcGone []string
	changed                              map[string][]string // "ip:port" → fields
}

func summarize(r Result) summary {
	s := summary{changed: map[string][]string{}}
	for _, h := range r.HostsNew {
		s.hostsNew = append(s.hostsNew, h.IP.String()+"/"+h.OtherRun)
	}
	for _, h := range r.HostsGone {
		s.hostsGone = append(s.hostsGone, h.IP.String())
	}
	for _, c := range r.ServicesNew {
		s.svcNew = append(s.svcNew, netip.AddrPortFrom(c.IP, c.Port).String())
	}
	for _, c := range r.ServicesGone {
		s.svcGone = append(s.svcGone, netip.AddrPortFrom(c.IP, c.Port).String())
	}
	for _, c := range r.ServicesChanged {
		s.changed[netip.AddrPortFrom(c.IP, c.Port).String()] = c.Fields
	}
	return s
}

func TestDiff(t *testing.T) {
	ssh := Fingerprint{Name: "ssh", Product: "OpenSSH", Version: "9.6"}
	web := Fingerprint{Name: "http", Product: "nginx", Version: "1.24", Title: "Home", Technologies: []string{"Nginx"}}
	up := map[netip.Addr]bool{ipA: true}
	tests := []struct {
		name string
		a, b Snapshot
		want summary
	}{
		{
			name: "unchanged",
			a:    snap(up, svc{ip: ipA, port: 22, fp: ssh}, svc{ip: ipA, port: 80, fp: web, http: true}),
			b:    snap(up, svc{ip: ipA, port: 22, fp: ssh}, svc{ip: ipA, port: 80, fp: web, http: true}),
		},
		{
			name: "new host from not scanned and from down",
			a:    snap(map[netip.Addr]bool{ipB: false}),
			b:    snap(map[netip.Addr]bool{ipA: true, ipB: true}, svc{ip: ipA, port: 22, fp: ssh}),
			// services of a new host are listed on the host, not as new services
			want: summary{hostsNew: []string{"10.0.0.1/not_scanned", "10.0.0.2/down"}},
		},
		{
			name: "host gone (down) keeps its services out of services_gone",
			a:    snap(up, svc{ip: ipA, port: 22, fp: ssh}),
			b:    snap(map[netip.Addr]bool{ipA: false}),
			want: summary{hostsGone: []string{"10.0.0.1"}},
		},
		{
			name: "host not scanned in to is not gone",
			a:    snap(up, svc{ip: ipA, port: 22, fp: ssh}),
			b:    snap(map[netip.Addr]bool{}),
		},
		{
			name: "service new and gone on a host up in both runs",
			a:    snap(up, svc{ip: ipA, port: 22, fp: ssh}),
			b:    snap(up, svc{ip: ipA, port: 80, fp: web}),
			want: summary{svcNew: []string{"10.0.0.1:80"}, svcGone: []string{"10.0.0.1:22"}},
		},
		{
			name: "service on a host down in from is not new",
			a:    snap(map[netip.Addr]bool{ipA: false}),
			b:    snap(up, svc{ip: ipA, port: 22, fp: ssh}),
			want: summary{hostsNew: []string{"10.0.0.1/down"}},
		},
		{
			name: "product and version changed",
			a:    snap(up, svc{ip: ipA, port: 22, fp: ssh}),
			b:    snap(up, svc{ip: ipA, port: 22, fp: Fingerprint{Name: "ssh", Product: "Dropbear", Version: "2022.83"}}),
			want: summary{changed: map[string][]string{"10.0.0.1:22": {"product", "version"}}},
		},
		{
			name: "title and technologies changed",
			a:    snap(up, svc{ip: ipA, port: 80, fp: web, http: true}),
			b: snap(up, svc{ip: ipA, port: 80, http: true,
				fp: Fingerprint{Name: "http", Product: "nginx", Version: "1.24", Title: "Login", Technologies: []string{"Nginx", "WordPress"}}}),
			want: summary{changed: map[string][]string{"10.0.0.1:80": {"title", "technologies"}}},
		},
		{
			name: "technologies not compared without httpx data in one run",
			a:    snap(up, svc{ip: ipA, port: 80, fp: web, http: true}),
			b:    snap(up, svc{ip: ipA, port: 80, fp: Fingerprint{Name: "http", Product: "nginx", Version: "1.24", Title: "Home"}}),
		},
		{
			name: "no fingerprint source in one run (e.g. imported) is not a change",
			a:    snap(up, svc{ip: ipA, port: 22, fp: ssh}),
			b:    snap(up, svc{ip: ipA, port: 22, bare: true}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarize(Diff(tt.a, tt.b))
			if tt.want.changed == nil {
				tt.want.changed = map[string][]string{}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestDiffDetails(t *testing.T) {
	a := snap(map[netip.Addr]bool{ipA: true}, svc{ip: ipA, port: 22, fp: Fingerprint{Name: "ssh", Version: "1"}})
	b := snap(map[netip.Addr]bool{ipA: true, ipB: true},
		svc{ip: ipA, port: 22, fp: Fingerprint{Name: "ssh", Version: "2"}},
		svc{ip: ipB, port: 443}, svc{ip: ipB, port: 80})
	r := Diff(a, b)
	if len(r.HostsNew) != 1 || !reflect.DeepEqual(r.HostsNew[0].Ports, []uint16{80, 443}) {
		t.Fatalf("hosts new: %+v", r.HostsNew)
	}
	c := r.ServicesChanged[0]
	if c.Before.Version != "1" || c.After.Version != "2" || c.Proto != "tcp" {
		t.Fatalf("changed: %+v %+v %+v", c, c.Before, c.After)
	}
}

func TestBuildSnapshot(t *testing.T) {
	obs := []ObsRow{
		{IP: ipA, Port: -1, Up: true}, {IP: ipA, Port: 22, Up: true}, {IP: ipA, Port: 80, Up: true},
		{IP: ipB, Port: -1, Up: false}, {IP: ipB, Port: 22, Up: true}, // port row of a down host: ignored
	}
	nm := []scanner.Observation{
		{Kind: scanner.ObsService, IP: ipA, Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH", Version: "8.0"},
		{Kind: scanner.ObsService, IP: ipA, Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH", Version: "9.6"}, // later batch wins
		{Kind: scanner.ObsService, IP: ipA, Port: 80, Proto: "tcp", Service: "http", Product: "nginx"},
		{Kind: scanner.ObsHTTP, IP: ipA, Port: 80, HTTP: &scanner.HTTPInfo{Title: "nmap title"}},
		{Kind: scanner.ObsService, IP: ipA, Port: 9999, Service: "x"}, // not in run_observations: ignored
	}
	http := []HTTPRow{
		{IP: ipA, Port: 80, Title: "", Technologies: []string{"Nginx"}},
		{IP: ipA, Port: 80, Title: "httpx title", Technologies: []string{"PHP", "Nginx"}},
	}
	s := BuildSnapshot(obs, nm, http)
	if !reflect.DeepEqual(s.Hosts, map[netip.Addr]bool{ipA: true, ipB: false}) || len(s.Services) != 2 {
		t.Fatalf("hosts %v, %d services", s.Hosts, len(s.Services))
	}
	ssh := s.Services[SvcKey{ipA, 22}]
	if ssh.FP.Version != "9.6" || !ssh.HasNmap || ssh.HasHTTP || ssh.FP.Title != "" {
		t.Fatalf("ssh: %+v", ssh)
	}
	web := s.Services[SvcKey{ipA, 80}]
	want := Fingerprint{Name: "http", Product: "nginx", Title: "httpx title", Technologies: []string{"Nginx", "PHP"}}
	if !reflect.DeepEqual(web.FP, want) || !web.HasHTTP {
		t.Fatalf("web: %+v", web.FP)
	}
	// without httpx rows the nmap http-title is used
	if got := BuildSnapshot(obs, nm, nil).Services[SvcKey{ipA, 80}].FP.Title; got != "nmap title" {
		t.Fatalf("nmap title: %q", got)
	}
}

// The nmap fixture of the scanner package parses into fingerprints.
func TestBuildSnapshotFromNmapFixture(t *testing.T) {
	raw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := nmap.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var obs []ObsRow
	for _, o := range res.Observations {
		switch o.Kind {
		case scanner.ObsHost:
			obs = append(obs, ObsRow{IP: o.IP, Port: -1, Up: o.Up})
		case scanner.ObsService:
			obs = append(obs, ObsRow{IP: o.IP, Port: int32(o.Port), Up: true})
		}
	}
	s := BuildSnapshot(obs, res.Observations, nil)
	n := 0
	for _, sv := range s.Services {
		if sv.HasNmap && sv.FP.Name != "" {
			n++
		}
	}
	if n == 0 || n != len(s.Services) {
		t.Fatalf("%d of %d services fingerprinted", n, len(s.Services))
	}
}
