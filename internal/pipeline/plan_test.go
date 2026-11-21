package pipeline

import (
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestSplitBatches(t *testing.T) {
	ips := make([]netip.Addr, 0, 600)
	base := netip.MustParseAddr("10.0.0.0")
	for range 600 {
		base = base.Next()
		ips = append(ips, base)
	}
	tests := []struct {
		name  string
		n     int
		size  int
		sizes []int
	}{
		{"empty", 0, 256, nil},
		{"one partial", 3, 256, []int{3}},
		{"exact", 512, 256, []int{256, 256}},
		{"remainder", 600, 256, []int{256, 256, 88}},
		{"size 1", 3, 1, []int{1, 1, 1}},
		{"size 0 = default", 300, 0, []int{256, 44}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitBatches(ips[:tt.n], tt.size)
			var sizes []int
			var all []netip.Addr
			for _, b := range got {
				sizes = append(sizes, len(b))
				all = append(all, b...)
			}
			if !slices.Equal(sizes, tt.sizes) {
				t.Fatalf("sizes = %v, want %v", sizes, tt.sizes)
			}
			if !slices.Equal(all, ips[:tt.n]) {
				t.Fatal("batches don't concatenate to the input in order")
			}
			if len(got) > 1 && cap(got[0]) != len(got[0]) {
				t.Fatal("batch slices must not share spare capacity")
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	ps, err := ParsePorts("22,80,8000-8100,443")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[uint16]bool{22: true, 80: true, 443: true, 8000: true, 8050: true, 8100: true, 8101: false, 21: false, 0: false} {
		if ps.Contains(p) != want {
			t.Errorf("Contains(%d) = %v, want %v", p, !want, want)
		}
	}
	for _, bad := range []string{"top-1000", "", "T:22", "80-", "0", "70000"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) succeeded", bad)
		}
	}
}

// The seeded default port list (migration) must be a spec nmap accepts.
func TestDefaultProfilePorts(t *testing.T) {
	b, err := os.ReadFile("../db/migrations/20261121131353_pipeline.sql")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`SET DEFAULT\s+'([0-9,-]+)'`).FindSubmatch(b)
	if m == nil {
		t.Fatal("default port list not found in migration")
	}
	ps, err := ParsePorts(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []uint16{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443, 9200} {
		if !ps.Contains(p) {
			t.Errorf("default ports miss %d", p)
		}
	}
	if _, err := nmap.BuildArgs(addrs("10.0.0.1"), scanner.Options{Ports: string(m[1]), MaxRate: 300}, nil); err != nil {
		t.Fatalf("nmap rejects the default ports: %v", err)
	}
}

func TestBuildPlan(t *testing.T) {
	ip1, ip2, ip3, other := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("10.9.9.9")
	obs := []scanner.Observation{
		{Kind: scanner.ObsHost, IP: ip1, Up: true, Hostname: "scan.example"},
		{Kind: scanner.ObsService, IP: ip1, Port: 443, Proto: "tcp", Service: "https", Product: "nginx", CPE: "igor_sysoev:nginx", Banner: "b"},
		{Kind: scanner.ObsService, IP: ip1, Port: 22, Proto: "tcp", Service: "ssh"},
		{Kind: scanner.ObsService, IP: ip1, Port: 22, Proto: "tcp", Service: "ssh"}, // duplicate
		{Kind: scanner.ObsHTTP, IP: ip1, Port: 443},
		{Kind: scanner.ObsHost, IP: ip2, Up: false},
		{Kind: scanner.ObsService, IP: ip2, Port: 80, Proto: "tcp"}, // of a down host: ignored
		{Kind: scanner.ObsHost, IP: other, Up: true},                // not in the batch
		// ip3: not reported at all → down
	}
	hn := map[netip.Addr][]string{ip1: {"www.example", "scan.example"}}
	p := BuildPlan([]netip.Addr{ip1, ip2, ip3}, hn, obs)

	if !slices.Equal(p.Up, []netip.Addr{ip1}) {
		t.Fatalf("Up = %v", p.Up)
	}
	if len(p.Hosts) != 1 || !slices.Equal(p.Hosts[0].Hostnames, []string{"scan.example", "www.example"}) {
		t.Fatalf("Hosts = %+v", p.Hosts)
	}
	if len(p.Services) != 2 || p.Services[0].Port != 22 || p.Services[1].Port != 443 ||
		p.Services[1].Product != "nginx" || p.Services[1].CPE != "igor_sysoev:nginx" || p.Services[1].Banner != "b" {
		t.Fatalf("Services = %+v", p.Services)
	}
	want := []ObsRow{
		{IP: ip1, HostLevel: true, Up: true},
		{IP: ip2, HostLevel: true, Up: false},
		{IP: ip3, HostLevel: true, Up: false},
		{IP: ip1, Port: 22, Up: true},
		{IP: ip1, Port: 443, Up: true},
	}
	if !slices.Equal(p.Observations, want) {
		t.Fatalf("Observations = %+v\nwant %+v", p.Observations, want)
	}
}

func TestBuildPlanFromFixture(t *testing.T) {
	raw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := nmap.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	batch := addrs("172.31.250.10", "172.31.250.11", "172.31.250.12", "172.31.250.20")
	p := BuildPlan(batch, nil, res.Observations)
	if len(p.Up) != 3 || len(p.Services) != 6 {
		t.Fatalf("up=%v services=%d, want 3 up and 6 services", p.Up, len(p.Services))
	}
	if len(p.Observations) != 4+6 {
		t.Fatalf("observations = %d", len(p.Observations))
	}
	cpes := map[string]string{}
	for _, s := range p.Services {
		cpes[netip.AddrPortFrom(s.IP, s.Port).String()] = s.CPE
	}
	if cpes["172.31.250.10:80"] != "igor_sysoev:nginx" || cpes["172.31.250.11:22"] != "openbsd:openssh:10.0" {
		t.Fatalf("fixture CPEs = %v", cpes)
	}
}

func TestGoneServices(t *testing.T) {
	up, down := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	p := Plan{
		Up:       []netip.Addr{up},
		Services: []ServiceRow{{IP: up, Port: 22, Proto: "tcp"}},
	}
	ports, _ := ParsePorts("22,80,443")
	before := []OpenService{
		{ID: 1, IP: up, Port: 22, Proto: "tcp"},   // still open
		{ID: 2, IP: up, Port: 80, Proto: "tcp"},   // in profile ports, not seen → gone
		{ID: 3, IP: up, Port: 8080, Proto: "tcp"}, // not in profile ports → kept
		{ID: 4, IP: up, Port: 443, Proto: "udp"},  // UDP is not scanned → kept
		{ID: 5, IP: down, Port: 80, Proto: "tcp"}, // host down → kept (S6)
		{ID: 6, IP: up, Port: 443, Proto: "tcp"},  // gone
	}
	if got := GoneServices(p, before, ports); !slices.Equal(got, []int64{2, 6}) {
		t.Fatalf("gone = %v, want [2 6]", got)
	}
}

func TestRunOutcome(t *testing.T) {
	tests := []struct {
		c        BatchCounts
		status   string
		finished bool
	}{
		{BatchCounts{Unfinished: 1}, "", false},
		{BatchCounts{Unfinished: 2, Failed: 1}, "", false},
		{BatchCounts{}, "done", true},
		{BatchCounts{Failed: 1}, "failed", true},
	}
	for _, tt := range tests {
		s, f := RunOutcome(tt.c)
		if s != tt.status || f != tt.finished {
			t.Errorf("RunOutcome(%+v) = %q,%v want %q,%v", tt.c, s, f, tt.status, tt.finished)
		}
	}
}

// Ingest writes only scan-owned columns: the queries it uses must not name
// a user-owned column (architecture §5, requirement 14).
func TestIngestQueriesSkipUserOwnedColumns(t *testing.T) {
	for _, name := range []string{"ingest.sql", "lifecycle.sql"} {
		b, err := os.ReadFile("../db/queries/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var code []string
		for line := range strings.SplitSeq(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				code = append(code, line)
			}
		}
		sql := strings.Join(code, "\n")
		for _, col := range []string{"owner", "criticality", "notes_enc", "user_tags", "overrides", "dojo_asset_id"} {
			if regexp.MustCompile(`\b` + col + `\b`).MatchString(sql) {
				t.Errorf("%s writes or reads %s", name, col)
			}
		}
	}
}
