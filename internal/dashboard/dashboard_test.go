package dashboard

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

func TestFindingCounts(t *testing.T) {
	tests := []struct {
		name  string
		rows  []gen.DashboardFindingCountsRow
		want  []int // Critical, High, Medium, Low, Info
		total int
	}{
		{"empty", nil, []int{0, 0, 0, 0, 0}, 0},
		{"some", []gen.DashboardFindingCountsRow{{Severity: "Info", N: 7}, {Severity: "High", N: 2}}, []int{0, 2, 0, 0, 7}, 9},
		{"all", []gen.DashboardFindingCountsRow{
			{Severity: "Low", N: 4}, {Severity: "Critical", N: 1}, {Severity: "Medium", N: 3},
			{Severity: "High", N: 2}, {Severity: "Info", N: 5},
		}, []int{1, 2, 3, 4, 5}, 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := findingCounts(tt.rows)
			if f.Total != tt.total {
				t.Errorf("total = %d, want %d", f.Total, tt.total)
			}
			if len(f.BySeverity) != 5 {
				t.Fatalf("by_severity has %d entries, want 5", len(f.BySeverity))
			}
			for i, sc := range f.BySeverity {
				if sc.Severity != Severities[i] || sc.Count != tt.want[i] {
					t.Errorf("[%d] = %+v, want %s %d", i, sc, Severities[i], tt.want[i])
				}
			}
		})
	}
}

func TestRunDuration(t *testing.T) {
	start := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	end := start.Add(90 * time.Minute)
	tests := []struct {
		name       string
		start, end *time.Time
		want       *int64
	}{
		{"pending", nil, nil, nil},
		{"running", &start, nil, nil},
		{"done", &start, &end, ptr(int64(90 * 60 * 1000))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(gen.DashboardRunsRow{ID: 3, Profile: "lab", Status: "done", StartedAt: tt.start, FinishedAt: tt.end,
				HostsTotal: 5, HostsUp: 4, BatchesTotal: 2, BatchesDone: 2})
			if !reflect.DeepEqual(r.DurationMS, tt.want) {
				t.Errorf("duration = %v, want %v", deref(r.DurationMS), deref(tt.want))
			}
			if r.Profile != "lab" || r.HostsUp != 4 || r.BatchesDone != 2 {
				t.Errorf("fields not copied: %+v", r)
			}
		})
	}
}

func TestTotalsFromWindowCount(t *testing.T) {
	ip := netip.MustParseAddr("172.30.0.10")
	hosts, n := newHosts([]gen.DashboardNewHostsRow{{Ip: ip, Ports: []int32{22, 80}, Total: 12}})
	if n != 12 || len(hosts) != 1 || hosts[0].IP != ip || !reflect.DeepEqual(hosts[0].Ports, []int32{22, 80}) {
		t.Errorf("newHosts = %+v, %d", hosts, n)
	}
	if hosts, n := newHosts(nil); n != 0 || hosts == nil || len(hosts) != 0 {
		t.Errorf("newHosts(nil) = %#v, %d; want empty non-nil, 0", hosts, n)
	}
	cves, n := cveMatches([]gen.DashboardCVEMatchesRow{{Ip: ip, Port: 80, Severity: "High", MaxCvss: 7.5, Cves: 3, Total: 4}})
	if n != 4 || cves[0].CVEs != 3 || cves[0].MaxCVSS != 7.5 {
		t.Errorf("cveMatches = %+v, %d", cves, n)
	}
	if cves, n := cveMatches(nil); n != 0 || cves == nil {
		t.Errorf("cveMatches(nil) = %#v, %d; want empty non-nil, 0", cves, n)
	}
}

func ptr[T any](v T) *T { return &v }

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
