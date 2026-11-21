package dojo

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A finding as Dojo 3.5.202 returns it with related_fields=true (trimmed).
const findingJSON = `{
  "id": 42, "title": "Open port: 22/tcp", "severity": "Medium", "active": false,
  "verified": true, "false_p": false, "risk_accepted": false, "is_mitigated": true,
  "tags": ["raven", "x"], "test": 7, "date": "2026-11-20",
  "last_status_update": "2026-11-21T10:00:00.123456Z",
  "test_type_name": "Nmap Scan",
  "related_fields": {"test": {"id": 7, "title": "nmap",
    "engagement": {"id": 3, "name": "RAVEN: default",
      "product": {"id": 9, "name": "10.0.0.5", "prod_type": {"id": 1, "name": "RAVEN"}}}}}
}`

func TestMirrorFinding(t *testing.T) {
	var f Finding
	if err := json.Unmarshal([]byte(findingJSON), &f); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	p := mirrorFinding(f, now)
	if p.ID != 42 || p.AssetID == nil || *p.AssetID != 9 || p.Ip == nil || p.Ip.String() != "10.0.0.5" {
		t.Fatalf("ids/ip: %+v", p)
	}
	if p.Severity != "Medium" || p.Active || !p.Verified || !p.IsMitigated || p.Scanner != "nmap" {
		t.Fatalf("fields: %+v", p)
	}
	if !p.Date.Valid || p.Date.Time.Format(time.DateOnly) != "2026-11-20" {
		t.Fatalf("date: %+v", p.Date)
	}
	if p.LastStatusUpdate == nil || !p.SyncedAt.Equal(now) || !reflect.DeepEqual(p.Tags, []string{"raven", "x"}) {
		t.Fatalf("misc: %+v", p)
	}

	// No related_fields, odd severity, no date: still a valid row.
	p = mirrorFinding(Finding{ID: 1, Title: "x", Severity: "weird"}, now)
	if p.AssetID != nil || p.Ip != nil || p.Severity != "Info" || p.Date.Valid || p.LastStatusUpdate != nil || p.Tags == nil {
		t.Fatalf("bare: %+v", p)
	}
}

func TestMirrorAsset(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name, ip string
	}{
		{"10.0.0.5", "10.0.0.5"},
		{"2001:db8::1", "2001:db8::1"},
		{"::ffff:10.1.2.3", "10.1.2.3"},
		{"RAVEN Planning", ""},
		{"10.0.0.0/24", ""},
	} {
		p := mirrorAsset(Asset{ID: 1, Name: tc.name}, now)
		got := ""
		if p.Ip != nil {
			got = p.Ip.String()
		}
		if got != tc.ip || p.Tags == nil {
			t.Errorf("%q: ip %q tags %v, want ip %q", tc.name, got, p.Tags, tc.ip)
		}
	}
}

func TestScannerFromScanType(t *testing.T) {
	for in, want := range map[string]string{
		"Nmap Scan": "nmap", "Nuclei Scan": "nuclei", "Generic Findings Import": "raven",
		"Wpscan": "wpscan", "ZAP Scan": "zap",
		"": "", "OpenVAS Parser": "openvas parser", "Nessus Scan": "nessus",
	} {
		if got := ScannerFromScanType(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestPageAll(t *testing.T) {
	data := make([]int, 600)
	var offsets []int
	got, err := pageAll(context.Background(), func(limit, offset int) (*Page[int], error) {
		offsets = append(offsets, offset)
		end := min(offset+limit, len(data))
		return &Page[int]{Count: len(data), Results: data[offset:end]}, nil
	})
	if err != nil || len(got) != 600 || !reflect.DeepEqual(offsets, []int{0, 250, 500}) {
		t.Fatalf("got %d, offsets %v, err %v", len(got), offsets, err)
	}
	// A list that shrinks under us still terminates on an empty page.
	calls := 0
	got, err = pageAll(context.Background(), func(limit, offset int) (*Page[int], error) {
		calls++
		if offset > 0 {
			return &Page[int]{Count: 1000}, nil
		}
		return &Page[int]{Count: 1000, Results: data[:limit]}, nil
	})
	if err != nil || len(got) != 250 || calls != 2 {
		t.Fatalf("shrinking: got %d, calls %d, err %v", len(got), calls, err)
	}
}

func TestBuildFindingList(t *testing.T) {
	yes := true
	pfx := netip.MustParsePrefix("10.0.0.0/24")
	one := netip.PrefixFrom(netip.MustParseAddr("10.0.0.5"), 32)
	for _, tc := range []struct {
		name      string
		f         FindingFilter
		where     string
		args      []any
		limitPos  string
		countArgs int
	}{
		{"none", FindingFilter{Limit: 50}, "", []any{int32(50), int32(0)}, "LIMIT $1 OFFSET $2", 0},
		{
			"all", FindingFilter{
				Severities: []string{"High", "Critical"}, Active: &yes, IP: &pfx, Q: "Port", Scanner: "nmap", Limit: 10, Offset: 20,
			},
			" WHERE severity = ANY($1::text[]) AND active = $2 AND ip <<= $3::inet AND strpos(lower(title), lower($4)) > 0 AND scanner = $5",
			[]any{[]string{"High", "Critical"}, true, "10.0.0.0/24", "Port", "nmap", int32(10), int32(20)},
			"LIMIT $6 OFFSET $7", 5,
		},
		{"single ip", FindingFilter{IP: &one, Limit: 1}, " WHERE ip <<= $1::inet", []any{"10.0.0.5/32", int32(1), int32(0)}, "LIMIT $2 OFFSET $3", 1},
		{"q injection stays a parameter", FindingFilter{Q: "'; DROP TABLE x; --", Limit: 1},
			" WHERE strpos(lower(title), lower($1)) > 0", []any{"'; DROP TABLE x; --", int32(1), int32(0)}, "LIMIT $2 OFFSET $3", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			where, wargs := buildFindingWhere(tc.f)
			if where != tc.where || len(wargs) != tc.countArgs {
				t.Fatalf("where = %q (%d args), want %q", where, len(wargs), tc.where)
			}
			list, count, args := buildFindingList(tc.f)
			if count != "SELECT count(*) FROM dojo_findings"+tc.where {
				t.Errorf("count = %q", count)
			}
			if !strings.Contains(list, "FROM dojo_findings"+tc.where+" ORDER BY CASE severity") ||
				!strings.HasSuffix(list, "date DESC NULLS LAST, id DESC "+tc.limitPos) {
				t.Errorf("list = %q", list)
			}
			if !reflect.DeepEqual(args, tc.args) {
				t.Errorf("args = %#v, want %#v", args, tc.args)
			}
		})
	}
}

func TestFindingURL(t *testing.T) {
	if got := FindingURL("http://localhost:8080/", 7); got != "http://localhost:8080/finding/7" {
		t.Fatal(got)
	}
	if FindingURL("", 7) != "" {
		t.Fatal("empty base")
	}
}
