package dojo

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPushNessus(t *testing.T) {
	f := newFake()
	p := &Pusher{Client: f, OrganizationID: 11, Parallel: 2}
	date := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	ip1 := netip.MustParseAddr("172.30.0.10")
	ip2 := netip.MustParseAddr("172.30.0.11")
	doc1 := []byte(`<NessusClientData_v2><Report name="r"><ReportHost name="172.30.0.10"/></Report></NessusClientData_v2>`)
	doc2 := []byte(`<NessusClientData_v2><Report name="r"><ReportHost name="172.30.0.11"/></Report></NessusClientData_v2>`)

	out := p.PushNessus(context.Background(), NessusBatch{
		Profile:  "default",
		ScanDate: date,
		Hosts: []NessusHost{
			{IP: ip1, Hostnames: []string{"web.lab"}, Report: doc1},
			{IP: ip2, Hostnames: []string{"ssh.lab"}, Report: doc2},
		},
	})
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
	for i, r := range out {
		if r.Err != nil {
			t.Fatalf("host %d err: %v", i, r.Err)
		}
		if r.AssetID == 0 || r.EngagementID == 0 || r.TestID == 0 {
			t.Fatalf("host %d missing IDs: %+v", i, r)
		}
	}

	if a := f.assets[ip1.String()]; a == nil || a.OrganizationID != 11 || !slices.Equal(a.Tags, []string{"raven", "host:web.lab"}) {
		t.Fatalf("ip1 asset = %+v", a)
	}
	for _, e := range f.engs {
		if e.Name != "RAVEN: default" {
			t.Fatalf("engagement = %+v", e)
		}
	}
	for _, ts := range f.tests {
		if ts.ScanType != TenableScanType || ts.Title != "RAVEN: nessus" {
			t.Fatalf("test = %+v, want scan_type=%q title=%q", ts, TenableScanType, "RAVEN: nessus")
		}
	}
	for _, ip := range []netip.Addr{ip1, ip2} {
		rs := f.importsOf(ip.String(), TenableScanType)
		if len(rs) != 1 {
			t.Fatalf("%s: got %d Tenable imports, want 1", ip, len(rs))
		}
		if rs[0].FileName != ip.String()+".nessus" || !rs[0].CloseOldFindings || !rs[0].TagFindings || !slices.Equal(rs[0].Tags, []string{"raven"}) {
			t.Fatalf("%s: reimport req = %+v", ip, rs[0].ImportRequest)
		}
		if !strings.Contains(rs[0].Body, ip.String()) {
			t.Fatalf("%s: report body missing IP", ip)
		}
	}
}

func TestPushNessusFailurePerIP(t *testing.T) {
	f := newFake()
	f.failIP = "172.30.0.10"
	p := &Pusher{Client: f, OrganizationID: 1}
	out := p.PushNessus(context.Background(), NessusBatch{
		Profile: "default",
		Hosts: []NessusHost{
			{IP: netip.MustParseAddr("172.30.0.10"), Report: []byte("<NessusClientData_v2/>")},
			{IP: netip.MustParseAddr("172.30.0.11"), Report: []byte("<NessusClientData_v2/>")},
			{IP: netip.MustParseAddr("172.30.0.12")}, // empty report
		},
	})
	if out[0].Err == nil || out[1].Err != nil || out[2].Err == nil {
		t.Fatalf("unexpected outcomes: %+v", out)
	}
}
