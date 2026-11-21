package dojo

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/wpscan"
)

func TestAppendWPScanReports(t *testing.T) {
	wpRes := parsedFixture(t, wpscan.Parse, fixture(t, "wpscan/testdata/lab-wordpress.json"))
	ipWP := netip.MustParseAddr("172.30.0.17")
	ipJoomla := netip.MustParseAddr("172.30.0.18")
	stages := append(pipeline.DefaultStages(), pipeline.StageWPScan)

	reports := map[netip.Addr][]scannerReport{}
	tags := map[netip.Addr][]string{}
	appendWPScanReports([]netip.Addr{ipWP, ipJoomla}, stages, wpRes, reports, tags)

	if len(reports[ipWP]) != 1 {
		t.Fatalf("ipWP reports = %d, want 1", len(reports[ipWP]))
	}
	r := reports[ipWP][0]
	if r.name != "wpscan" || r.scanType != "Wpscan" || r.extension != "json" {
		t.Errorf("report meta = %+v, want wpscan/Wpscan/json", r)
	}
	if !bytes.Contains(r.content, []byte(`"target_ip": "172.30.0.17"`)) {
		t.Errorf("unexpected wpscan content: %s", r.content)
	}
	if !slices.Contains(tags[ipWP], "tech:wordpress") {
		t.Errorf("tags[ipWP] = %v, want tech:wordpress", tags[ipWP])
	}
	if len(reports[ipJoomla]) != 0 {
		t.Errorf("non-WordPress IP got wpscan report: %+v", reports[ipJoomla])
	}

	// Default stages (without wpscan) must emit nothing even if wpRes is non-nil.
	reportsDefault := map[netip.Addr][]scannerReport{}
	tagsDefault := map[netip.Addr][]string{}
	appendWPScanReports([]netip.Addr{ipWP}, pipeline.DefaultStages(), wpRes, reportsDefault, tagsDefault)
	if len(reportsDefault) != 0 || len(tagsDefault) != 0 {
		t.Errorf("default stages emitted wpscan reports=%v tags=%v, want empty", reportsDefault, tagsDefault)
	}
}
