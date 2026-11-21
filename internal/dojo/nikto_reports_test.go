package dojo

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/nikto"
)

func TestAppendNiktoReports(t *testing.T) {
	ip1 := netip.MustParseAddr("172.30.0.19")
	ip2 := netip.MustParseAddr("172.30.0.20")
	ip3 := netip.MustParseAddr("172.30.0.21")

	raw := []byte(`[
		{"host":"172.30.0.19","ip":"172.30.0.19","port":"80","vulnerabilities":[{"id":"999103","method":"GET","url":"/","msg":"Missing header"}]},
		{"host":"172.30.0.20","ip":"172.30.0.20","port":"80","vulnerabilities":[]}
	]`)
	res, err := nikto.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Stage not present -> nothing appended.
	reports := map[netip.Addr][]scannerReport{}
	appendNiktoReports(reports, []netip.Addr{ip1, ip2, ip3}, pipeline.DefaultStages(), res)
	if len(reports) != 0 {
		t.Fatalf("default stages appended nikto reports: %+v", reports)
	}

	// Stage present -> ip1 (with finding) and ip2 (empty vulns) appended, ip3 (unscanned/failed) skipped.
	aggStages := []string{pipeline.StageNmap, pipeline.StageHTTPX, pipeline.StageNikto}
	appendNiktoReports(reports, []netip.Addr{ip1, ip2, ip3}, aggStages, res)
	if len(reports[ip1]) != 1 || reports[ip1][0].scanType != "Nikto Scan" || reports[ip1][0].extension != "json" || !bytes.Contains(reports[ip1][0].content, []byte("Missing header")) {
		t.Fatalf("ip1 reports = %+v", reports[ip1])
	}
	if len(reports[ip2]) != 1 || !bytes.Contains(reports[ip2][0].content, []byte(`"vulnerabilities":[]`)) {
		t.Fatalf("ip2 reports = %+v", reports[ip2])
	}
	if len(reports[ip3]) != 0 {
		t.Fatalf("unscanned ip3 got nikto reports: %+v", reports[ip3])
	}
}
