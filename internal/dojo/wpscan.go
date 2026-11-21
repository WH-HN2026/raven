package dojo

import (
	"bytes"
	"net/netip"

	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
)

// appendWPScanReports adds per-IP "Wpscan" reports for responding IPs that had
// WordPress scanned in this run (architecture §3.11). Non-WordPress IPs have no
// entry in wp.PerIP and receive no Wpscan Test in DefectDojo.
func appendWPScanReports(ips []netip.Addr, stages []string, wp *scanner.Result, reports map[netip.Addr][]scannerReport, tags map[netip.Addr][]string) {
	stages = pipeline.EffectiveStages(stages)
	if !pipeline.HasStage(stages, pipeline.StageWPScan) || wp == nil {
		return
	}
	covered := make(map[netip.Addr]bool)
	for _, ip := range ips {
		if raw := bytes.TrimSpace(wp.PerIP(ip)); len(raw) > 0 {
			covered[ip.Unmap()] = true
			reports[ip] = append(reports[ip], scannerReport{
				name:      pipeline.StageWPScan,
				scanType:  "Wpscan",
				extension: "json",
				content:   raw,
			})
		}
	}
	for _, o := range wp.Observations {
		if covered[o.IP.Unmap()] && o.Kind == scanner.ObsTech && o.Product == "WordPress" {
			tags[o.IP.Unmap()] = append(tags[o.IP.Unmap()], "tech:wordpress")
		}
	}
}
