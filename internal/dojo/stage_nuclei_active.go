package dojo

import (
	"bytes"
	"net/netip"

	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
)

// appendNucleiActiveReports adds per-IP nuclei_active reports (separate Dojo
// Test "RAVEN: nuclei_active", scan type "Nuclei Scan") strictly when the
// stage ran in this run (architecture §3.11).
func appendNucleiActiveReports(
	reports map[netip.Addr][]scannerReport,
	tags map[netip.Addr][]string,
	ips []netip.Addr,
	stages []string,
	httpxRes, activeRes *scanner.Result,
) {
	stages = pipeline.EffectiveStages(stages)
	if !pipeline.HasStage(stages, pipeline.StageHTTPX) || httpxRes == nil {
		return
	}
	if !pipeline.HasStage(stages, pipeline.StageNucleiActive) || activeRes == nil {
		return
	}
	covered := make(map[netip.Addr]bool)
	for _, ip := range nuclei.BuildInput(ips, httpxRes.Observations).IPs {
		covered[ip] = true
		raw := bytes.TrimSpace(activeRes.PerIP(ip))
		if len(raw) == 0 {
			// Valid empty report for Dojo's Nuclei Scan parser; closes old findings.
			raw = []byte("[]")
		}
		reports[ip] = append(reports[ip], scannerReport{
			name:      pipeline.StageNucleiActive,
			scanType:  "Nuclei Scan",
			extension: "jsonl",
			content:   raw,
		})
	}
	for _, o := range activeRes.Observations {
		if covered[o.IP] {
			tags[o.IP] = append(tags[o.IP], observationTags(o)...)
		}
	}
}
