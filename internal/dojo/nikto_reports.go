package dojo

import (
	"bytes"
	"net/netip"

	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
)

// appendNiktoReports attaches per-IP Nikto JSON reports for DefectDojo's
// "Nikto Scan" parser, strictly when the nikto stage ran in this run
// (architecture §3.11). IPs with no Nikto report (not scanned or failed) are
// skipped so close_old_findings does not close prior findings.
func appendNiktoReports(reports map[netip.Addr][]scannerReport, ips []netip.Addr, stages []string, niktoRes *scanner.Result) {
	stages = pipeline.EffectiveStages(stages)
	if !pipeline.HasStage(stages, pipeline.StageHTTPX) || !pipeline.HasStage(stages, pipeline.StageNikto) || niktoRes == nil {
		return
	}
	for _, ip := range ips {
		if raw := bytes.TrimSpace(niktoRes.PerIP(ip)); len(raw) > 0 {
			reports[ip] = append(reports[ip], scannerReport{pipeline.StageNikto, "Nikto Scan", "json", raw})
		}
	}
}
