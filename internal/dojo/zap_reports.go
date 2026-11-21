package dojo

import (
	"bytes"
	"net/netip"

	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
)

// appendZAPReports adds per-IP "ZAP Scan" XML reports when the zap stage ran
// in this run (architecture §3.11). An IP whose ZAP pass failed has no <site>
// in zapRes.PerIP(ip) and is skipped so existing Dojo findings stay intact.
func appendZAPReports(reports map[netip.Addr][]scannerReport, ips []netip.Addr, stages []string, zapRes *scanner.Result) {
	if !pipeline.HasStage(pipeline.EffectiveStages(stages), pipeline.StageZAP) || zapRes == nil {
		return
	}
	for _, ip := range ips {
		if raw := bytes.TrimSpace(zapRes.PerIP(ip)); len(raw) > 0 {
			reports[ip] = append(reports[ip], scannerReport{"zap", "ZAP Scan", "xml", raw})
		}
	}
}
