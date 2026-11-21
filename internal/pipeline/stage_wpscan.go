package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/wpscan"
)

func defaultWPScan() scanner.Scanner {
	return &wpscan.Scanner{
		DBDir: os.Getenv("RAVEN_WPSCAN_DB"),
	}
}

type wpscanStageResult struct {
	result      *scanner.Result
	skipped     string
	urlsScanned int
	errCount    int
}

func (s *Service) scanWPScan(ctx context.Context, b gen.Batch, prof gen.Profile, web, detection *scanner.Result) (*wpscanStageResult, error) {
	var webObs, nucleiObs []scanner.Observation
	if web != nil {
		webObs = web.Observations
	}
	if detection != nil {
		nucleiObs = detection.Observations
	}
	in := wpscan.BuildInput(b.Ips, webObs, nucleiObs)
	if len(in.URLs) == 0 {
		slog.Info("wpscan stage skipped: no WordPress", "run", b.RunID, "batch", b.ID)
		return &wpscanStageResult{skipped: "skipped: no WordPress"}, nil
	}

	out := &wpscanStageResult{}
	var docs [][]byte
	for _, rawURL := range in.URLs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		urlIn := scanner.Input{IPs: in.IPs, URLs: []string{rawURL}}
		res, err := s.cfg.WPScan.Run(ctx, urlIn, scanner.Options{RateLimit: s.webRate(prof)})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			out.errCount++
			slog.Warn("wpscan URL failed", "run", b.RunID, "batch", b.ID, "url", rawURL, "err", err)
			continue
		}
		out.urlsScanned++
		if res != nil {
			if trimmed := bytes.TrimSpace(res.Raw); len(trimmed) > 0 {
				docs = append(docs, trimmed)
			}
		}
	}

	if len(docs) > 0 {
		combined := bytes.Join(docs, []byte("\n"))
		combined = append(combined, '\n')
		parsed, err := wpscan.Parse(combined)
		if err != nil {
			out.errCount++
			slog.Warn("wpscan parse combined output failed", "run", b.RunID, "batch", b.ID, "err", err)
			return out, nil
		}
		out.result = parsed
	}
	return out, nil
}

func (s *Service) ingestWPScan(ctx context.Context, q *gen.Queries, run gen.Run, b gen.Batch, wp *wpscanStageResult) error {
	if wp == nil {
		return nil
	}

	// Accumulate stage stats on runs.stats (caller holds LockRun).
	var existing map[string]any
	if len(run.Stats) > 0 {
		_ = json.Unmarshal(run.Stats, &existing)
	}
	prevURLs := jsonInt(existing["wpscan_urls"])
	prevErrors := jsonInt(existing["wpscan_errors"])
	totalURLs := prevURLs + wp.urlsScanned
	totalErrors := prevErrors + wp.errCount

	patch := map[string]any{}
	switch {
	case totalURLs > 0:
		patch["wpscan"] = "ok"
		patch["wpscan_urls"] = totalURLs
		patch["wpscan_errors"] = totalErrors
	case totalErrors > 0:
		patch["wpscan"] = "error"
		patch["wpscan_errors"] = totalErrors
	case wp.skipped != "":
		patch["wpscan"] = wp.skipped
	}
	if len(patch) > 0 {
		patchJSON, err := json.Marshal(patch)
		if err != nil {
			return fmt.Errorf("marshal wpscan stats: %w", err)
		}
		if err := q.MergeRunStats(ctx, gen.MergeRunStatsParams{ID: run.ID, Stats: patchJSON}); err != nil {
			return fmt.Errorf("merge wpscan stats: %w", err)
		}
	}

	if wp.result == nil {
		return nil
	}

	// Merge WordPress core and tracked plugin/theme versions + CPEs into
	// http_observations and services so offline CVE matching (internal/cve)
	// picks them up on the next pass.
	type serviceKey struct {
		ip   netip.Addr
		port uint16
	}
	type urlKey struct {
		serviceKey
		url string
	}
	tech := make(map[urlKey][]string)
	urlCPEs := make(map[urlKey][]string)
	svcCPEs := make(map[serviceKey][]string)

	for _, o := range wp.result.Observations {
		if o.Kind != scanner.ObsTech || !o.IP.IsValid() || o.Port == 0 {
			continue
		}
		sk := serviceKey{o.IP.Unmap(), o.Port}
		if o.URL != "" {
			uk := urlKey{sk, o.URL}
			if o.Tech != "" {
				tech[uk] = append(tech[uk], o.Tech)
			}
			if o.CPE != "" {
				urlCPEs[uk] = append(urlCPEs[uk], o.CPE)
			}
		}
		if o.CPE != "" {
			svcCPEs[sk] = append(svcCPEs[sk], o.CPE)
		}
	}

	if len(tech) > 0 {
		params := gen.MergeNucleiTechnologiesBatchParams{
			RunID:            &b.RunID,
			Ips:              make([]netip.Addr, 0, len(tech)),
			Ports:            make([]int32, 0, len(tech)),
			Urls:             make([]string, 0, len(tech)),
			TechnologiesJson: make([]string, 0, len(tech)),
		}
		for k, list := range tech {
			tj, _ := json.Marshal(list)
			params.Ips = append(params.Ips, k.ip)
			params.Ports = append(params.Ports, int32(k.port))
			params.Urls = append(params.Urls, k.url)
			params.TechnologiesJson = append(params.TechnologiesJson, string(tj))
		}
		if _, err := q.MergeNucleiTechnologiesBatch(ctx, params); err != nil {
			return fmt.Errorf("ingest wpscan technologies: %w", err)
		}
	}
	if len(urlCPEs) > 0 {
		params := gen.MergeNucleiCPEsBatchParams{RunID: &b.RunID}
		for k, cpes := range urlCPEs {
			j, _ := json.Marshal(cpes)
			params.Ips = append(params.Ips, k.ip)
			params.Ports = append(params.Ports, int32(k.port))
			params.Urls = append(params.Urls, k.url)
			params.CpesJson = append(params.CpesJson, string(j))
		}
		if _, err := q.MergeNucleiCPEsBatch(ctx, params); err != nil {
			return fmt.Errorf("ingest wpscan cpes: %w", err)
		}
	}
	for k, cpes := range svcCPEs {
		if svcCPE := preferredServiceCPE(cpes); svcCPE != "" {
			if err := q.BackfillServiceCPE(ctx, gen.BackfillServiceCPEParams{
				Ip: k.ip, Port: int32(k.port), Cpe: svcCPE,
			}); err != nil {
				return fmt.Errorf("backfill wpscan service cpe for %s/%d: %w", k.ip, k.port, err)
			}
		}
	}

	if len(wp.result.Raw) > 0 {
		if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
			RunID: b.RunID, BatchID: &b.ID, Scanner: StageWPScan, Content: string(wp.result.Raw),
		}); err != nil {
			return fmt.Errorf("ingest wpscan artifact: %w", err)
		}
	}
	return nil
}

func jsonInt(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}
