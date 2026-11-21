package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
)

// techCPEs maps technology strings (e.g. "WordPress:6.4.2", "Apache Tomcat:9.0.50")
// to normalized CPE strings via cve.CPEForTech, sorted and deduplicated.
func techCPEs(technologies []string) []string {
	var out []string
	for _, t := range technologies {
		if c, v, ok := cve.CPEForTech(t); ok {
			out = append(out, cve.FormatCPE(c, v))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// preferredServiceCPE picks one CPE to backfill services.cpe when nmap didn't
// produce one, preferring a versioned CPE ("vendor:product:version").
func preferredServiceCPE(cpes []string) string {
	for _, c := range cpes {
		if strings.Count(c, ":") >= 2 {
			return c
		}
	}
	if len(cpes) > 0 {
		return cpes[0]
	}
	return ""
}

// ingestHTTP adds URL-level facts to the services already written by Ingest.
// The corresponding port-level run_observations row is shared by the IP URL
// and all its virtual hosts, so these facts don't add another presence row.
func (s *Service) ingestHTTP(ctx context.Context, q *gen.Queries, b gen.Batch, res *scanner.Result, seen time.Time) error {
	type key struct {
		ip  netip.Addr
		url string
	}
	type serviceKey struct {
		ip   netip.Addr
		port uint16
	}
	inserted := make(map[key]bool)
	params := gen.InsertHTTPObservationsParams{RunID: &b.RunID}
	backfill := make(map[serviceKey]string)
	for _, o := range res.Observations {
		k := key{o.IP, o.URL}
		if o.Kind != scanner.ObsHTTP || o.HTTP == nil || inserted[k] {
			continue
		}
		inserted[k] = true
		h := o.HTTP
		// These values contain only JSON-serializable strings.
		headers, _ := json.Marshal(h.Headers)
		cookies, _ := json.Marshal(nonNil(h.Cookies))
		redirects, _ := json.Marshal(nonNil(h.Redirects))
		techs, _ := json.Marshal(nonNil(h.Technologies))
		cpes := techCPEs(h.Technologies)
		cpesJSON, _ := json.Marshal(nonNil(cpes))
		if svcCPE := preferredServiceCPE(cpes); svcCPE != "" {
			if _, ok := backfill[serviceKey{o.IP, o.Port}]; !ok {
				backfill[serviceKey{o.IP, o.Port}] = svcCPE
			}
		}
		at := o.At
		if at.IsZero() {
			at = seen
		}
		params.Ips = append(params.Ips, o.IP)
		params.Ports = append(params.Ports, int32(o.Port))
		params.Urls = append(params.Urls, o.URL)
		params.Statuses = append(params.Statuses, int32(h.Status))
		params.Titles = append(params.Titles, h.Title)
		params.Headers = append(params.Headers, string(headers))
		params.Cookies = append(params.Cookies, string(cookies))
		params.TlsCerts = append(params.TlsCerts, h.TLSCert)
		params.Redirects = append(params.Redirects, string(redirects))
		params.TechnologiesJson = append(params.TechnologiesJson, string(techs))
		params.CpesJson = append(params.CpesJson, string(cpesJSON))
		params.FaviconHashes = append(params.FaviconHashes, h.FaviconHash)
		params.ObservedAts = append(params.ObservedAts, at)
	}
	if len(params.Ips) > 0 {
		n, err := q.InsertHTTPObservations(ctx, params)
		if err != nil {
			return fmt.Errorf("ingest HTTP observations: %w", err)
		}
		if n != int64(len(params.Ips)) {
			return fmt.Errorf("ingest HTTP observations: inserted %d of %d (service missing)", n, len(params.Ips))
		}
	}
	for k, svcCPE := range backfill {
		if err := q.BackfillServiceCPE(ctx, gen.BackfillServiceCPEParams{
			Ip: k.ip, Port: int32(k.port), Cpe: svcCPE,
		}); err != nil {
			return fmt.Errorf("backfill service cpe for %s/%d: %w", k.ip, k.port, err)
		}
	}
	if len(res.Raw) == 0 {
		return nil
	}
	if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
		RunID: b.RunID, BatchID: &b.ID, Scanner: s.cfg.HTTPX.Name(), Content: string(res.Raw),
	}); err != nil {
		return fmt.Errorf("ingest HTTP artifact: %w", err)
	}
	return nil
}
