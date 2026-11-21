package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/signatures"
)

func defaultNuclei(pool *pgxpool.Pool) scanner.Scanner {
	return &nuclei.Scanner{
		TemplatesDir: os.Getenv("RAVEN_NUCLEI_TEMPLATES"),
		CustomDir:    "/opt/raven-signatures",
		LoadSignatures: func(ctx context.Context) ([]string, error) {
			items, err := (&signatures.Store{Pool: pool}).Enabled(ctx)
			if err != nil {
				return nil, err
			}
			sources := make([]string, 0, len(items))
			for _, item := range items {
				sources = append(sources, item.TemplateYaml)
			}
			return sources, nil
		},
	}
}

func (s *Service) scanNuclei(ctx context.Context, b gen.Batch, prof gen.Profile, web *scanner.Result) (*scanner.Result, error) {
	if web == nil {
		return nil, nil
	}
	in := nuclei.BuildInput(b.Ips, web.Observations)
	if len(in.URLs) == 0 {
		return nil, nil
	}
	res, err := s.cfg.Nuclei.Run(ctx, in, scanner.Options{RateLimit: s.webRate(prof), Tags: prof.NucleiTags})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		slog.Warn("nuclei stage failed", "run", b.RunID, "batch", b.ID, "err", err)
		return nil, nil
	}
	return res, nil
}

type nucleiMatch struct {
	Kind       scanner.ObservationKind `json:"kind"`
	TemplateID string                  `json:"template_id"`
	Name       string                  `json:"name"`
	Severity   string                  `json:"severity"`
	Tags       []string                `json:"tags"`
	Matcher    string                  `json:"matcher,omitempty"`
	URL        string                  `json:"url"`
	Tech       string                  `json:"tech,omitempty"`
	CPE        string                  `json:"cpe,omitempty"`
	Version    string                  `json:"version,omitempty"`
}

func (s *Service) ingestNuclei(ctx context.Context, q *gen.Queries, b gen.Batch, res *scanner.Result) error {
	type serviceKey struct {
		ip   netip.Addr
		port uint16
	}
	type urlKey struct {
		serviceKey
		url string
	}
	type matches struct {
		facts    []nucleiMatch
		evidence [][]string
	}
	byService := make(map[serviceKey]*matches)
	tech := make(map[urlKey][]string)
	urlCPEs := make(map[urlKey][]string)
	svcCPEs := make(map[serviceKey][]string)
	for _, o := range res.Observations {
		if o.Match == nil || (o.Kind != scanner.ObsMatch && o.Kind != scanner.ObsTech) {
			continue
		}
		k := serviceKey{o.IP, o.Port}
		m := byService[k]
		if m == nil {
			m = &matches{}
			byService[k] = m
		}
		u, err := url.Parse(o.URL)
		if err != nil {
			return fmt.Errorf("ingest nuclei observation for %s/%d: invalid matched URL", o.IP, o.Port)
		}
		// Query strings and complete extraction results stay in encrypted evidence.
		u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = "", "", "", false
		cpeStr, ver := o.CPE, o.Version
		if cpeStr == "" {
			for _, cand := range []string{o.Tech, o.Match.TemplateID, o.Match.Name} {
				if c, v, ok := cve.CPEForTech(cand); ok {
					cpeStr = c
					if ver == "" {
						ver = v
					}
					break
				}
			}
		}
		m.facts = append(m.facts, nucleiMatch{
			Kind: o.Kind, TemplateID: o.Match.TemplateID, Name: o.Match.Name,
			Severity: o.Match.Severity, Tags: nonNil(o.Match.Tags), Matcher: o.Match.Matcher,
			URL: u.String(), Tech: o.Tech, CPE: cpeStr, Version: ver,
		})
		m.evidence = append(m.evidence, nonNil(o.Match.Extracted))
		if o.Kind == scanner.ObsTech && o.Tech != "" {
			uk := urlKey{k, o.Match.SourceURL}
			tech[uk] = append(tech[uk], o.Tech)
		}
		if fullCPE := cve.FormatCPE(cpeStr, ver); fullCPE != "" {
			svcCPEs[k] = append(svcCPEs[k], fullCPE)
			if o.Match.SourceURL != "" {
				uk := urlKey{k, o.Match.SourceURL}
				urlCPEs[uk] = append(urlCPEs[uk], fullCPE)
			}
		}
	}
	if len(byService) > 0 {
		params := gen.RecordNucleiMatchesBatchParams{
			RunID:     b.RunID,
			Ips:       make([]netip.Addr, 0, len(byService)),
			Ports:     make([]int32, 0, len(byService)),
			Matches:   make([]string, 0, len(byService)),
			Evidences: make([]string, 0, len(byService)),
		}
		for k, m := range byService {
			facts, _ := json.Marshal(m.facts)
			evidence, _ := json.Marshal(m.evidence)
			params.Ips = append(params.Ips, k.ip)
			params.Ports = append(params.Ports, int32(k.port))
			params.Matches = append(params.Matches, string(facts))
			params.Evidences = append(params.Evidences, string(evidence))
		}
		n, err := q.RecordNucleiMatchesBatch(ctx, params)
		if err != nil {
			return fmt.Errorf("ingest nuclei matches: %w", err)
		}
		if n != int64(len(byService)) {
			return fmt.Errorf("ingest nuclei matches: updated %d of %d (open service observation missing)", n, len(byService))
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
		for k, technologies := range tech {
			tj, _ := json.Marshal(technologies)
			params.Ips = append(params.Ips, k.ip)
			params.Ports = append(params.Ports, int32(k.port))
			params.Urls = append(params.Urls, k.url)
			params.TechnologiesJson = append(params.TechnologiesJson, string(tj))
		}
		n, err := q.MergeNucleiTechnologiesBatch(ctx, params)
		if err != nil {
			return fmt.Errorf("ingest nuclei technologies: %w", err)
		}
		if n < int64(len(tech)) {
			return fmt.Errorf("ingest nuclei technologies: updated %d of %d (HTTP observation missing)", n, len(tech))
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
			return fmt.Errorf("ingest nuclei cpes: %w", err)
		}
	}
	for k, cpes := range svcCPEs {
		if svcCPE := preferredServiceCPE(cpes); svcCPE != "" {
			if err := q.BackfillServiceCPE(ctx, gen.BackfillServiceCPEParams{
				Ip: k.ip, Port: int32(k.port), Cpe: svcCPE,
			}); err != nil {
				return fmt.Errorf("backfill service cpe for %s/%d: %w", k.ip, k.port, err)
			}
		}
	}
	if res.Raw != nil {
		if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
			RunID: b.RunID, BatchID: &b.ID, Scanner: s.cfg.Nuclei.Name(), Content: string(res.Raw),
		}); err != nil {
			return fmt.Errorf("ingest nuclei artifact: %w", err)
		}
	}
	return nil
}
