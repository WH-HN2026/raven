package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nuclei"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/signatures"
)

func defaultNuclei(pool *pgxpool.Pool) scanner.Scanner {
	return &nuclei.Scanner{
		TemplatesDir: os.Getenv("ASI_NUCLEI_TEMPLATES"),
		CustomDir:    "/opt/asi-signatures",
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
		m.facts = append(m.facts, nucleiMatch{
			Kind: o.Kind, TemplateID: o.Match.TemplateID, Name: o.Match.Name,
			Severity: o.Match.Severity, Tags: nonNil(o.Match.Tags), Matcher: o.Match.Matcher,
			URL: u.String(), CPE: o.CPE, Version: o.Version,
		})
		m.evidence = append(m.evidence, nonNil(o.Match.Extracted))
		if o.Kind == scanner.ObsTech && o.Tech != "" {
			uk := urlKey{k, o.Match.SourceURL}
			tech[uk] = append(tech[uk], o.Tech)
		}
	}
	for k, m := range byService {
		facts, _ := json.Marshal(m.facts)
		evidence, _ := json.Marshal(m.evidence)
		n, err := q.RecordNucleiMatches(ctx, gen.RecordNucleiMatchesParams{
			RunID: b.RunID, Ip: k.ip, Port: pgtype.Int4{Int32: int32(k.port), Valid: true},
			Matches: facts, Evidence: string(evidence),
		})
		if err != nil {
			return fmt.Errorf("ingest nuclei matches for %s/%d: %w", k.ip, k.port, err)
		}
		if n != 1 {
			return fmt.Errorf("ingest nuclei matches for %s/%d: open service observation missing", k.ip, k.port)
		}
	}
	for k, technologies := range tech {
		n, err := q.MergeNucleiTechnologies(ctx, gen.MergeNucleiTechnologiesParams{
			RunID: &b.RunID, Ip: k.ip, Port: int32(k.port), Url: k.url, Technologies: technologies,
		})
		if err != nil {
			return fmt.Errorf("ingest nuclei technologies for %s/%d: %w", k.ip, k.port, err)
		}
		if n == 0 {
			return fmt.Errorf("ingest nuclei technologies for %s/%d: HTTP observation missing", k.ip, k.port)
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
