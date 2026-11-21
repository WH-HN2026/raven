package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/targets"
)

// ImportArtifact is an extra raw upload stored encrypted in artifacts.
type ImportArtifact struct {
	Scanner string
	Raw     []byte
}

// ImportInput holds parsed scan results to ingest without running any scanner.
type ImportInput struct {
	ProfileID int64
	Source    string          // e.g. "results-json", "results-csv", "nmap-xml", "nuclei-jsonl", "nessus"
	Scanner   scanner.Scanner // scanner identity for BatchHook (nil = no hook)
	// ArtifactScanner names the primary artifact written by Ingest (defaults to
	// Scanner.Name() when empty). Set Raw to nil on Result if an extra artifact
	// or Nuclei carries the raw bytes instead.
	ArtifactScanner string
	Result          *scanner.Result         // primary observations (ObsHost, ObsService) + Raw + PerIP
	HTTP            *scanner.Result         // optional ObsHTTP observations + Raw
	Nuclei          *scanner.Result         // optional ObsMatch/ObsTech observations + Raw
	RawExtra        []ImportArtifact        // optional additional raw artifacts (e.g. uploaded JSON/CSV)
	IPs             []netip.Addr            // candidate IPs (filtered through profile scope + global blacklist)
	Hostnames       map[netip.Addr][]string // optional known hostnames per IP
	// Partial prevents GoneServices from closing ports not present in this import
	// (used for partial-view formats like nuclei-jsonl or .nessus).
	Partial  bool
	SkipHook bool // true when the caller pushes to Dojo directly (e.g. .nessus)
	Seen     time.Time
}

// ImportOutcome reports the created run and what passed scope filtering.
type ImportOutcome struct {
	Run         Run
	BatchID     int64
	AllowedIPs  []netip.Addr
	Responding  []netip.Addr
	Candidates  int
	Excluded    int
	NotIncluded int
	Rejected    int
	Warnings    []string
}

// ImportResults creates a run (stats.source = "import"), filters candidate IPs
// through the profile's scope and global blacklist, builds the plan from
// scanner.Observations, ingests into our DB in one transaction, writes
// audit_log, and triggers the configured BatchHook after commit.
func (s *Service) ImportResults(ctx context.Context, u *auth.User, in ImportInput) (ImportOutcome, error) {
	if in.Result == nil {
		return ImportOutcome{}, fmt.Errorf("%w: import result is required", ErrInvalid)
	}
	q := gen.New(s.pool)
	prof, err := q.GetProfile(ctx, in.ProfileID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ImportOutcome{}, fmt.Errorf("%w: profile %d does not exist", ErrInvalid, in.ProfileID)
	}
	if err != nil {
		return ImportOutcome{}, fmt.Errorf("get profile %d: %w", in.ProfileID, err)
	}
	var ports PortSet
	if !in.Partial {
		ports, err = ParsePorts(prof.Ports)
		if err != nil {
			return ImportOutcome{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}

	allowedIPs, hostnames, scopeStats, err := s.filterImportScope(ctx, in.ProfileID, in.IPs, in.Hostnames)
	if err != nil {
		return ImportOutcome{}, fmt.Errorf("filter import scope for profile %d: %w", in.ProfileID, err)
	}

	seen := in.Seen
	if seen.IsZero() {
		seen = time.Now().UTC()
	}
	start := time.Now()

	plan := BuildPlan(allowedIPs, hostnames, in.Result.Observations)
	httpRes, nucleiRes := filterSupplemental(plan, in.HTTP, in.Nuclei)

	initStats := map[string]any{
		"source":       "import",
		"import_kind":  in.Source,
		"candidates":   scopeStats.candidates,
		"not_included": scopeStats.notIncluded,
		"excluded":     scopeStats.excluded,
		"rejected":     scopeStats.rejected,
		"warnings":     nonNil(scopeStats.warnings),
	}
	initStatsJSON, err := json.Marshal(initStats)
	if err != nil {
		return ImportOutcome{}, fmt.Errorf("marshal import stats: %w", err)
	}

	artifactScanner := in.ArtifactScanner
	if artifactScanner == "" && in.Scanner != nil {
		artifactScanner = in.Scanner.Name()
	}
	if artifactScanner == "" {
		artifactScanner = in.Source
	}

	var (
		run     gen.Run
		batchID int64
	)
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		run, err = q.InsertRun(ctx, gen.InsertRunParams{
			ProfileID:  in.ProfileID,
			Status:     "running",
			CreatedBy:  userID(u),
			StartedAt:  &seen,
			HostsTotal: int32(len(allowedIPs)),
			Stats:      initStatsJSON,
		})
		if err != nil {
			return fmt.Errorf("insert import run: %w", err)
		}
		if len(allowedIPs) == 0 {
			extra := map[string]any{"reason": "empty import: no hosts in scope for this profile"}
			if err := s.finishBatchRun(ctx, tx, q, run.ID, "done", extra, nil); err != nil {
				return err
			}
			return audit.Log(ctx, q, userID(u), "import.results", "run", strconv.FormatInt(run.ID, 10), map[string]any{
				"kind": in.Source, "profile_id": in.ProfileID,
				"hosts_total": 0, "hosts_up": 0,
				"excluded": scopeStats.excluded, "not_included": scopeStats.notIncluded, "rejected": scopeStats.rejected,
			})
		}

		batchID, err = q.InsertBatch(ctx, gen.InsertBatchParams{RunID: run.ID, Seq: 1, Ips: allowedIPs})
		if err != nil {
			return fmt.Errorf("insert import batch: %w", err)
		}
		b, err := q.StartBatch(ctx, batchID)
		if err != nil {
			return fmt.Errorf("start import batch: %w", err)
		}
		if err := Ingest(ctx, q, IngestInput{
			RunID: run.ID, BatchID: batchID, Scanner: artifactScanner, Raw: in.Result.Raw,
			Plan: plan, Ports: ports, Seen: seen,
		}); err != nil {
			return err
		}
		if httpRes != nil && (len(httpRes.Observations) > 0 || len(httpRes.Raw) > 0) {
			if err := s.ingestHTTP(ctx, q, b, httpRes, seen); err != nil {
				return err
			}
		}
		if nucleiRes != nil && (len(nucleiRes.Observations) > 0 || len(nucleiRes.Raw) > 0) {
			if err := s.ingestNuclei(ctx, q, b, nucleiRes); err != nil {
				return err
			}
		}
		for _, extra := range in.RawExtra {
			if len(extra.Raw) == 0 || extra.Scanner == "" {
				continue
			}
			if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
				RunID: run.ID, BatchID: &batchID, Scanner: extra.Scanner, Content: string(extra.Raw),
			}); err != nil {
				return fmt.Errorf("ingest %s artifact: %w", extra.Scanner, err)
			}
		}
		now := time.Now()
		dur := now.Sub(start).Milliseconds()
		if err := q.FinishBatch(ctx, gen.FinishBatchParams{
			ID: batchID, Status: "done", FinishedAt: &now, DurationMs: &dur, HostsUp: int32(len(plan.Up)),
		}); err != nil {
			return fmt.Errorf("finish import batch %d: %w", batchID, err)
		}
		if err := s.finishBatchRun(ctx, tx, q, run.ID, "done", nil, nil); err != nil {
			return err
		}
		return audit.Log(ctx, q, userID(u), "import.results", "run", strconv.FormatInt(run.ID, 10), map[string]any{
			"kind": in.Source, "profile_id": in.ProfileID,
			"hosts_total": len(allowedIPs), "hosts_up": len(plan.Up), "services": len(plan.Services),
			"excluded": scopeStats.excluded, "not_included": scopeStats.notIncluded, "rejected": scopeStats.rejected,
		})
	})
	if err != nil {
		return ImportOutcome{}, err
	}

	if !in.SkipHook && in.Scanner != nil && len(plan.Up) > 0 {
		hookRes := in.Result
		if in.Scanner.Name() == "nuclei" && nucleiRes != nil {
			hookRes = nucleiRes
		}
		if err := s.cfg.Hook.AfterBatch(ctx, BatchResult{
			RunID: run.ID, BatchID: batchID, ProfileID: prof.ID,
			Responding: plan.Up, Scanner: in.Scanner, Result: hookRes,
		}); err != nil {
			slog.Error("import after-batch hook", "run", run.ID, "batch", batchID, "err", err)
		}
	}

	view, err := s.GetRun(ctx, run.ID)
	if err != nil {
		return ImportOutcome{}, err
	}
	return ImportOutcome{
		Run:         view,
		BatchID:     batchID,
		AllowedIPs:  allowedIPs,
		Responding:  plan.Up,
		Candidates:  scopeStats.candidates,
		Excluded:    scopeStats.excluded,
		NotIncluded: scopeStats.notIncluded,
		Rejected:    scopeStats.rejected,
		Warnings:    scopeStats.warnings,
	}, nil
}

type importScopeStats struct {
	candidates  int
	notIncluded int
	excluded    int
	rejected    int
	warnings    []string
}

// filterImportScope applies the profile's include/exclude rules and the global
// blacklist (exclusions always win) to the imported IPs using targets.Expand,
// plus offline hostname matching against domain exclude rules.
func (s *Service) filterImportScope(ctx context.Context, profileID int64, ips []netip.Addr, hostnames map[netip.Addr][]string) ([]netip.Addr, map[netip.Addr][]string, importScopeStats, error) {
	rules, err := gen.New(s.pool).ListEffectiveScope(ctx, &profileID)
	if err != nil {
		return nil, nil, importScopeStats{}, fmt.Errorf("load effective scope: %w", err)
	}
	var sc targets.Scope
	var excludeDomains []string
	for _, r := range rules {
		rule := targets.Rule{Kind: targets.Kind(r.Kind), Value: r.Value}
		if r.List == "include" {
			sc.Include = append(sc.Include, rule)
		} else {
			sc.Exclude = append(sc.Exclude, rule)
			if rule.Kind == targets.KindDomain {
				excludeDomains = append(excludeDomains, strings.ToLower(strings.TrimSuffix(rule.Value, ".")))
			}
		}
	}

	seen := make(map[netip.Addr]bool, len(ips))
	entries := make([]targets.Entry, 0, len(ips))
	for _, rawIP := range ips {
		if !rawIP.IsValid() {
			continue
		}
		ip := rawIP.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		entries = append(entries, targets.Entry{Kind: targets.KindIP, Value: ip.String()})
	}

	sl, err := targets.Expand(ctx, entries, sc, s.cfg.Resolver, targets.Limits{})
	if err != nil {
		return nil, nil, importScopeStats{}, err
	}

	st := importScopeStats{
		candidates:  sl.Stats.Candidates,
		notIncluded: sl.Stats.NotIncluded,
		excluded:    sl.Stats.Excluded,
		rejected:    sl.Stats.Rejected,
		warnings:    sl.Warnings,
	}

	allowed := make([]netip.Addr, 0, len(sl.IPs))
	outNames := make(map[netip.Addr][]string, len(sl.IPs))
	for _, ip := range sl.IPs {
		names := hostnames[ip]
		if matchesAnyDomain(names, excludeDomains) {
			st.excluded++
			continue
		}
		allowed = append(allowed, ip)
		if len(names) > 0 {
			outNames[ip] = slices.Clone(names)
		}
	}
	return allowed, outNames, st, nil
}

func matchesAnyDomain(hostnames, domains []string) bool {
	if len(hostnames) == 0 || len(domains) == 0 {
		return false
	}
	for _, h := range hostnames {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		for _, d := range domains {
			if h == d || strings.HasSuffix(h, "."+d) {
				return true
			}
		}
	}
	return false
}

// filterSupplemental restricts HTTP and Nuclei observations to TCP services
// that are open in plan (ensuring ingestHTTP and ingestNuclei never fail on a
// filtered-out IP or missing service row).
func filterSupplemental(plan Plan, web, det *scanner.Result) (*scanner.Result, *scanner.Result) {
	openTCP := make(map[svcKey]bool, len(plan.Services))
	for _, sv := range plan.Services {
		if sv.Proto == "tcp" {
			openTCP[sv.key()] = true
		}
	}

	var outWeb *scanner.Result
	httpURLs := make(map[string]bool)
	if web != nil {
		filtered := &scanner.Result{Raw: web.Raw, PerIP: web.PerIP}
		for _, o := range web.Observations {
			ip := o.IP.Unmap()
			if o.Kind != scanner.ObsHTTP || o.HTTP == nil || !openTCP[svcKey{ip, o.Port, "tcp"}] {
				continue
			}
			o.IP = ip
			filtered.Observations = append(filtered.Observations, o)
			httpURLs[ip.String()+"|"+strconv.Itoa(int(o.Port))+"|"+o.URL] = true
		}
		outWeb = filtered
	}

	var outDet *scanner.Result
	if det != nil {
		filtered := &scanner.Result{Raw: det.Raw, PerIP: det.PerIP}
		for _, o := range det.Observations {
			ip := o.IP.Unmap()
			if o.Match == nil || (o.Kind != scanner.ObsMatch && o.Kind != scanner.ObsTech) {
				continue
			}
			if !openTCP[svcKey{ip, o.Port, "tcp"}] {
				continue
			}
			o.IP = ip
			// MergeNucleiTechnologies requires an HTTP observation for (ip, port, SourceURL).
			if o.Kind == scanner.ObsTech && o.Tech != "" && o.Match.SourceURL != "" {
				key := ip.String() + "|" + strconv.Itoa(int(o.Port)) + "|" + o.Match.SourceURL
				if !httpURLs[key] {
					if outWeb == nil {
						outWeb = &scanner.Result{}
					}
					outWeb.Observations = append(outWeb.Observations, scanner.Observation{
						Kind: scanner.ObsHTTP, IP: ip, Hostname: o.Hostname, At: o.At,
						Port: o.Port, Proto: "tcp", URL: o.Match.SourceURL,
						HTTP: &scanner.HTTPInfo{},
					})
					httpURLs[key] = true
				}
			}
			filtered.Observations = append(filtered.Observations, o)
		}
		outDet = filtered
	}
	return outWeb, outDet
}
