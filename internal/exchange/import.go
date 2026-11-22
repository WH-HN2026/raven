package exchange

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
)

// Service coordinates scan-result imports and data exports.
type Service struct {
	Pool          *pgxpool.Pool
	Pipeline      *pipeline.Service
	DojoPush      *dojo.PushService // optional: used for .nessus push into DefectDojo
	DojoPublicURL string
}

// ImportRequest is one uploaded scan-result file.
type ImportRequest struct {
	Kind     ImportKind // empty = auto-detect from Filename / Data
	Profile  string     // profile ID or name; empty = pipeline.DefaultProfileName
	Filename string
	Data     []byte
}

// staticScanner provides scanner Name/DojoScanType metadata to the pipeline's
// BatchHook without ever executing a subprocess.
type staticScanner struct {
	name     string
	scanType string
}

func (s staticScanner) Name() string         { return s.name }
func (s staticScanner) DojoScanType() string { return s.scanType }
func (s staticScanner) Run(context.Context, scanner.Input, scanner.Options) (*scanner.Result, error) {
	return nil, errors.New("import scanner cannot be executed")
}

var (
	nmapImportScanner   = staticScanner{name: "nmap", scanType: "Nmap Scan"}
	nucleiImportScanner = staticScanner{name: "nuclei", scanType: "Nuclei Scan"}
)

// ImportResults parses an uploaded scan-result file, filters its hosts through
// the profile's scope and global blacklist, ingests through the pipeline, and
// triggers Dojo push.
func (s *Service) ImportResults(ctx context.Context, u *auth.User, req ImportRequest) (pipeline.Run, error) {
	if s.Pipeline == nil {
		return pipeline.Run{}, fmt.Errorf("%w: pipeline service not configured", ErrNotReady)
	}
	if len(req.Data) == 0 {
		return pipeline.Run{}, fmt.Errorf("%w: uploaded file is empty", ErrInvalid)
	}
	if len(req.Data) > MaxImportBytes {
		return pipeline.Run{}, fmt.Errorf("%w: file exceeds %d bytes", ErrInvalid, MaxImportBytes)
	}
	kind := req.Kind
	if kind == "" {
		kind = DetectImportKind(req.Filename, req.Data)
	}
	if !ValidImportKind(kind) {
		return pipeline.Run{}, fmt.Errorf("%w: kind must be one of results-json, results-csv, nmap-xml, nuclei-jsonl, nessus", ErrInvalid)
	}

	prof, err := s.resolveProfile(ctx, req.Profile)
	if err != nil {
		return pipeline.Run{}, err
	}

	switch kind {
	case ImportResultsJSON:
		doc, err := ParseResultsJSON(req.Data)
		if err != nil {
			return pipeline.Run{}, err
		}
		return s.importNativeResults(ctx, u, prof.ID, kind, req.Data, doc)

	case ImportResultsCSV:
		doc, err := ParseResultsCSV(bytes.NewReader(req.Data))
		if err != nil {
			return pipeline.Run{}, err
		}
		return s.importNativeResults(ctx, u, prof.ID, kind, req.Data, doc)

	case ImportNmapXML:
		return s.importNmapXML(ctx, u, prof.ID, req.Data)

	case ImportNucleiJSONL:
		return s.importNucleiJSONL(ctx, u, prof.ID, req.Data)

	case ImportNessus:
		return s.importNessus(ctx, u, prof, req.Data)

	default:
		return pipeline.Run{}, fmt.Errorf("%w: unsupported kind %q", ErrInvalid, kind)
	}
}

func (s *Service) resolveProfile(ctx context.Context, ref string) (gen.Profile, error) {
	q := gen.New(s.Pool)
	ref = strings.TrimSpace(ref)
	if ref == "" {
		ref = pipeline.DefaultProfileName
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil && id > 0 {
		p, err := q.GetProfile(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return gen.Profile{}, fmt.Errorf("%w: profile %d not found", ErrInvalid, id)
		}
		if err != nil {
			return gen.Profile{}, fmt.Errorf("get profile %d: %w", id, err)
		}
		return p, nil
	}
	p, err := q.GetProfileByName(ctx, ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return gen.Profile{}, fmt.Errorf("%w: profile %q not found", ErrInvalid, ref)
	}
	if err != nil {
		return gen.Profile{}, fmt.Errorf("get profile %q: %w", ref, err)
	}
	return p, nil
}

func (s *Service) importNativeResults(ctx context.Context, u *auth.User, profileID int64, kind ImportKind, raw []byte, doc *ResultsDocument) (pipeline.Run, error) {
	primary, httpRes, nucleiRes, ips, hostnames, err := doc.BuildImportData()
	if err != nil {
		return pipeline.Run{}, err
	}
	var seen time.Time
	if doc.ScannedAt != nil {
		seen = doc.ScannedAt.UTC()
	}
	out, err := s.Pipeline.ImportResults(ctx, u, pipeline.ImportInput{
		ProfileID:       profileID,
		Source:          string(kind),
		Scanner:         nmapImportScanner,
		ArtifactScanner: "nmap",
		Result:          primary,
		HTTP:            httpRes,
		Nuclei:          nucleiRes,
		RawExtra:        []pipeline.ImportArtifact{{Scanner: string(kind), Raw: raw}},
		IPs:             ips,
		Hostnames:       hostnames,
		Seen:            seen,
	})
	if err != nil {
		return pipeline.Run{}, err
	}
	return out.Run, nil
}

func (s *Service) importNmapXML(ctx context.Context, u *auth.User, profileID int64, raw []byte) (pipeline.Run, error) {
	res, err := nmap.Parse(raw)
	if err != nil {
		return pipeline.Run{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var (
		ips       []netip.Addr
		seenIP    = make(map[netip.Addr]bool)
		hostnames = make(map[netip.Addr][]string)
		httpObs   []scanner.Observation
		seenAt    time.Time
	)
	for _, o := range res.Observations {
		if !o.IP.IsValid() {
			continue
		}
		ip := o.IP.Unmap()
		if !seenIP[ip] {
			seenIP[ip] = true
			ips = append(ips, ip)
		}
		if o.Hostname != "" {
			hostnames[ip] = mergeUniqueStrings(hostnames[ip], []string{o.Hostname})
		}
		if seenAt.IsZero() && !o.At.IsZero() {
			seenAt = o.At
		}
		if o.Kind == scanner.ObsHTTP && o.HTTP != nil && o.URL != "" {
			cp := o
			info := *o.HTTP
			if info.Headers == nil {
				info.Headers = map[string]string{}
			}
			cp.HTTP = &info
			httpObs = append(httpObs, cp)
		}
	}
	if len(ips) == 0 {
		return pipeline.Run{}, fmt.Errorf("%w: nmap XML contains no hosts", ErrInvalid)
	}
	var httpRes *scanner.Result
	if len(httpObs) > 0 {
		httpRes = &scanner.Result{Observations: httpObs}
	}
	out, err := s.Pipeline.ImportResults(ctx, u, pipeline.ImportInput{
		ProfileID:       profileID,
		Source:          string(ImportNmapXML),
		Scanner:         nmapImportScanner,
		ArtifactScanner: "nmap",
		Result:          res,
		HTTP:            httpRes,
		IPs:             ips,
		Hostnames:       hostnames,
		Seen:            seenAt,
	})
	if err != nil {
		return pipeline.Run{}, err
	}
	return out.Run, nil
}

func (s *Service) importNucleiJSONL(ctx context.Context, u *auth.User, profileID int64, raw []byte) (pipeline.Run, error) {
	parsed, err := nuclei.Parse(raw)
	if err != nil {
		return pipeline.Run{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(parsed.Observations) == 0 {
		return pipeline.Run{}, fmt.Errorf("%w: nuclei JSONL contains no valid match records", ErrInvalid)
	}

	type svcKey struct {
		ip   netip.Addr
		port uint16
	}
	var (
		ips       []netip.Addr
		seenIP    = make(map[netip.Addr]bool)
		seenSvc   = make(map[svcKey]bool)
		hostnames = make(map[netip.Addr][]string)
		baseObs   []scanner.Observation
		seenAt    time.Time
	)
	for _, o := range parsed.Observations {
		ip := o.IP.Unmap()
		if !ip.IsValid() {
			continue
		}
		if seenAt.IsZero() && !o.At.IsZero() {
			seenAt = o.At
		}
		if o.Hostname != "" {
			hostnames[ip] = mergeUniqueStrings(hostnames[ip], []string{o.Hostname})
		}
		if !seenIP[ip] {
			seenIP[ip] = true
			ips = append(ips, ip)
			baseObs = append(baseObs, scanner.Observation{
				Kind: scanner.ObsHost, IP: ip, Hostname: o.Hostname, At: o.At, Up: true,
			})
		}
		sk := svcKey{ip, o.Port}
		if o.Port > 0 && !seenSvc[sk] {
			seenSvc[sk] = true
			svcName := "http"
			if strings.HasPrefix(o.URL, "https://") {
				svcName = "https"
			}
			baseObs = append(baseObs, scanner.Observation{
				Kind: scanner.ObsService, IP: ip, Hostname: o.Hostname, At: o.At,
				Port: o.Port, Proto: "tcp", Service: svcName,
				Product: o.Product, Version: o.Version, CPE: o.CPE,
			})
		}
	}

	primary := &scanner.Result{Observations: baseObs, PerIP: parsed.PerIP}
	out, err := s.Pipeline.ImportResults(ctx, u, pipeline.ImportInput{
		ProfileID:       profileID,
		Source:          string(ImportNucleiJSONL),
		Scanner:         nucleiImportScanner,
		ArtifactScanner: "nuclei",
		Result:          primary,
		Nuclei:          parsed,
		IPs:             ips,
		Hostnames:       hostnames,
		Partial:         true,
		Seen:            seenAt,
	})
	if err != nil {
		return pipeline.Run{}, err
	}
	return out.Run, nil
}

func (s *Service) importNessus(ctx context.Context, u *auth.User, prof gen.Profile, raw []byte) (pipeline.Run, error) {
	doc, err := ParseNessus(raw)
	if err != nil {
		return pipeline.Run{}, err
	}
	// If Dojo integration is configured, wait until bootstrap has produced a Pusher
	// so we don't ingest without pushing the Nessus findings to Dojo.
	var pusher *dojo.Pusher
	if s.DojoPush != nil {
		pusher = s.DojoPush.Pusher()
		if pusher == nil {
			return pipeline.Run{}, ErrNotReady
		}
	}

	seen := time.Now().UTC()
	res, ips, hostnames := doc.BuildObservations(seen)
	out, err := s.Pipeline.ImportResults(ctx, u, pipeline.ImportInput{
		ProfileID:       prof.ID,
		Source:          string(ImportNessus),
		ArtifactScanner: dojo.NessusScanner,
		Result:          res,
		IPs:             ips,
		Hostnames:       hostnames,
		Partial:         true,
		SkipHook:        true,
		Seen:            seen,
	})
	if err != nil {
		return pipeline.Run{}, err
	}

	if pusher != nil && len(out.AllowedIPs) > 0 {
		allowed := make(map[netip.Addr]bool, len(out.AllowedIPs))
		for _, ip := range out.AllowedIPs {
			allowed[ip] = true
		}
		var batch dojo.NessusBatch
		batch.Profile = prof.Name
		batch.ScanDate = seen
		for _, h := range doc.Hosts {
			if !allowed[h.IP] {
				continue
			}
			if slice := doc.PerIP(h.IP); len(slice) > 0 {
				batch.Hosts = append(batch.Hosts, dojo.NessusHost{
					IP: h.IP, Hostnames: slices.Clone(h.Hostnames), Report: slice,
				})
			}
		}
		if len(batch.Hosts) > 0 {
			results := pusher.PushNessus(ctx, batch)
			q := gen.New(s.Pool)
			okCount, failCount := 0, 0
			for _, r := range results {
				if r.Err != nil {
					failCount++
					slog.Warn("nessus dojo push failed", "run", out.Run.ID, "ip", r.IP, "err", r.Err)
					continue
				}
				id := r.AssetID
				if err := q.SetHostDojoAsset(ctx, gen.SetHostDojoAssetParams{Ip: r.IP, DojoAssetID: &id}); err != nil {
					failCount++
					slog.Warn("nessus dojo push: store asset id", "run", out.Run.ID, "ip", r.IP, "err", err)
					continue
				}
				okCount++
			}
			if err := q.AddRunDojoPushStats(ctx, gen.AddRunDojoPushStatsParams{
				ID: out.Run.ID, Ok: int32(okCount), Failed: int32(failCount),
			}); err != nil {
				slog.Warn("nessus dojo push: record run stats", "run", out.Run.ID, "err", err)
			}
			if updated, err := s.Pipeline.GetRun(ctx, out.Run.ID); err == nil {
				out.Run = updated
			}
		}
	}
	return out.Run, nil
}
