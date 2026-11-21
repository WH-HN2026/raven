package dojo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
)

// The push runs as its own River job on its own queue, so a slow or down
// Dojo never fails or delays a scan batch: the batch hook only enqueues.

const (
	PushQueue        = "dojo"
	pushMaxAttempts  = 8 // River's backoff (attempt^4 s): retries over ~1.5 h
	pushWorkers      = 2 // concurrent push jobs; each pushes its IPs in parallel
	pushNotReadyWait = 30 * time.Second
	pushJobTimeout   = time.Hour
)

// PushArgs is one batch's push job. The scanner output is read back from the
// batch's (encrypted) artifact, so no scan data sits in the job table.
type PushArgs struct {
	RunID     int64        `json:"run_id"`
	BatchID   int64        `json:"batch_id"`
	ProfileID int64        `json:"profile_id"`
	Scanner   string       `json:"scanner"`   // artifacts.scanner, "nmap"
	ScanType  string       `json:"scan_type"` // Dojo parser, "Nmap Scan"
	IPs       []netip.Addr `json:"ips"`       // responding IPs only (§3.7)
	ScanDate  time.Time    `json:"scan_date"`
}

func (PushArgs) Kind() string { return "dojo_push" }

func (PushArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: PushQueue, MaxAttempts: pushMaxAttempts}
}

// ParseFunc turns a stored artifact back into a scanner result (for PerIP).
type ParseFunc func(raw []byte) (*scanner.Result, error)

// PushService owns the push queue. Pushes wait (snooze) until SetPusher is
// called, i.e. until the Dojo bootstrap has finished.
type PushService struct {
	pool    *pgxpool.Pool
	parsers map[string]ParseFunc // by scanner name
	pusher  atomic.Pointer[Pusher]
	river   *river.Client[pgx.Tx]
}

// NewPushService builds the queue; parsers maps scanner name → parser of its raw output.
func NewPushService(pool *pgxpool.Pool, parsers map[string]ParseFunc) (*PushService, error) {
	s := &PushService{pool: pool, parsers: parsers}
	workers := river.NewWorkers()
	river.AddWorker(workers, &pushWorker{s: s})
	river.AddWorker(workers, &offlineWorker{s: s})
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:     map[string]river.QueueConfig{PushQueue: {MaxWorkers: pushWorkers}},
		Workers:    workers,
		JobTimeout: pushJobTimeout,
		Logger:     slog.Default(),
	})
	if err != nil {
		return nil, fmt.Errorf("dojo push river client: %w", err)
	}
	s.river = rc
	return s, nil
}

func (s *PushService) Start(ctx context.Context) error {
	if err := s.river.Start(ctx); err != nil {
		return fmt.Errorf("dojo push river start: %w", err)
	}
	return nil
}

func (s *PushService) Shutdown(ctx context.Context) error { return s.river.Stop(ctx) }

// SetPusher makes the queue live (called once Dojo is bootstrapped).
func (s *PushService) SetPusher(p *Pusher) { s.pusher.Store(p) }

// AfterBatch is the pipeline's BatchHook: it only enqueues the batch's push.
func (s *PushService) AfterBatch(ctx context.Context, b pipeline.BatchResult) error {
	return s.Enqueue(ctx, ArgsFromBatch(b, time.Now()))
}

// ArgsFromBatch is the push job of a finished batch: only the IPs that
// responded in it (a non-responding host must never be reimported, because
// close_old_findings would close everything on it, §3.7).
func ArgsFromBatch(b pipeline.BatchResult, now time.Time) PushArgs {
	return PushArgs{
		RunID: b.RunID, BatchID: b.BatchID, ProfileID: b.ProfileID,
		Scanner: b.Scanner.Name(), ScanType: b.Scanner.DojoScanType(),
		IPs: append([]netip.Addr(nil), b.Responding...), ScanDate: now,
	}
}

// Enqueue adds a push job for one batch; nothing to do without responding IPs.
func (s *PushService) Enqueue(ctx context.Context, a PushArgs) error {
	if len(a.IPs) == 0 {
		return nil
	}
	if _, err := s.river.Insert(ctx, a, nil); err != nil {
		return fmt.Errorf("enqueue dojo push of batch %d: %w", a.BatchID, err)
	}
	return nil
}

type pushWorker struct {
	river.WorkerDefaults[PushArgs]
	s *PushService
}

func (w *pushWorker) Timeout(*river.Job[PushArgs]) time.Duration { return pushJobTimeout }

func (w *pushWorker) Work(ctx context.Context, job *river.Job[PushArgs]) error {
	p := w.s.pusher.Load()
	if p == nil {
		// Doesn't count as an attempt: wait for the Dojo bootstrap.
		slog.Info("dojo push waiting for dojo bootstrap", "run", job.Args.RunID, "batch", job.Args.BatchID)
		return river.JobSnooze(pushNotReadyWait)
	}
	return w.s.run(ctx, p, job.Args, job.Attempt >= job.MaxAttempts)
}

// run pushes one batch. Every attempt pushes all its IPs again (reimport is
// idempotent); the run's stats.dojo_push are counted once, at the final
// outcome: success, or the last attempt.
func (s *PushService) run(ctx context.Context, p *Pusher, a PushArgs, last bool) error {
	b, err := s.load(ctx, a)
	if err != nil {
		err = fmt.Errorf("dojo push run %d batch %d: %w", a.RunID, a.BatchID, err)
		slog.Error("dojo push", "run", a.RunID, "batch", a.BatchID, "last", last, "err", err)
		if last {
			s.recordStats(ctx, a.RunID, 0, len(a.IPs))
		}
		return err
	}
	results := p.Push(ctx, b)
	ok, failed := 0, 0
	newDevices := 0
	q := gen.New(s.pool)
	ips := make([]netip.Addr, 0, len(results))
	assetIDs := make([]int64, 0, len(results))
	for _, r := range results {
		if r.Err != nil {
			failed++
			slog.Warn("dojo push failed", "run", a.RunID, "batch", a.BatchID, "ip", r.IP, "last", last, "err", r.Err)
			continue
		}
		ips = append(ips, r.IP)
		assetIDs = append(assetIDs, r.AssetID)
		if r.NewDevice {
			newDevices++
		}
	}
	if len(ips) > 0 {
		if err := q.SetHostDojoAssets(ctx, gen.SetHostDojoAssetsParams{Ips: ips, AssetIds: assetIDs}); err != nil {
			failed += len(ips)
			slog.Warn("dojo push: store asset ids", "run", a.RunID, "batch", a.BatchID, "count", len(ips), "err", err)
		} else {
			ok = len(ips)
		}
	}
	slog.Info("dojo push done", "run", a.RunID, "batch", a.BatchID, "ok", ok, "failed", failed,
		"new_devices", newDevices, "last", last)
	if failed > 0 && !last {
		return fmt.Errorf("dojo push run %d batch %d: %d of %d IPs failed", a.RunID, a.BatchID, failed, len(results))
	}
	s.recordStats(ctx, a.RunID, ok, failed)
	return nil
}

func (s *PushService) recordStats(ctx context.Context, runID int64, ok, failed int) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := gen.New(s.pool).AddRunDojoPushStats(dctx, gen.AddRunDojoPushStatsParams{
		ID: runID, Ok: int32(ok), Failed: int32(failed),
	}); err != nil {
		slog.Error("dojo push: record run stats", "run", runID, "err", err)
	}
}

// load gathers the batch's per-IP output and host facts from our DB.
func (s *PushService) load(ctx context.Context, a PushArgs) (PushBatch, error) {
	q := gen.New(s.pool)
	prof, err := q.GetProfile(ctx, a.ProfileID)
	if err != nil {
		return PushBatch{}, fmt.Errorf("get profile %d: %w", a.ProfileID, err)
	}
	res, err := s.loadArtifact(ctx, q, a.BatchID, a.Scanner)
	if err != nil {
		return PushBatch{}, err
	}
	if res == nil {
		return PushBatch{}, fmt.Errorf("no %s artifact", a.Scanner)
	}
	web, err := s.loadArtifact(ctx, q, a.BatchID, "httpx")
	if err != nil {
		return PushBatch{}, err
	}
	detection, err := s.loadArtifact(ctx, q, a.BatchID, "nuclei")
	if err != nil {
		return PushBatch{}, err
	}
	reports, tags := webReports(a.IPs, web, detection)
	hosts, err := q.ListPushHosts(ctx, a.IPs)
	if err != nil {
		return PushBatch{}, fmt.Errorf("list hosts: %w", err)
	}
	svcs, err := q.ListOpenServicesOf(ctx, a.IPs)
	if err != nil {
		return PushBatch{}, fmt.Errorf("list services: %w", err)
	}
	ports := map[netip.Addr][]string{}
	for _, sv := range svcs {
		ports[sv.Ip] = append(ports[sv.Ip], strconv.Itoa(int(sv.Port))+"/"+sv.Proto)
	}
	byIP := make(map[netip.Addr]gen.ListPushHostsRow, len(hosts))
	for _, h := range hosts {
		byIP[h.Ip] = h
	}
	b := PushBatch{RunID: a.RunID, BatchID: a.BatchID, Profile: prof.Name, Scanner: a.Scanner,
		ScanType: a.ScanType, ScanDate: a.ScanDate}
	for _, ip := range a.IPs {
		h := PushHost{IP: ip, OpenPorts: ports[ip], Report: res.PerIP(ip), FirstSeen: a.ScanDate, web: reports[ip], tags: tags[ip]}
		if row, ok := byIP[ip]; ok {
			h.Hostnames, h.FirstSeen = row.Hostnames, row.FirstSeen
			h.tags = append(h.tags, MergeAssetTags(nil, row.UserTags)...)
			if row.DojoAssetID != nil {
				h.AssetID = *row.DojoAssetID
			}
		}
		b.Hosts = append(b.Hosts, h)
	}
	return b, nil
}

func (s *PushService) loadArtifact(ctx context.Context, q *gen.Queries, batchID int64, name string) (*scanner.Result, error) {
	raw, err := q.GetBatchArtifact(ctx, gen.GetBatchArtifactParams{BatchID: &batchID, Scanner: name})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get %s artifact: %w", name, err)
	}
	parse := s.parsers[name]
	if parse == nil {
		return nil, fmt.Errorf("no parser for scanner %q", name)
	}
	res, err := parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("parse %s artifact: %w", name, err)
	}
	return res, nil
}
