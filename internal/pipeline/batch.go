package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/httpx"
)

// BatchArgs is the River job of one batch. The IPs live in batches.ips;
// the host names known from the scan list travel with the job.
type BatchArgs struct {
	BatchID   int64               `json:"batch_id"`
	RunID     int64               `json:"run_id"`
	Hostnames map[string][]string `json:"hostnames,omitempty"`
}

func (BatchArgs) Kind() string { return "scan_batch" }

type batchWorker struct {
	river.WorkerDefaults[BatchArgs]
	s *Service
}

func (w *batchWorker) Timeout(*river.Job[BatchArgs]) time.Duration { return jobTimeout }

func (w *batchWorker) Work(ctx context.Context, job *river.Job[BatchArgs]) error {
	return w.s.runBatch(ctx, job.Args, job.ID, job.Attempt, job.MaxAttempts)
}

func isActive(status string) bool { return status == "pending" || status == "running" }

// errSkip means the batch must not run (its run was stopped, or the batch is
// already finished); the job ends without error.
var errSkip = errors.New("skip batch")

func (s *Service) runBatch(ctx context.Context, a BatchArgs, jobID int64, attempt, maxAttempts int) error {
	var (
		b      gen.Batch
		prof   gen.Profile
		window gen.Run
		closed bool
	)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		run, err := q.LockRun(ctx, a.RunID)
		if err != nil {
			return fmt.Errorf("lock run %d: %w", a.RunID, err)
		}
		if !isActive(run.Status) {
			return errSkip
		}
		if run.ScheduleID != nil {
			owned, err := scheduledJobOwnsBatch(ctx, q, a.BatchID, &jobID)
			if err != nil {
				return err
			}
			if !owned {
				return errSkip
			}
			window = run
			if run.ScheduleWindowEnd != nil && !time.Now().Before(*run.ScheduleWindowEnd) {
				closed = true
				return suspendLockedRun(ctx, q, run)
			}
		}
		b, err = q.StartBatch(ctx, a.BatchID)
		if errors.Is(err, pgx.ErrNoRows) {
			return errSkip
		}
		if err != nil {
			return fmt.Errorf("start batch %d: %w", a.BatchID, err)
		}
		if err := q.MarkRunRunning(ctx, run.ID); err != nil {
			return fmt.Errorf("mark run %d running: %w", run.ID, err)
		}
		prof, err = q.GetProfile(ctx, run.ProfileID)
		if err != nil {
			return fmt.Errorf("get profile %d: %w", run.ProfileID, err)
		}
		return nil
	})
	if errors.Is(err, errSkip) {
		slog.Info("batch skipped", "run", a.RunID, "batch", a.BatchID)
		return nil
	}
	if err != nil {
		return err
	}

	if closed {
		return nil
	}

	jobCtx := ctx
	if window.ScheduleWindowEnd != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadlineCause(ctx, *window.ScheduleWindowEnd, errWindowClosed)
		defer cancel()
	}

	start := time.Now()
	slog.Info("batch started", "run", a.RunID, "batch", b.ID, "seq", b.Seq, "hosts", len(b.Ips), "attempt", attempt)
	hostnames := map[netip.Addr][]string{}
	for k, v := range a.Hostnames {
		if ip, err := netip.ParseAddr(k); err == nil {
			hostnames[ip] = v
		}
	}
	in := scanner.Input{IPs: b.Ips, Hostnames: hostnames}
	res, err := s.cfg.Scanner.Run(ctx, in,
		scanner.Options{Ports: prof.Ports, MaxRate: s.nmapRate(prof)})
	var web *scanner.Result
	if err == nil {
		if webIn := httpx.BuildInput(in, res.Observations); len(webIn.URLs) > 0 {
			web, err = s.cfg.HTTPX.Run(ctx, webIn, scanner.Options{RateLimit: s.webRate(prof)})
		}
	}
	var detection *scanner.Result
	if err == nil {
		detection, err = s.scanNuclei(ctx, b, prof, web)
	}
	if err == nil {
		var plan Plan
		plan, err = s.ingestBatch(ctx, b, prof, hostnames, res, web, detection, start)
		if err == nil {
			s.afterBatch(jobCtx, b, prof, plan, res)
			return nil
		}
	}
	if errors.Is(context.Cause(ctx), errWindowClosed) {
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(jobCtx), 30*time.Second)
		defer cancel()
		return s.pauseScheduledRun(recordCtx, window)
	}
	if errors.Is(err, errSkip) {
		return river.JobCancel(errSkip)
	}
	return s.batchFailed(ctx, b, start, err, attempt, maxAttempts)
}

// ingestBatch writes the batch result, marks the batch done and, if it was
// the last one, finishes the run, all in one transaction under the run lock.
func (s *Service) ingestBatch(ctx context.Context, b gen.Batch, prof gen.Profile,
	hostnames map[netip.Addr][]string, res, web, detection *scanner.Result, start time.Time) (Plan, error) {
	ports, err := ParsePorts(prof.Ports)
	if err != nil {
		return Plan{}, err
	}
	plan := BuildPlan(b.Ips, hostnames, res.Observations)
	var reprobeIPs []netip.Addr
	var lifecycle lifecycleStats
	commit := func(tx pgx.Tx) error {
		q := gen.New(tx)
		run, err := q.LockRun(ctx, b.RunID)
		if err != nil {
			return fmt.Errorf("lock run %d: %w", b.RunID, err)
		}
		if !isActive(run.Status) {
			return errSkip
		}
		if run.ScheduleID != nil {
			owned, err := scheduledJobOwnsBatch(ctx, q, b.ID, b.JobID)
			if err != nil {
				return err
			}
			if !owned {
				return errSkip
			}
		}
		bs, err := q.RunBatchStats(ctx, run.ID)
		if err != nil {
			return fmt.Errorf("batch stats of run %d: %w", run.ID, err)
		}
		status, finished := RunOutcome(BatchCounts{Unfinished: bs.Unfinished - 1, Failed: bs.Failed})
		if status == "done" && len(reprobeIPs) == 0 {
			reprobeIPs, err = listReprobeIPs(ctx, q, run, plan)
			if err != nil || len(reprobeIPs) > 0 {
				// Leave this batch running while its job re-probes outside the lock.
				return err
			}
		}
		now := time.Now()
		if err := Ingest(ctx, q, IngestInput{
			RunID: b.RunID, BatchID: b.ID, Scanner: s.cfg.Scanner.Name(), Raw: res.Raw,
			Plan: plan, Ports: ports, Seen: now,
		}); err != nil {
			return err
		}
		if web != nil {
			if err := s.ingestHTTP(ctx, q, b, web, now); err != nil {
				return err
			}
		}
		if detection != nil {
			if err := s.ingestNuclei(ctx, q, b, detection); err != nil {
				return err
			}
		}
		dur := now.Sub(start).Milliseconds()
		if err := q.FinishBatch(ctx, gen.FinishBatchParams{
			ID: b.ID, Status: "done", FinishedAt: &now, DurationMs: &dur, HostsUp: int32(len(plan.Up)),
		}); err != nil {
			return fmt.Errorf("finish batch %d: %w", b.ID, err)
		}
		if !finished {
			return nil
		}
		var extra map[string]any
		if status == "done" {
			if err := lifecycle.apply(ctx, q, run, prof.MissThreshold, now); err != nil {
				return err
			}
			extra = lifecycle.runStats()
		}
		slog.Info("run finished", "run", run.ID, "status", status)
		return s.finishBatchRun(ctx, tx, q, run.ID, status, extra, lifecycle.inactiveIPs)
	}
	err = pgx.BeginFunc(ctx, s.pool, commit)
	if err == nil && len(reprobeIPs) > 0 {
		lifecycle, err = s.reprobeHosts(ctx, reprobeIPs, prof, ports)
		if err == nil {
			err = pgx.BeginFunc(ctx, s.pool, commit)
		}
	}
	if err == nil {
		slog.Info("batch done", "run", b.RunID, "batch", b.ID, "up", len(plan.Up),
			"services", len(plan.Services), "dur", time.Since(start).Round(time.Millisecond))
	}
	return plan, err
}

// maybeFinishRun finishes the run when no batch is pending or running. The
// caller holds the run's row lock (LockRun), so two batches finishing at
// the same time can't both see themselves as last or both miss it.
func maybeFinishRun(ctx context.Context, q *gen.Queries, runID int64) error {
	bs, err := q.RunBatchStats(ctx, runID)
	if err != nil {
		return fmt.Errorf("batch stats of run %d: %w", runID, err)
	}
	status, finished := RunOutcome(BatchCounts{Unfinished: bs.Unfinished, Failed: bs.Failed})
	if !finished {
		return nil
	}
	slog.Info("run finished", "run", runID, "status", status)
	return finishRun(ctx, q, runID, status, nil)
}

// batchFailed records a failed attempt. A stopped run → the job is cancelled
// (no retry). Otherwise the batch goes back to pending while River has
// attempts left, and becomes 'failed' (possibly finishing the run) on the
// last one. The DB writes use a context detached from the job's, because
// the job's ctx is usually what was cancelled.
func (s *Service) batchFailed(ctx context.Context, b gen.Batch, start time.Time, cause error, attempt, maxAttempts int) error {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	msg := cause.Error()
	last := attempt >= maxAttempts
	var suspended bool
	err := pgx.BeginFunc(dctx, s.pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		run, err := q.LockRun(dctx, b.RunID)
		if err != nil {
			return fmt.Errorf("lock run %d: %w", b.RunID, err)
		}
		if !isActive(run.Status) {
			return errSkip // StopRun already marked the batch stopped
		}
		if run.ScheduleID != nil {
			owned, err := scheduledJobOwnsBatch(dctx, q, b.ID, b.JobID)
			if err != nil {
				return err
			}
			if !owned {
				return errSkip
			}
			if run.ScheduleWindowEnd != nil && !time.Now().Before(*run.ScheduleWindowEnd) {
				suspended = true
				return suspendLockedRun(dctx, q, run)
			}
		}
		if !last {
			return q.RetryBatch(dctx, gen.RetryBatchParams{ID: b.ID, Error: msg})
		}
		now := time.Now()
		dur := now.Sub(start).Milliseconds()
		if err := q.FinishBatch(dctx, gen.FinishBatchParams{
			ID: b.ID, Status: "failed", FinishedAt: &now, DurationMs: &dur, Error: msg,
		}); err != nil {
			return fmt.Errorf("fail batch %d: %w", b.ID, err)
		}
		return maybeFinishRun(dctx, q, run.ID)
	})
	switch {
	case errors.Is(err, errSkip):
		slog.Info("batch stopped", "run", b.RunID, "batch", b.ID)
		return river.JobCancel(cause)
	case err != nil:
		slog.Error("record batch failure", "run", b.RunID, "batch", b.ID, "err", err)
	}
	if err == nil && suspended {
		return nil
	}
	slog.Warn("batch failed", "run", b.RunID, "batch", b.ID, "attempt", attempt, "last", last, "err", cause)
	return fmt.Errorf("batch %d: %w", b.ID, cause)
}

func (s *Service) afterBatch(ctx context.Context, b gen.Batch, prof gen.Profile, plan Plan, res *scanner.Result) {
	err := s.cfg.Hook.AfterBatch(ctx, BatchResult{
		RunID: b.RunID, BatchID: b.ID, ProfileID: prof.ID,
		Responding: plan.Up, Scanner: s.cfg.Scanner, Result: res,
	})
	if err != nil {
		slog.Error("after-batch hook", "run", b.RunID, "batch", b.ID, "err", err)
	}
}
