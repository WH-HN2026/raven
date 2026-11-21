// Package pipeline orchestrates scan runs (architecture §3):
// a run's scan list is split into batches, each batch is one River job that
// runs nmap, httpx and nuclei and ingests their results in one transaction.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/audit"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/httpx"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/targets"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid input")
)

const (
	maxAttempts = 3             // per batch, River's retries
	maxWorkers  = 2             // concurrent batches (S5: global concurrency cap)
	jobTimeout  = 4 * time.Hour // nmap's --host-timeout bounds it well below this
)

// BatchHook runs after a batch's ingest committed (D2 pushes to Dojo here).
// Errors are logged; they don't fail the batch.
type BatchHook interface {
	AfterBatch(ctx context.Context, b BatchResult) error
}

// BatchResult is what a hook gets: the batch, the IPs that responded in it
// (only those may be reimported, architecture §3.7) and the raw scanner result.
type BatchResult struct {
	RunID, BatchID, ProfileID int64
	Responding                []netip.Addr
	Scanner                   scanner.Scanner
	Result                    *scanner.Result
}

type nopHook struct{}

func (nopHook) AfterBatch(context.Context, BatchResult) error { return nil }

// Config wires the pipeline's collaborators.
type Config struct {
	Scanner   scanner.Scanner  // nmap
	HTTPX     scanner.Scanner  // nil = ProjectDiscovery httpx from PATH
	Nuclei    scanner.Scanner  // nil = ProjectDiscovery nuclei from PATH
	Resolver  targets.Resolver // net.DefaultResolver in production
	Hook      BatchHook        // nil = no-op
	BatchSize int              // 0 = BatchSize
	Workers   int              // 0 = maxWorkers
}

type Service struct {
	pool  *pgxpool.Pool
	cfg   Config
	river *river.Client[pgx.Tx]
}

// New builds the service and its River client (not started yet).
func New(pool *pgxpool.Pool, cfg Config) (*Service, error) {
	if cfg.HTTPX == nil {
		cfg.HTTPX = &httpx.Scanner{}
	}
	if cfg.Nuclei == nil {
		cfg.Nuclei = defaultNuclei(pool)
	}
	if cfg.Hook == nil {
		cfg.Hook = nopHook{}
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = BatchSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = maxWorkers
	}
	s := &Service{pool: pool, cfg: cfg}
	workers := river.NewWorkers()
	river.AddWorker(workers, &batchWorker{s: s})
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:     map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: cfg.Workers}},
		Workers:    workers,
		JobTimeout: jobTimeout,
		Logger:     slog.Default(),
	})
	if err != nil {
		return nil, fmt.Errorf("river client: %w", err)
	}
	s.river = rc
	return s, nil
}

// Start starts the job workers.
func (s *Service) Start(ctx context.Context) error {
	if err := s.river.Start(ctx); err != nil {
		return fmt.Errorf("river start: %w", err)
	}
	return nil
}

// Shutdown cancels running batches (River retries them later) and stops.
func (s *Service) Shutdown(ctx context.Context) error {
	return s.river.StopAndCancel(ctx)
}

func userID(u *auth.User) *int64 {
	if u == nil {
		return nil
	}
	return &u.ID
}

// Run is the API view of a run with batch progress.
type Run struct {
	ID            int64           `json:"id"`
	ProfileID     int64           `json:"profile_id"`
	ScheduleID    *int64          `json:"schedule_id"`
	Status        string          `json:"status"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
	HostsTotal    int32           `json:"hosts_total"`
	HostsUp       int32           `json:"hosts_up"`
	BatchesTotal  int64           `json:"batches_total"`
	BatchesDone   int64           `json:"batches_done"`
	BatchesFailed int64           `json:"batches_failed"`
	Stats         json.RawMessage `json:"stats"`
}

func runView(r gen.Run, total, done, failed int64) Run {
	return Run{ID: r.ID, ProfileID: r.ProfileID, ScheduleID: r.ScheduleID, Status: r.Status,
		CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		HostsTotal: r.HostsTotal, HostsUp: r.HostsUp,
		BatchesTotal: total, BatchesDone: done, BatchesFailed: failed, Stats: r.Stats}
}

// Batch is the API view of a batch.
type Batch struct {
	ID         int64      `json:"id"`
	RunID      int64      `json:"run_id"`
	Seq        int32      `json:"seq"`
	HostCount  int        `json:"host_count"`
	HostsUp    int32      `json:"hosts_up"`
	Status     string     `json:"status"`
	Attempts   int32      `json:"attempts"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	DurationMs *int64     `json:"duration_ms"`
	Error      string     `json:"error"`
}

// GetRun returns one run with its batch progress.
func (s *Service) GetRun(ctx context.Context, id int64) (Run, error) {
	r, err := gen.New(s.pool).GetRunView(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, fmt.Errorf("%w: run %d", ErrNotFound, id)
	}
	if err != nil {
		return Run{}, fmt.Errorf("get run %d: %w", id, err)
	}
	return runView(r.Run, r.BatchesTotal, r.BatchesDone, r.BatchesFailed), nil
}

// ListRuns returns runs newest first, optionally of one profile.
func (s *Service) ListRuns(ctx context.Context, profileID *int64, limit, offset int32) ([]Run, int64, error) {
	q := gen.New(s.pool)
	rows, err := q.ListRunViews(ctx, gen.ListRunViewsParams{ProfileID: profileID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, 0, fmt.Errorf("list runs: %w", err)
	}
	total, err := q.CountRuns(ctx, profileID)
	if err != nil {
		return nil, 0, fmt.Errorf("count runs: %w", err)
	}
	out := make([]Run, 0, len(rows))
	for _, r := range rows {
		out = append(out, runView(r.Run, r.BatchesTotal, r.BatchesDone, r.BatchesFailed))
	}
	return out, total, nil
}

// ListBatches returns the batches of a run in order.
func (s *Service) ListBatches(ctx context.Context, runID int64) ([]Batch, error) {
	if _, err := s.GetRun(ctx, runID); err != nil {
		return nil, err
	}
	bs, err := gen.New(s.pool).ListBatches(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list batches of run %d: %w", runID, err)
	}
	out := make([]Batch, 0, len(bs))
	for _, b := range bs {
		out = append(out, Batch{ID: b.ID, RunID: b.RunID, Seq: b.Seq, HostCount: len(b.Ips), HostsUp: b.HostsUp,
			Status: b.Status, Attempts: b.Attempts, StartedAt: b.StartedAt, FinishedAt: b.FinishedAt,
			DurationMs: b.DurationMs, Error: b.Error})
	}
	return out, nil
}

// StartRun builds the profile's scan list, splits it into batches and
// enqueues one job per batch, all in one transaction. A profile has at most
// one pending/running run (ErrConflict). An empty scan list gives a run that
// is done immediately, with the reason in stats.
func (s *Service) StartRun(ctx context.Context, u *auth.User, profileID int64) (Run, error) {
	q := gen.New(s.pool)
	prof, err := q.GetProfile(ctx, profileID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, fmt.Errorf("%w: profile %d does not exist", ErrInvalid, profileID)
	}
	if err != nil {
		return Run{}, fmt.Errorf("get profile %d: %w", profileID, err)
	}
	if _, err := ParsePorts(prof.Ports); err != nil {
		return Run{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !prof.Enabled {
		return Run{}, fmt.Errorf("%w: profile %q is disabled", ErrInvalid, prof.Name)
	}
	// Resolve outside the transaction: DNS can be slow.
	sl, err := (&targets.Store{Pool: s.pool}).ScanList(ctx, profileID, s.cfg.Resolver, targets.Limits{})
	if err != nil {
		return Run{}, fmt.Errorf("scan list of profile %d: %w", profileID, err)
	}

	batches := SplitBatches(sl.IPs, s.cfg.BatchSize)
	stats := lifecycleStats{}.runStats()
	maps.Copy(stats, map[string]any{
		"candidates":   sl.Stats.Candidates,
		"not_included": sl.Stats.NotIncluded,
		"excluded":     sl.Stats.Excluded,
		"rejected":     sl.Stats.Rejected,
		"warnings":     nonNil(sl.Warnings),
		"batch_size":   s.cfg.BatchSize,
	})
	now := time.Now()
	status, finished := "running", (*time.Time)(nil)
	if len(sl.IPs) == 0 {
		status, finished = "done", &now
		stats["reason"] = "empty scan list: no targets in scope for this profile"
	}
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		return Run{}, fmt.Errorf("marshal run stats: %w", err)
	}

	var run gen.Run
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		if _, err := q.LockProfile(ctx, profileID); err != nil {
			return fmt.Errorf("lock profile %d: %w", profileID, err)
		}
		n, err := q.CountActiveRuns(ctx, profileID)
		if err != nil {
			return fmt.Errorf("count active runs: %w", err)
		}
		if n > 0 {
			return fmt.Errorf("%w: profile %q already has a pending or running run", ErrConflict, prof.Name)
		}
		run, err = q.InsertRun(ctx, gen.InsertRunParams{
			ProfileID: profileID, Status: status, CreatedBy: userID(u),
			StartedAt: &now, FinishedAt: finished, HostsTotal: int32(len(sl.IPs)), Stats: statsJSON,
		})
		if err != nil {
			return fmt.Errorf("insert run: %w", err)
		}
		params := make([]river.InsertManyParams, 0, len(batches))
		ids := make([]int64, 0, len(batches))
		for i, ips := range batches {
			id, err := q.InsertBatch(ctx, gen.InsertBatchParams{RunID: run.ID, Seq: int32(i + 1), Ips: ips})
			if err != nil {
				return fmt.Errorf("insert batch %d: %w", i+1, err)
			}
			hn := map[string][]string{}
			for _, ip := range ips {
				if names := sl.Hostnames[ip]; len(names) > 0 {
					hn[ip.String()] = names
				}
			}
			ids = append(ids, id)
			params = append(params, river.InsertManyParams{
				Args:       BatchArgs{BatchID: id, RunID: run.ID, Hostnames: hn},
				InsertOpts: &river.InsertOpts{MaxAttempts: maxAttempts},
			})
		}
		if len(params) > 0 {
			res, err := s.river.InsertManyTx(ctx, tx, params)
			if err != nil {
				return fmt.Errorf("enqueue batches: %w", err)
			}
			for i, r := range res {
				if err := q.SetBatchJob(ctx, gen.SetBatchJobParams{ID: ids[i], JobID: &r.Job.ID}); err != nil {
					return fmt.Errorf("set batch job: %w", err)
				}
			}
		}
		return audit.Log(ctx, q, userID(u), "runs.start", "run", strconv.FormatInt(run.ID, 10),
			map[string]any{"profile_id": profileID, "hosts_total": len(sl.IPs), "batches": len(batches)})
	})
	if err != nil {
		return Run{}, err
	}
	return s.GetRun(ctx, run.ID)
}

// StopRun stops an active run: unfinished batches become 'stopped', the run
// becomes 'stopped', and the batches' River jobs are cancelled (a running
// job's ctx is cancelled, which kills its nmap).
func (s *Service) StopRun(ctx context.Context, u *auth.User, id int64) (Run, error) {
	var jobs []int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		run, err := q.LockRun(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: run %d", ErrNotFound, id)
		}
		if err != nil {
			return fmt.Errorf("lock run %d: %w", id, err)
		}
		if run.Status != "pending" && run.Status != "running" {
			return fmt.Errorf("%w: run %d is %s", ErrConflict, id, run.Status)
		}
		stopped, err := q.StopUnfinishedBatches(ctx, id)
		if err != nil {
			return fmt.Errorf("stop batches of run %d: %w", id, err)
		}
		for _, b := range stopped {
			if b.JobID != nil {
				jobs = append(jobs, *b.JobID)
			}
		}
		if err := finishRun(ctx, q, run.ID, "stopped", map[string]any{"batches_stopped": len(stopped)}); err != nil {
			return err
		}
		return audit.Log(ctx, q, userID(u), "runs.stop", "run", strconv.FormatInt(id, 10),
			map[string]any{"batches_stopped": len(stopped)})
	})
	if err != nil {
		return Run{}, err
	}
	for _, j := range jobs {
		if _, err := s.river.JobCancel(ctx, j); err != nil && !errors.Is(err, rivertype.ErrNotFound) {
			slog.Warn("cancel batch job", "run", id, "job", j, "err", err)
		}
	}
	return s.GetRun(ctx, id)
}

// finishRun writes the final status and the run's summary stats.
func finishRun(ctx context.Context, q *gen.Queries, runID int64, status string, extra map[string]any) error {
	bs, err := q.RunBatchStats(ctx, runID)
	if err != nil {
		return fmt.Errorf("batch stats of run %d: %w", runID, err)
	}
	observations, err := q.RunObservationStats(ctx, runID)
	if err != nil {
		return fmt.Errorf("observation stats of run %d: %w", runID, err)
	}
	stats := map[string]any{
		"batches":         bs.Total,
		"batches_done":    bs.Done,
		"batches_failed":  bs.Failed,
		"batches_stopped": bs.Stopped,
		"duration_ms_sum": bs.DurationMsSum,
		"duration_ms_max": bs.DurationMsMax,
		"services_open":   observations.ServicesOpen,
	}
	for k, v := range extra {
		stats[k] = v
	}
	b, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("marshal run stats: %w", err)
	}
	now := time.Now()
	if err := q.FinishRun(ctx, gen.FinishRunParams{
		ID: runID, Status: status, FinishedAt: &now, HostsUp: int32(observations.HostsUp), Stats: b,
	}); err != nil {
		return fmt.Errorf("finish run %d: %w", runID, err)
	}
	return nil
}
