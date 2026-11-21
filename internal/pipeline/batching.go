package pipeline

import (
	"context"
	"fmt"
	"math"
	"net/netip"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

const (
	// DefaultBatchSize is the starting batch size for a profile with no
	// finished batch history yet. It is small enough to run workers in
	// parallel and checkpoint early on an unknown network while large enough
	// to amortize per-batch scanner startup cost.
	DefaultBatchSize = BatchSize // 256

	// MinBatchSize and MaxBatchSize clamp adaptive batch sizes.
	// MinBatchSize=8 avoids per-host process overhead while still letting
	// dense or short-target scans (including the local lab) split across
	// batches; MaxBatchSize=4096 bounds checkpoint and cancellation granularity
	// (architecture §3.2).
	MinBatchSize = 8
	MaxBatchSize = 4096

	// DefaultTargetBatchSeconds is a defensive fallback if a profile row has a
	// non-positive target_batch_seconds.
	DefaultTargetBatchSeconds = 600

	// BatchHistoryLimit is the number of most-recent finished batches of a
	// profile used to estimate per-IP scan duration.
	BatchHistoryLimit = 20

	// batchHistoryDecay weights newer finished batches higher than older ones
	// (weight_i = decay^i, newest first) so changes in profile ports, rate
	// limits, or network latency converge within a few runs.
	batchHistoryDecay = 0.85
)

// BatchSample is one finished batch's measured IP count and wall duration.
type BatchSample struct {
	HostCount  int
	DurationMs int64
}

// BatchPlan describes the batch size chosen for a run and how it was derived.
type BatchPlan struct {
	Size     int     // target IPs per batch
	Source   string  // "fixed", "default", or "adaptive"
	SecPerIP float64 // weighted seconds per IP from history (0 when no samples)
	Samples  int     // number of valid historical batches used
}

// PlanBatchSize computes the target batch size for a run targeting
// targetSeconds per batch from recent finished batches (newest first).
//
// Design (S5): batches are sized and created upfront in StartRun from the
// profile's completed batch history (status = 'done', duration_ms > 0).
// Planning in StartRun avoids mutating queued River jobs and keeps StopRun,
// retries, batches_total progress, and P1 suspend/resume intact.
//
// Throughput is estimated as a recency- and host-count-weighted average of
// seconds per IP:
//
//	sec_per_ip = sum(decay^i * duration_s_i) / sum(decay^i * host_count_i)
//
// Host-count weighting keeps small remainder batches from skewing the estimate,
// while exponential recency decay lets throughput changes converge across runs.
// The resulting size = round(targetSeconds / sec_per_ip) is clamped to
// [MinBatchSize, MaxBatchSize]. When no valid samples exist, DefaultBatchSize
// is used (clamped to [MinBatchSize, MaxBatchSize]).
func PlanBatchSize(targetSeconds int, samples []BatchSample) BatchPlan {
	if targetSeconds <= 0 {
		targetSeconds = DefaultTargetBatchSeconds
	}
	var weightedSec, weightedHosts float64
	weight := 1.0
	used := 0
	for _, s := range samples {
		if s.HostCount <= 0 || s.DurationMs <= 0 {
			continue
		}
		weightedSec += weight * (float64(s.DurationMs) / 1000.0)
		weightedHosts += weight * float64(s.HostCount)
		weight *= batchHistoryDecay
		used++
	}
	if used == 0 || weightedSec <= 0 || weightedHosts <= 0 {
		return BatchPlan{
			Size:   clampBatchSize(DefaultBatchSize),
			Source: "default",
		}
	}
	secPerIP := weightedSec / weightedHosts
	size := clampFloatBatchSize(float64(targetSeconds) / secPerIP)
	return BatchPlan{
		Size:     size,
		Source:   "adaptive",
		SecPerIP: secPerIP,
		Samples:  used,
	}
}

func clampBatchSize(n int) int {
	if n < MinBatchSize {
		return MinBatchSize
	}
	if n > MaxBatchSize {
		return MaxBatchSize
	}
	return n
}

func clampFloatBatchSize(raw float64) int {
	if math.IsNaN(raw) || raw <= float64(MinBatchSize) {
		return MinBatchSize
	}
	if math.IsInf(raw, 1) || raw >= float64(MaxBatchSize) {
		return MaxBatchSize
	}
	return clampBatchSize(int(math.Round(raw)))
}

// PerWorkerRate splits a profile's configured rate limit evenly across the
// global concurrency cap so aggregate scanner traffic across all concurrent
// batch workers stays bounded by the profile's rate limit.
//
// When profileRate > 0, the per-worker rate is floored at 1 because nmap,
// httpx, and nuclei require a positive rate. A non-positive profileRate
// returns 0 so scanner validation rejects it.
func PerWorkerRate(profileRate, workers int) int {
	if profileRate <= 0 {
		return 0
	}
	if workers <= 1 {
		return profileRate
	}
	return max(1, profileRate/workers)
}

func (s *Service) nmapRate(prof gen.Profile) int {
	return PerWorkerRate(int(prof.NmapMaxRate), s.cfg.Workers)
}

func (s *Service) webRate(prof gen.Profile) int {
	return PerWorkerRate(int(prof.NucleiRate), s.cfg.Workers)
}

// planRunBatches picks the batch size for a new run of prof and splits ips.
// If cfg.BatchSize > 0, that fixed size is used (e.g. deterministic tests);
// otherwise the size is computed from the profile's recent finished batches.
func (s *Service) planRunBatches(ctx context.Context, prof gen.Profile, ips []netip.Addr) (BatchPlan, [][]netip.Addr, error) {
	if s.cfg.BatchSize > 0 {
		plan := BatchPlan{Size: s.cfg.BatchSize, Source: "fixed"}
		return plan, SplitBatches(ips, plan.Size), nil
	}
	rows, err := gen.New(s.pool).ListProfileBatchSamples(ctx, gen.ListProfileBatchSamplesParams{
		ProfileID: prof.ID,
		Limit:     BatchHistoryLimit,
	})
	if err != nil {
		return BatchPlan{}, nil, fmt.Errorf("batch history of profile %d: %w", prof.ID, err)
	}
	samples := make([]BatchSample, 0, len(rows))
	for _, r := range rows {
		if r.DurationMs == nil {
			continue
		}
		samples = append(samples, BatchSample{
			HostCount:  int(r.HostCount),
			DurationMs: *r.DurationMs,
		})
	}
	plan := PlanBatchSize(int(prof.TargetBatchSeconds), samples)
	return plan, SplitBatches(ips, plan.Size), nil
}

func batchSizes(batches [][]netip.Addr) []int {
	out := make([]int, len(batches))
	for i, b := range batches {
		out[i] = len(b)
	}
	return out
}

func (p BatchPlan) statsMap(batches [][]netip.Addr, prof gen.Profile, workers int) map[string]any {
	m := map[string]any{
		"batch_size":              p.Size,
		"batch_sizes":             batchSizes(batches),
		"batch_sizing":            p.Source,
		"target_batch_seconds":    prof.TargetBatchSeconds,
		"batch_history_samples":   p.Samples,
		"max_workers":             workers,
		"effective_nmap_max_rate": PerWorkerRate(int(prof.NmapMaxRate), workers),
		"effective_nuclei_rate":   PerWorkerRate(int(prof.NucleiRate), workers),
	}
	if p.Samples > 0 {
		m["measured_sec_per_ip"] = math.Round(p.SecPerIP*1e6) / 1e6
	}
	return m
}
