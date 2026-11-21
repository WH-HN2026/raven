package pipeline

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/targets"
)

func TestPlanBatchSize(t *testing.T) {
	tests := []struct {
		name          string
		targetSeconds int
		samples       []BatchSample
		wantSize      int
		wantSource    string
		wantSamples   int
	}{
		{
			name:          "no history uses default",
			targetSeconds: 600,
			samples:       nil,
			wantSize:      DefaultBatchSize,
			wantSource:    "default",
			wantSamples:   0,
		},
		{
			name:          "empty slice uses default",
			targetSeconds: 60,
			samples:       []BatchSample{},
			wantSize:      DefaultBatchSize,
			wantSource:    "default",
			wantSamples:   0,
		},
		{
			name:          "only zero or negative samples fall back to default",
			targetSeconds: 60,
			samples: []BatchSample{
				{HostCount: 0, DurationMs: 1000},
				{HostCount: 50, DurationMs: 0},
				{HostCount: 50, DurationMs: -100},
			},
			wantSize:    DefaultBatchSize,
			wantSource:  "default",
			wantSamples: 0,
		},
		{
			name:          "steady history sizes to target",
			targetSeconds: 10,
			samples: []BatchSample{
				{HostCount: 100, DurationMs: 5000}, // 0.05 s/IP => 20 hosts/s => 200
			},
			wantSize:    200,
			wantSource:  "adaptive",
			wantSamples: 1,
		},
		{
			name:          "fast history clamps to MaxBatchSize",
			targetSeconds: 600,
			samples: []BatchSample{
				{HostCount: 200, DurationMs: 1000}, // 200 hosts/s * 600s = 120000
			},
			wantSize:    MaxBatchSize,
			wantSource:  "adaptive",
			wantSamples: 1,
		},
		{
			name:          "slow history clamps to MinBatchSize",
			targetSeconds: 30,
			samples: []BatchSample{
				{HostCount: 10, DurationMs: 100000}, // 10 s/IP => raw 3
			},
			wantSize:    MinBatchSize,
			wantSource:  "adaptive",
			wantSamples: 1,
		},
		{
			name:          "exact min boundary",
			targetSeconds: 80,
			samples: []BatchSample{
				{HostCount: 10, DurationMs: 100000}, // 10 s/IP => raw 8
			},
			wantSize:    MinBatchSize,
			wantSource:  "adaptive",
			wantSamples: 1,
		},
		{
			name:          "exact max boundary",
			targetSeconds: 4096,
			samples: []BatchSample{
				{HostCount: 100, DurationMs: 100000}, // 1 s/IP => raw 4096
			},
			wantSize:    MaxBatchSize,
			wantSource:  "adaptive",
			wantSamples: 1,
		},
		{
			name:          "host-count weighting resists small slow remainder batch",
			targetSeconds: 100,
			samples: []BatchSample{
				{HostCount: 10, DurationMs: 5000},   // newest remainder: 0.5 s/IP (weight 1.0)
				{HostCount: 200, DurationMs: 20000}, // main batch: 0.1 s/IP (weight 0.85)
			},
			// weightedSec = 5 + 0.85*20 = 22.0; weightedHosts = 10 + 0.85*200 = 180
			// secPerIP = 22/180 = 0.1222...; 100 / (22/180) = 818.18 -> 818
			wantSize:    818,
			wantSource:  "adaptive",
			wantSamples: 2,
		},
		{
			name:          "recency decay shifts toward newer throughput",
			targetSeconds: 100,
			samples: []BatchSample{
				{HostCount: 100, DurationMs: 20000}, // newest: 0.2 s/IP
				{HostCount: 100, DurationMs: 20000},
				{HostCount: 100, DurationMs: 5000}, // older: 0.05 s/IP
				{HostCount: 100, DurationMs: 5000},
			},
			// w = 1, 0.85, 0.7225, 0.614125; sumW = 3.186625
			// weightedSec = 100*(0.2*(1+0.85) + 0.05*(0.7225+0.614125)) = 43.683125
			// weightedHosts = 318.6625; secPerIP = 0.1370827...; 100/secPerIP = 729.48 -> 729
			wantSize:    729,
			wantSource:  "adaptive",
			wantSamples: 4,
		},
		{
			name:          "non-positive target falls back to DefaultTargetBatchSeconds",
			targetSeconds: 0,
			samples: []BatchSample{
				{HostCount: 100, DurationMs: 200000}, // 2 s/IP => 600 / 2 = 300
			},
			wantSize:    300,
			wantSource:  "adaptive",
			wantSamples: 1,
		},
		{
			name:          "skips invalid samples mixed with valid ones",
			targetSeconds: 10,
			samples: []BatchSample{
				{HostCount: 0, DurationMs: 500},
				{HostCount: 50, DurationMs: 2500}, // 0.05 s/IP => 200
				{HostCount: 50, DurationMs: 0},
			},
			wantSize:    200,
			wantSource:  "adaptive",
			wantSamples: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PlanBatchSize(tt.targetSeconds, tt.samples)
			if got.Size != tt.wantSize {
				t.Errorf("Size = %d, want %d (plan=%+v)", got.Size, tt.wantSize, got)
			}
			if got.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tt.wantSource)
			}
			if got.Samples != tt.wantSamples {
				t.Errorf("Samples = %d, want %d", got.Samples, tt.wantSamples)
			}
			if tt.wantSamples == 0 && got.SecPerIP != 0 {
				t.Errorf("SecPerIP = %v, want 0", got.SecPerIP)
			}
			if tt.wantSamples > 0 && (got.SecPerIP <= 0 || math.IsNaN(got.SecPerIP) || math.IsInf(got.SecPerIP, 0)) {
				t.Errorf("SecPerIP = %v, want finite positive", got.SecPerIP)
			}
		})
	}
}

func TestPerWorkerRate(t *testing.T) {
	tests := []struct {
		name        string
		profileRate int
		workers     int
		want        int
	}{
		{name: "single worker keeps full rate", profileRate: 300, workers: 1, want: 300},
		{name: "non-positive workers keeps full rate", profileRate: 300, workers: 0, want: 300},
		{name: "two workers split evenly", profileRate: 300, workers: 2, want: 150},
		{name: "two workers nuclei rate", profileRate: 50, workers: 2, want: 25},
		{name: "three workers rounds down so aggregate <= profile", profileRate: 50, workers: 3, want: 16},
		{name: "small positive rate floors at 1", profileRate: 1, workers: 4, want: 1},
		{name: "zero profile rate stays 0", profileRate: 0, workers: 2, want: 0},
		{name: "negative profile rate stays 0", profileRate: -5, workers: 2, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PerWorkerRate(tt.profileRate, tt.workers); got != tt.want {
				t.Fatalf("PerWorkerRate(%d, %d) = %d, want %d", tt.profileRate, tt.workers, got, tt.want)
			}
		})
	}
}

// TestPlanSlash8 plans a run over a full /8 (2^24 IPs) the way StartRun
// does, without a DB or any scan, and logs the cost of the plan.
func TestPlanSlash8(t *testing.T) {
	if testing.Short() {
		t.Skip("expands 2^24 addresses")
	}
	start := time.Now()
	sl, err := targets.Expand(context.Background(), []targets.Entry{{Kind: targets.KindCIDR, Value: "10.0.0.0/8"}},
		targets.Scope{}, nil, targets.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	expanded := time.Since(start)
	for _, tc := range []struct {
		name    string
		plan    BatchPlan
		batches int
	}{
		{"default size", PlanBatchSize(0, nil), 1 << 24 / DefaultBatchSize},
		{"max size", BatchPlan{Size: MaxBatchSize}, 1 << 24 / MaxBatchSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			batches := SplitBatches(sl.IPs, tc.plan.Size)
			stats, err := json.Marshal(tc.plan.statsMap(batches, gen.Profile{}, 2))
			if err != nil {
				t.Fatal(err)
			}
			if len(batches) != tc.batches || len(batches[0]) != tc.plan.Size || batches[len(batches)-1][tc.plan.Size-1].String() != "10.255.255.255" {
				t.Fatalf("%d batches, want %d of %d", len(batches), tc.batches, tc.plan.Size)
			}
			t.Logf("/8: expand %v; %d batches of %d planned in %v; run stats JSON %d KiB",
				expanded, len(batches), tc.plan.Size, time.Since(start), len(stats)>>10)
		})
	}
}
