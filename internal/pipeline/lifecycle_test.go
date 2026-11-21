package pipeline

import (
	"math"
	"testing"
)

func TestNextHostState(t *testing.T) {
	tests := []struct {
		name, state, wantState        string
		misses, threshold, wantMisses int32
		up                            bool
	}{
		{name: "first miss", state: "active", threshold: 3, wantState: "unstable", wantMisses: 1},
		{name: "second miss", state: "unstable", misses: 1, threshold: 3, wantState: "unstable", wantMisses: 2},
		{name: "threshold reached", state: "unstable", misses: 2, threshold: 3, wantState: "inactive", wantMisses: 3},
		{name: "threshold one", state: "active", threshold: 1, wantState: "inactive", wantMisses: 1},
		{name: "still inactive", state: "inactive", misses: 3, threshold: 5, wantState: "inactive", wantMisses: 4},
		{name: "saturated", state: "inactive", misses: math.MaxInt32, threshold: 3, wantState: "inactive", wantMisses: math.MaxInt32},
		{name: "still active", state: "active", threshold: 3, up: true, wantState: "active"},
		{name: "unstable recovery", state: "unstable", misses: 2, threshold: 3, up: true, wantState: "active"},
		{name: "inactive recovery", state: "inactive", misses: 3, threshold: 3, up: true, wantState: "active"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, misses := nextHostState(tt.state, tt.misses, tt.threshold, tt.up)
			if state != tt.wantState || misses != tt.wantMisses {
				t.Errorf("state and misses = %s/%d, want %s/%d", state, misses, tt.wantState, tt.wantMisses)
			}
		})
	}
}
