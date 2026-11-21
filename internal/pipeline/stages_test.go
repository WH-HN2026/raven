package pipeline

import (
	"slices"
	"strings"
	"testing"
)

func TestValidateStages(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []string
		wantErr string
	}{
		{
			name: "default preset",
			in:   DefaultStages(),
			want: []string{StageNmap, StageHTTPX, StageNuclei},
		},
		{
			name: "nmap only",
			in:   []string{StageNmap},
			want: []string{StageNmap},
		},
		{
			name: "nmap and httpx",
			in:   []string{StageNmap, StageHTTPX},
			want: []string{StageNmap, StageHTTPX},
		},
		{
			name: "normalises to registry order",
			in:   []string{StageNuclei, StageHTTPX, StageNmap},
			want: []string{StageNmap, StageHTTPX, StageNuclei},
		},
		{
			name:    "nuclei without httpx",
			in:      []string{StageNmap, StageNuclei},
			wantErr: "stage nuclei requires httpx",
		},
		{
			name:    "httpx without nmap",
			in:      []string{StageHTTPX},
			wantErr: "stage nmap is required",
		},
		{
			name:    "empty",
			in:      []string{},
			wantErr: "stage nmap is required",
		},
		{
			name:    "unknown stage",
			in:      []string{StageNmap, "masscan"},
			wantErr: `unknown stage "masscan"`,
		},
		{
			name:    "duplicate stage",
			in:      []string{StageNmap, StageHTTPX, StageNmap},
			wantErr: `duplicate stage "nmap"`,
		},
		{
			name:    "aggressive nuclei_active rejected as unavailable",
			in:      []string{StageNmap, StageHTTPX, StageNucleiActive},
			wantErr: "stage nuclei_active is not available",
		},
		{
			name:    "aggressive nikto rejected as unavailable",
			in:      []string{StageNmap, StageHTTPX, StageNikto},
			wantErr: "stage nikto is not available",
		},
		{
			name:    "aggressive wpscan rejected as unavailable",
			in:      []string{StageNmap, StageHTTPX, StageWPScan},
			wantErr: "stage wpscan is not available",
		},
		{
			name:    "aggressive zap rejected as unavailable",
			in:      []string{StageNmap, StageHTTPX, StageZAP},
			wantErr: "stage zap is not available",
		},
		{
			name:    "aggressive preset rejected as unavailable",
			in:      AggressiveStages(),
			wantErr: "is not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Validate(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Validate(%v) = %v, nil; want error containing %q", tt.in, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Validate(%v) error = %q, want substring %q", tt.in, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%v) unexpected error: %v", tt.in, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("Validate(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestStageRegistryAndHelpers(t *testing.T) {
	defs := Stages()
	var names []string
	for _, d := range defs {
		names = append(names, d.Name)
	}
	wantOrder := []string{StageNmap, StageHTTPX, StageNuclei, StageNucleiActive, StageNikto, StageWPScan, StageZAP}
	if !slices.Equal(names, wantOrder) {
		t.Fatalf("registry order = %v, want %v", names, wantOrder)
	}
	if !slices.Equal(EffectiveStages(nil), DefaultStages()) {
		t.Fatalf("EffectiveStages(nil) = %v", EffectiveStages(nil))
	}
	if !slices.Equal(EffectiveStages([]string{StageNmap}), []string{StageNmap}) {
		t.Fatalf("EffectiveStages([nmap]) = %v", EffectiveStages([]string{StageNmap}))
	}
	if got := SharedStages(nil, []string{StageNmap}); !slices.Equal(got, []string{StageNmap}) {
		t.Fatalf("SharedStages(nil, [nmap]) = %v", got)
	}
	if got := SharedStages([]string{StageNmap, StageHTTPX, StageNuclei}, []string{StageNmap, StageHTTPX}); !slices.Equal(got, []string{StageNmap, StageHTTPX}) {
		t.Fatalf("SharedStages(default, nmap+httpx) = %v", got)
	}
	if IsAggressive(DefaultStages()) {
		t.Fatal("DefaultStages should not be aggressive")
	}
	if !IsAggressive(AggressiveStages()) {
		t.Fatal("AggressiveStages should be aggressive")
	}
}

func TestWithStageAvailable(t *testing.T) {
	// Production default: nikto is unavailable.
	if _, err := Validate([]string{StageNmap, StageHTTPX, StageNikto}); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("expected nikto unavailable by default, got err=%v", err)
	}

	t.Run("enabled inside subtest", func(t *testing.T) {
		WithStageAvailable(t, StageNikto)
		got, err := Validate([]string{StageNikto, StageHTTPX, StageNmap})
		if err != nil {
			t.Fatalf("Validate with nikto available: %v", err)
		}
		if !slices.Equal(got, []string{StageNmap, StageHTTPX, StageNikto}) {
			t.Fatalf("got %v, want [nmap httpx nikto]", got)
		}
		// Dependency checks still apply.
		if _, err := Validate([]string{StageNmap, StageNikto}); err == nil || !strings.Contains(err.Error(), "requires httpx") {
			t.Fatalf("expected missing dependency error, got %v", err)
		}
		// Other aggressive stages remain unavailable.
		if _, err := Validate([]string{StageNmap, StageHTTPX, StageZAP}); err == nil || !strings.Contains(err.Error(), "not available") {
			t.Fatalf("expected zap still unavailable, got %v", err)
		}
	})

	// Cleanup restored production availability.
	if _, err := Validate([]string{StageNmap, StageHTTPX, StageNikto}); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("expected nikto restored to unavailable after cleanup, got err=%v", err)
	}
}
