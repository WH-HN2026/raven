package pipeline

import (
	"fmt"
	"slices"
	"sync"
)

// Stage names (architecture §3.11).
const (
	StageNmap         = "nmap"
	StageHTTPX        = "httpx"
	StageNuclei       = "nuclei"
	StageNucleiActive = "nuclei_active"
	StageNikto        = "nikto"
	StageWPScan       = "wpscan"
	StageZAP          = "zap"
)

// StageDef describes one workflow stage in the registry (architecture §3.11).
type StageDef struct {
	Name       string   `json:"name"`
	Needs      []string `json:"needs"`
	Aggressive bool     `json:"aggressive"`
	Available  bool     `json:"available"`
}

// StagePresets holds the named workflow presets (architecture §3.11).
type StagePresets struct {
	Default    []string `json:"default"`
	Aggressive []string `json:"aggressive"`
}

// stageRegistry is the canonical stage order and dependency graph.
// Aggressive stages remain Available: false until implemented and gated (AG1–AG5).
var stageRegistry = []StageDef{
	{Name: StageNmap, Needs: []string{}, Aggressive: false, Available: true},
	{Name: StageHTTPX, Needs: []string{StageNmap}, Aggressive: false, Available: true},
	{Name: StageNuclei, Needs: []string{StageHTTPX}, Aggressive: false, Available: true},
	{Name: StageNucleiActive, Needs: []string{StageHTTPX}, Aggressive: true, Available: true},
	{Name: StageNikto, Needs: []string{StageHTTPX}, Aggressive: true, Available: false},
	{Name: StageWPScan, Needs: []string{StageHTTPX}, Aggressive: true, Available: true},
	{Name: StageZAP, Needs: []string{StageHTTPX}, Aggressive: true, Available: false},
}

var stageMu sync.RWMutex

var stageByName = func() map[string]StageDef {
	m := make(map[string]StageDef, len(stageRegistry))
	for _, s := range stageRegistry {
		m[s.Name] = s
	}
	return m
}()

// testingTB is the subset of testing.TB needed by WithStageAvailable so this
// package does not pull testing's flags into production binaries.
type testingTB interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...any)
}

// SetStageAvailable updates a stage's runtime availability (e.g. ZAP when
// RAVEN_ZAP_URL is configured). Unknown stage names are ignored.
func SetStageAvailable(name string, available bool) {
	stageMu.Lock()
	defer stageMu.Unlock()
	def, ok := stageByName[name]
	if !ok {
		return
	}
	def.Available = available
	stageByName[name] = def
	for i := range stageRegistry {
		if stageRegistry[i].Name == name {
			stageRegistry[i].Available = available
			break
		}
	}
}

// WithStageAvailable marks the named stages as Available for the duration of a
// test and restores their prior availability in t.Cleanup.
// Test helper only; production stage availability is defined in stageRegistry.
func WithStageAvailable(t testingTB, names ...string) {
	t.Helper()
	stageMu.Lock()
	prior := make(map[string]bool, len(names))
	for _, name := range names {
		def, ok := stageByName[name]
		if !ok {
			stageMu.Unlock()
			t.Fatalf("pipeline.WithStageAvailable: unknown stage %q", name)
			return
		}
		if _, saved := prior[name]; !saved {
			prior[name] = def.Available
		}
		def.Available = true
		stageByName[name] = def
		for i := range stageRegistry {
			if stageRegistry[i].Name == name {
				stageRegistry[i].Available = true
				break
			}
		}
	}
	stageMu.Unlock()
	t.Cleanup(func() {
		stageMu.Lock()
		defer stageMu.Unlock()
		for name, prev := range prior {
			def := stageByName[name]
			def.Available = prev
			stageByName[name] = def
			for i := range stageRegistry {
				if stageRegistry[i].Name == name {
					stageRegistry[i].Available = prev
					break
				}
			}
		}
	})
}

// Stages returns a copy of the ordered stage registry.
func Stages() []StageDef {
	stageMu.RLock()
	defer stageMu.RUnlock()
	out := make([]StageDef, len(stageRegistry))
	for i, s := range stageRegistry {
		s.Needs = slices.Clone(s.Needs)
		out[i] = s
	}
	return out
}

// DefaultStages returns the Default workflow preset in registry order.
func DefaultStages() []string {
	return []string{StageNmap, StageHTTPX, StageNuclei}
}

// AggressiveStages returns the Aggressive workflow preset in registry order.
func AggressiveStages() []string {
	return []string{StageNmap, StageHTTPX, StageNuclei, StageNucleiActive, StageNikto, StageWPScan, StageZAP}
}

// Presets returns the named workflow presets.
func Presets() StagePresets {
	return StagePresets{
		Default:    DefaultStages(),
		Aggressive: AggressiveStages(),
	}
}

// Validate checks a stage set against the registry:
//   - no unknown or duplicate stages;
//   - every stage must be Available (aggressive stages are rejected until AG1–AG5);
//   - nmap is required;
//   - every stage's Needs must also be enabled.
//
// On success it returns the stages normalised to registry order.
func Validate(stages []string) ([]string, error) {
	stageMu.RLock()
	defer stageMu.RUnlock()
	seen := make(map[string]bool, len(stages))
	for _, name := range stages {
		def, ok := stageByName[name]
		if !ok {
			return nil, fmt.Errorf("unknown stage %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate stage %q", name)
		}
		if !def.Available {
			return nil, fmt.Errorf("stage %s is not available", name)
		}
		seen[name] = true
	}
	if !seen[StageNmap] {
		return nil, fmt.Errorf("stage %s is required", StageNmap)
	}
	out := make([]string, 0, len(seen))
	for _, def := range stageRegistry {
		if !seen[def.Name] {
			continue
		}
		for _, need := range def.Needs {
			if !seen[need] {
				return nil, fmt.Errorf("stage %s requires %s", def.Name, need)
			}
		}
		out = append(out, def.Name)
	}
	return out, nil
}

// EffectiveStages returns stages if non-empty, or DefaultStages for legacy rows
// where runs.stages is NULL.
func EffectiveStages(stages []string) []string {
	if len(stages) == 0 {
		return DefaultStages()
	}
	return slices.Clone(stages)
}

// HasStage reports whether name is present in stages.
func HasStage(stages []string, name string) bool {
	return slices.Contains(stages, name)
}

// SharedStages returns the stages present in both runs (NULL/empty = Default),
// in registry order.
func SharedStages(a, b []string) []string {
	ea := EffectiveStages(a)
	eb := EffectiveStages(b)
	out := make([]string, 0, len(stageRegistry))
	for _, def := range stageRegistry {
		if slices.Contains(ea, def.Name) && slices.Contains(eb, def.Name) {
			out = append(out, def.Name)
		}
	}
	return out
}

// IsAggressive reports whether any stage in stages is marked Aggressive.
func IsAggressive(stages []string) bool {
	stageMu.RLock()
	defer stageMu.RUnlock()
	for _, name := range stages {
		if def, ok := stageByName[name]; ok && def.Aggressive {
			return true
		}
	}
	return false
}
