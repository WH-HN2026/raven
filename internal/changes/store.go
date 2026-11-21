package changes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

var (
	ErrRunNotFound = errors.New("run not found")
	ErrNoRuns      = errors.New("not enough finished runs to compare")
	ErrSameRun     = errors.New("from and to are the same run")
	ErrRunOrder    = errors.New("from must be older than to")
)

// RunRef identifies a compared run.
type RunRef struct {
	ID         int64      `json:"id"`
	ProfileID  int64      `json:"profile_id"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Stages     []string   `json:"stages,omitempty"`
}

// Summary has the full counts, also when the lists are capped.
type Summary struct {
	HostsNew        int `json:"hosts_new"`
	HostsGone       int `json:"hosts_gone"`
	ServicesNew     int `json:"services_new"`
	ServicesGone    int `json:"services_gone"`
	ServicesChanged int `json:"services_changed"`
}

// Changes is the API view of a diff (GET /api/changes).
type Changes struct {
	From            RunRef          `json:"from"`
	To              RunRef          `json:"to"`
	Summary         Summary         `json:"summary"`
	HostsNew        []HostChange    `json:"hosts_new"`
	HostsGone       []HostChange    `json:"hosts_gone"`
	ServicesNew     []ServiceChange `json:"services_new"`
	ServicesGone    []ServiceChange `json:"services_gone"`
	ServicesChanged []ServiceChange `json:"services_changed"`
	Truncated       bool            `json:"truncated"` // some list has more than limit items
}

// Compare diffs two runs. A nil to means the latest finished run (of
// from's profile if from is given); a nil from means the finished run of
// to's profile right before to. limit caps each list.
func Compare(ctx context.Context, q *gen.Queries, from, to *int64, limit int) (*Changes, error) {
	return CompareSorted(ctx, q, from, to, limit, db.ListOrder{})
}

// CompareSorted orders each category before applying its limit.
func CompareSorted(ctx context.Context, q *gen.Queries, from, to *int64, limit int, order db.ListOrder) (*Changes, error) {
	f, t, err := resolve(ctx, q, from, to)
	if err != nil {
		return nil, err
	}
	shared := pipeline.SharedStages(f.Stages, t.Stages)
	a, err := loadSnapshot(ctx, q, f.ID, f.Stages, shared)
	if err != nil {
		return nil, err
	}
	b, err := loadSnapshot(ctx, q, t.ID, t.Stages, shared)
	if err != nil {
		return nil, err
	}
	r := Diff(a, b)
	r.orderLists(order)
	c := &Changes{
		From: f, To: t,
		Summary: Summary{
			HostsNew: len(r.HostsNew), HostsGone: len(r.HostsGone), ServicesNew: len(r.ServicesNew),
			ServicesGone: len(r.ServicesGone), ServicesChanged: len(r.ServicesChanged),
		},
	}
	c.HostsNew = capList(r.HostsNew, limit, &c.Truncated)
	c.HostsGone = capList(r.HostsGone, limit, &c.Truncated)
	c.ServicesNew = capList(r.ServicesNew, limit, &c.Truncated)
	c.ServicesGone = capList(r.ServicesGone, limit, &c.Truncated)
	c.ServicesChanged = capList(r.ServicesChanged, limit, &c.Truncated)
	return c, nil
}

func capList[T any](s []T, limit int, truncated *bool) []T {
	if len(s) > limit {
		*truncated = true
		return s[:limit]
	}
	return s
}

func resolve(ctx context.Context, q *gen.Queries, from, to *int64) (RunRef, RunRef, error) {
	var f, t RunRef
	var err error
	if from != nil {
		if f, err = getRun(ctx, q, *from); err != nil {
			return f, t, err
		}
	}
	switch {
	case to != nil:
		t, err = getRun(ctx, q, *to)
	case from != nil:
		t, err = one(q.LatestDoneRun(ctx, &f.ProfileID))
		if err == nil && !f.before(t) {
			err = ErrNoRuns
		}
	default:
		t, err = one(q.LatestDoneRun(ctx, nil))
	}
	if err != nil {
		return f, t, err
	}
	if from == nil {
		if f, err = one(q.PreviousDoneRun(ctx, gen.PreviousDoneRunParams{ProfileID: t.ProfileID, BeforeID: t.ID})); err != nil {
			return f, t, err
		}
	}
	if f.ID == t.ID {
		return f, t, ErrSameRun
	}
	if !f.before(t) {
		return f, t, ErrRunOrder
	}
	return f, t, nil
}

// before orders missing start times first and uses ID to break ties, like the SQL defaults.
func (r RunRef) before(other RunRef) bool {
	switch {
	case r.StartedAt == nil && other.StartedAt != nil:
		return true
	case r.StartedAt != nil && other.StartedAt == nil:
		return false
	case r.StartedAt != nil && !r.StartedAt.Equal(*other.StartedAt):
		return r.StartedAt.Before(*other.StartedAt)
	default:
		return r.ID < other.ID
	}
}

func getRun(ctx context.Context, q *gen.Queries, id int64) (RunRef, error) {
	r, err := q.GetChangeRun(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return RunRef{}, fmt.Errorf("run %d: %w", id, ErrRunNotFound)
	}
	if err != nil {
		return RunRef{}, fmt.Errorf("get run %d: %w", id, err)
	}
	ref := RunRef(r)
	ref.Stages = pipeline.EffectiveStages(ref.Stages)
	return ref, nil
}

// one converts a LatestDoneRun / PreviousDoneRun result.
func one[T gen.LatestDoneRunRow | gen.PreviousDoneRunRow](r T, err error) (RunRef, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return RunRef{}, ErrNoRuns
	}
	if err != nil {
		return RunRef{}, fmt.Errorf("find run: %w", err)
	}
	ref := RunRef(r)
	ref.Stages = pipeline.EffectiveStages(ref.Stages)
	return ref, nil
}

// LoadSnapshot reads one run's state (see the package doc for the sources).
// When run_observations carries service_fp (written by pipeline.Ingest), it
// skips decrypting and XML-parsing the run's nmap artifacts; otherwise it
// falls back to parsing artifacts for legacy/seeded runs.
func LoadSnapshot(ctx context.Context, q *gen.Queries, runID int64) (Snapshot, error) {
	return loadSnapshot(ctx, q, runID, nil, pipeline.DefaultStages())
}

func loadSnapshot(ctx context.Context, q *gen.Queries, runID int64, runStages, shared []string) (Snapshot, error) {
	rows, err := q.ListRunObservations(ctx, runID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("run %d observations: %w", runID, err)
	}
	obs := make([]ObsRow, len(rows))
	missingFP := false
	for i, r := range rows {
		row := ObsRow{IP: r.Ip, Port: r.Port, Up: r.Up}
		if r.Port >= 0 && r.Up {
			if len(r.ServiceFp) > 0 {
				var fp ServiceFP
				if err := json.Unmarshal(r.ServiceFp, &fp); err == nil {
					row.FP = &fp
				} else {
					missingFP = true
				}
			} else {
				missingFP = true
			}
		}
		obs[i] = row
	}
	var nmapObs []scanner.Observation
	if missingFP {
		arts, err := q.ListRunNmapArtifacts(ctx, runID)
		if err != nil {
			return Snapshot{}, fmt.Errorf("run %d artifacts: %w", runID, err)
		}
		for _, a := range arts {
			res, err := nmap.Parse([]byte(a))
			if err != nil { // a broken artifact only loses fingerprints, not the diff
				slog.Warn("changes: skip unparsable nmap artifact", "run", runID, "err", err)
				continue
			}
			nmapObs = append(nmapObs, res.Observations...)
		}
	}
	effStages := pipeline.EffectiveStages(runStages)
	var http []HTTPRow
	if pipeline.HasStage(shared, pipeline.StageHTTPX) {
		hrows, err := q.ListRunHTTPObservations(ctx, &runID)
		if err != nil {
			return Snapshot{}, fmt.Errorf("run %d http observations: %w", runID, err)
		}
		var excludeTech map[SvcKey]map[string]bool
		if !pipeline.HasStage(shared, pipeline.StageNuclei) && pipeline.HasStage(effStages, pipeline.StageNuclei) {
			excludeTech, err = loadNucleiTechExclusions(ctx, q, runID)
			if err != nil {
				return Snapshot{}, err
			}
		}
		http = make([]HTTPRow, len(hrows))
		for i, h := range hrows {
			techs := h.Technologies
			if excl := excludeTech[SvcKey{h.Ip.Unmap(), uint16(h.Port)}]; len(excl) > 0 {
				filtered := make([]string, 0, len(techs))
				for _, t := range techs {
					if !excl[t] {
						filtered = append(filtered, t)
					}
				}
				techs = filtered
			}
			http[i] = HTTPRow{IP: h.Ip, Port: uint16(h.Port), Title: h.Title, Technologies: techs}
		}
	}
	s := BuildSnapshot(obs, nmapObs, http)
	s.Stages = effStages
	return s, nil
}

func loadNucleiTechExclusions(ctx context.Context, q *gen.Queries, runID int64) (map[SvcKey]map[string]bool, error) {
	rows, err := q.ListRunNucleiMatches(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("run %d nuclei matches: %w", runID, err)
	}
	out := make(map[SvcKey]map[string]bool)
	for _, r := range rows {
		var matches []struct {
			Kind    string `json:"kind"`
			Name    string `json:"name"`
			Matcher string `json:"matcher"`
			Tech    string `json:"tech"`
			CPE     string `json:"cpe"`
		}
		if err := json.Unmarshal(r.NucleiMatches, &matches); err != nil {
			continue
		}
		key := SvcKey{r.Ip.Unmap(), uint16(r.Port)}
		for _, m := range matches {
			if m.Kind != string(scanner.ObsTech) {
				continue
			}
			tech := m.Tech
			if tech == "" {
				// Backwards compatibility for runs recorded before nucleiMatch.Tech existed.
				if _, prod, ok := cutCPE(m.CPE); ok {
					tech = prod
				} else if m.Matcher != "" {
					tech = m.Matcher
				} else {
					tech = m.Name
				}
			}
			if tech == "" {
				continue
			}
			if out[key] == nil {
				out[key] = make(map[string]bool)
			}
			out[key][tech] = true
		}
	}
	return out, nil
}

func cutCPE(cpe string) (vendor, product string, ok bool) {
	for i := 0; i < len(cpe); i++ {
		if cpe[i] == ':' {
			rest := cpe[i+1:]
			for j := 0; j < len(rest); j++ {
				if rest[j] == ':' {
					rest = rest[:j]
					break
				}
			}
			return cpe[:i], rest, i > 0 && len(rest) > 0
		}
	}
	return "", "", false
}

// TimelineRun is a host's state in one run.
type TimelineRun struct {
	Run        RunRef    `json:"run"`
	Up         bool      `json:"up"`
	ObservedAt time.Time `json:"observed_at"`
	OpenPorts  []int32   `json:"open_ports"`
}

// Timeline is a host's up/down history (GET /api/changes/hosts/{ip}).
type Timeline struct {
	IP    netip.Addr    `json:"ip"`
	Ports []int32       `json:"ports"` // every port open in any of the runs
	Runs  []TimelineRun `json:"runs"`  // newest first
}

// HostTimeline returns the host's state in the last n runs that scanned it.
func HostTimeline(ctx context.Context, q *gen.Queries, ip netip.Addr, n int32) (*Timeline, error) {
	rows, err := q.HostTimelineRuns(ctx, gen.HostTimelineRunsParams{Ip: ip, Lim: n})
	if err != nil {
		return nil, fmt.Errorf("timeline %s: %w", ip, err)
	}
	tl := &Timeline{IP: ip, Ports: []int32{}, Runs: make([]TimelineRun, len(rows))}
	ids := make([]int64, len(rows))
	idx := map[int64]int{}
	for i, r := range rows {
		ids[i], idx[r.ID] = r.ID, i
		tl.Runs[i] = TimelineRun{
			Run: RunRef{ID: r.ID, ProfileID: r.ProfileID, Status: r.Status, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Stages: pipeline.EffectiveStages(r.Stages)},
			Up:  r.Up, ObservedAt: r.ObservedAt, OpenPorts: []int32{},
		}
	}
	if len(ids) == 0 {
		return tl, nil
	}
	ports, err := q.HostTimelinePorts(ctx, gen.HostTimelinePortsParams{Ip: ip, RunIds: ids})
	if err != nil {
		return nil, fmt.Errorf("timeline %s ports: %w", ip, err)
	}
	for _, p := range ports {
		if !p.Up {
			continue
		}
		tr := &tl.Runs[idx[p.RunID]]
		tr.OpenPorts = append(tr.OpenPorts, p.Port)
		tl.Ports = append(tl.Ports, p.Port)
	}
	slices.Sort(tl.Ports)
	tl.Ports = slices.Compact(tl.Ports)
	return tl, nil
}
