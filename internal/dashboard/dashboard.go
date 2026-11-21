// Package dashboard builds the read-only overview behind GET /api/dashboard
// (task W4): active findings by severity, the change summary of the latest
// run pair (internal/changes), new and unstable hosts, top technologies,
// CVE matches and the last runs, in a few SQL queries.
package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/WH-HN2026/raven/internal/changes"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

// Limit caps every list on the dashboard.
const Limit = 8

// changesLimit caps the change lists (the page shows a short table).
const changesLimit = 10

// Severities is the display order of finding severities.
var Severities = []string{"Critical", "High", "Medium", "Low", "Info"}

// SeverityCount is the number of active findings of one severity.
type SeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// Findings are the active findings in the Dojo mirror.
type Findings struct {
	BySeverity []SeverityCount `json:"by_severity"` // all five, Critical first
	Total      int             `json:"total"`
}

// Hosts are the host and service counts by state.
type Hosts struct {
	Active       int `json:"active"`
	Unstable     int `json:"unstable"`
	Inactive     int `json:"inactive"`
	ServicesOpen int `json:"services_open"`
}

// NewHost is a host first seen in the latest run.
type NewHost struct {
	IP        netip.Addr `json:"ip"`
	Hostnames []string   `json:"hostnames"`
	State     string     `json:"state"`
	FirstSeen time.Time  `json:"first_seen"`
	Ports     []int32    `json:"ports"`
}

// UnstableHost is an unstable or inactive host with its recent up count.
type UnstableHost struct {
	IP        netip.Addr `json:"ip"`
	Hostnames []string   `json:"hostnames"`
	State     string     `json:"state"`
	LastSeen  time.Time  `json:"last_seen"`
	MissCount int        `json:"miss_count"`
	UpRuns    int        `json:"up_runs"`   // runs the host was up in, of the last SeenRuns
	SeenRuns  int        `json:"seen_runs"` // runs that scanned it, at most 10
}

// Technology is the number of hosts with a web technology.
type Technology struct {
	Name  string `json:"name"`
	Hosts int    `json:"hosts"`
}

// CVEMatch is one service with offline CVE matches.
type CVEMatch struct {
	IP       netip.Addr `json:"ip"`
	Port     int        `json:"port"`
	Proto    string     `json:"proto"`
	Product  string     `json:"product"`
	Version  string     `json:"version"`
	Severity string     `json:"severity"`
	MaxCVSS  float64    `json:"max_cvss"`
	KEV      int        `json:"kev"`
	CVEs     int        `json:"cves"`
}

// Run is a recent run.
type Run struct {
	ID           int64      `json:"id"`
	ProfileID    int64      `json:"profile_id"`
	Profile      string     `json:"profile"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	DurationMS   *int64     `json:"duration_ms"` // finished - started; null while unfinished
	HostsTotal   int        `json:"hosts_total"`
	HostsUp      int        `json:"hosts_up"`
	BatchesTotal int        `json:"batches_total"`
	BatchesDone  int        `json:"batches_done"`
}

// Dashboard is the GET /api/dashboard body.
type Dashboard struct {
	Findings      Findings         `json:"findings"`
	Hosts         Hosts            `json:"hosts"`
	Changes       *changes.Changes `json:"changes"` // nil until there are two done runs of a profile
	NewHosts      []NewHost        `json:"new_hosts"`
	NewHostsTotal int              `json:"new_hosts_total"`
	UnstableHosts []UnstableHost   `json:"unstable_hosts"` // unstable first, then inactive
	Technologies  []Technology     `json:"technologies"`
	CVEMatches    []CVEMatch       `json:"cve_matches"`
	CVETotal      int              `json:"cve_total"`
	Runs          []Run            `json:"runs"`
	LatestRun     *changes.RunRef  `json:"latest_run"` // latest done run
}

// Get builds the dashboard.
func Get(ctx context.Context, q *gen.Queries) (*Dashboard, error) {
	d := &Dashboard{}

	fc, err := q.DashboardFindingCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("dashboard findings: %w", err)
	}
	d.Findings = findingCounts(fc)

	hc, err := q.DashboardHostCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("dashboard host counts: %w", err)
	}
	d.Hosts = Hosts{Active: int(hc.Active), Unstable: int(hc.Unstable), Inactive: int(hc.Inactive), ServicesOpen: int(hc.ServicesOpen)}

	// The change summary of the latest done run against the previous done
	// run of the same profile (the C1 defaults).
	c, err := changes.Compare(ctx, q, nil, nil, changesLimit)
	switch {
	case err == nil:
		d.Changes = c
		d.LatestRun = &c.To
	case errors.Is(err, changes.ErrNoRuns):
		// fewer than two done runs: no diff; LatestRun may still exist
	default:
		return nil, fmt.Errorf("dashboard changes: %w", err)
	}
	if d.LatestRun == nil {
		r, err := q.LatestDoneRun(ctx, nil)
		switch {
		case err == nil:
			ref := changes.RunRef(r)
			d.LatestRun = &ref
		case !errors.Is(err, pgx.ErrNoRows):
			return nil, fmt.Errorf("dashboard latest run: %w", err)
		}
	}

	d.NewHosts = []NewHost{}
	if d.LatestRun != nil && d.LatestRun.StartedAt != nil {
		rows, err := q.DashboardNewHosts(ctx, gen.DashboardNewHostsParams{Since: *d.LatestRun.StartedAt, Lim: Limit})
		if err != nil {
			return nil, fmt.Errorf("dashboard new hosts: %w", err)
		}
		d.NewHosts, d.NewHostsTotal = newHosts(rows)
	}

	uh, err := q.DashboardUnstableHosts(ctx, Limit)
	if err != nil {
		return nil, fmt.Errorf("dashboard unstable hosts: %w", err)
	}
	d.UnstableHosts = unstableHosts(uh)

	tech, err := q.DashboardTechnologies(ctx, Limit)
	if err != nil {
		return nil, fmt.Errorf("dashboard technologies: %w", err)
	}
	d.Technologies = make([]Technology, len(tech))
	for i, t := range tech {
		d.Technologies[i] = Technology{Name: t.Name, Hosts: int(t.Hosts)}
	}

	cm, err := q.DashboardCVEMatches(ctx, Limit)
	if err != nil {
		return nil, fmt.Errorf("dashboard cve matches: %w", err)
	}
	d.CVEMatches, d.CVETotal = cveMatches(cm)

	runs, err := q.DashboardRuns(ctx, Limit)
	if err != nil {
		return nil, fmt.Errorf("dashboard runs: %w", err)
	}
	d.Runs = make([]Run, len(runs))
	for i, r := range runs {
		d.Runs[i] = run(r)
	}
	return d, nil
}

// findingCounts returns all five severities in display order (missing = 0).
func findingCounts(rows []gen.DashboardFindingCountsRow) Findings {
	by := map[string]int{}
	for _, r := range rows {
		by[r.Severity] = int(r.N)
	}
	f := Findings{BySeverity: make([]SeverityCount, len(Severities))}
	for i, s := range Severities {
		f.BySeverity[i] = SeverityCount{Severity: s, Count: by[s]}
		f.Total += by[s]
	}
	return f
}

func newHosts(rows []gen.DashboardNewHostsRow) ([]NewHost, int) {
	out := make([]NewHost, len(rows))
	total := 0
	for i, r := range rows {
		out[i] = NewHost{IP: r.Ip, Hostnames: r.Hostnames, State: r.State, FirstSeen: r.FirstSeen, Ports: r.Ports}
		total = int(r.Total)
	}
	return out, total
}

func unstableHosts(rows []gen.DashboardUnstableHostsRow) []UnstableHost {
	out := make([]UnstableHost, len(rows))
	for i, r := range rows {
		out[i] = UnstableHost{IP: r.Ip, Hostnames: r.Hostnames, State: r.State, LastSeen: r.LastSeen,
			MissCount: int(r.MissCount), UpRuns: int(r.UpRuns), SeenRuns: int(r.SeenRuns)}
	}
	return out
}

func cveMatches(rows []gen.DashboardCVEMatchesRow) ([]CVEMatch, int) {
	out := make([]CVEMatch, len(rows))
	total := 0
	for i, r := range rows {
		out[i] = CVEMatch{IP: r.Ip, Port: int(r.Port), Proto: r.Proto, Product: r.Product, Version: r.Version,
			Severity: r.Severity, MaxCVSS: float64(r.MaxCvss), KEV: int(r.Kev), CVEs: int(r.Cves)}
		total = int(r.Total)
	}
	return out, total
}

func run(r gen.DashboardRunsRow) Run {
	out := Run{ID: r.ID, ProfileID: r.ProfileID, Profile: r.Profile, Status: r.Status, CreatedAt: r.CreatedAt,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, HostsTotal: int(r.HostsTotal), HostsUp: int(r.HostsUp),
		BatchesTotal: int(r.BatchesTotal), BatchesDone: int(r.BatchesDone)}
	if r.StartedAt != nil && r.FinishedAt != nil {
		ms := r.FinishedAt.Sub(*r.StartedAt).Milliseconds()
		out.DurationMS = &ms
	}
	return out
}
