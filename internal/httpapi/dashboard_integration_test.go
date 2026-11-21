//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/dashboard"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
)

// A small seeded dataset → GET /api/dashboard shape.
func TestDashboardAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	t0 := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)
	runID := func(status string, start time.Time, finished *time.Time) int64 {
		t.Helper()
		var id int64
		err := pool.QueryRow(ctx, `INSERT INTO runs (profile_id, status, started_at, finished_at, hosts_total, hosts_up)
			SELECT id, $1, $2, $3, 4, 3 FROM profiles WHERE name = 'default' RETURNING id`, status, start, finished).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	end0, end1 := t0.Add(10*time.Minute), t1.Add(90*time.Second)
	r1 := runID("done", t0, &end0)
	r2 := runID("done", t1, &end1)
	r3 := runID("running", t1.Add(time.Hour), nil)
	exec(`INSERT INTO batches (run_id, seq, ips, status) VALUES ($1, 1, '{172.30.0.10}', 'done'), ($1, 2, '{172.30.0.11}', 'failed')`, r2)

	// .10 old+stable, .11 unstable (seen in both runs, down in r2), .12 new in r2, .13 inactive
	exec(`INSERT INTO run_observations (run_id, ip, port, up) VALUES
		($1, '172.30.0.10', NULL, true), ($1, '172.30.0.10', 80, true),
		($1, '172.30.0.11', NULL, true), ($1, '172.30.0.11', 22, true),
		($2, '172.30.0.10', NULL, true), ($2, '172.30.0.10', 80, true),
		($2, '172.30.0.11', NULL, false),
		($2, '172.30.0.12', NULL, true), ($2, '172.30.0.12', 8080, true)`, r1, r2)
	exec(`INSERT INTO hosts (ip, state, first_seen, last_seen, miss_count) VALUES
		('172.30.0.10', 'active', $1, $2, 0), ('172.30.0.11', 'unstable', $1, $1, 1),
		('172.30.0.12', 'active', $2, $2, 0), ('172.30.0.13', 'inactive', $1 - interval '1 day', $1 - interval '1 day', 3)`,
		t0.Add(time.Minute), t1.Add(time.Minute))
	exec(`INSERT INTO services (ip, port, proto, name, product, version, state) VALUES
		('172.30.0.10', 80, 'tcp', 'http', 'Apache httpd', '2.4.49', 'open'),
		('172.30.0.12', 8080, 'tcp', 'http', 'nginx', '1.18.0', 'open'),
		('172.30.0.12', 9090, 'tcp', 'http', '', '', 'gone')`)
	// .10: an older observation (PHP) superseded by the latest one; .12 and the gone service add Nginx / Jenkins
	exec(`INSERT INTO http_observations (service_id, url, technologies, run_id, observed_at)
		SELECT id, 'http://172.30.0.10', '{Apache HTTP Server,PHP}', $1, $2 FROM services WHERE port = 80`, r1, t0)
	exec(`INSERT INTO http_observations (service_id, url, technologies, run_id, observed_at)
		SELECT id, 'http://172.30.0.10', '{Apache HTTP Server}', $1, $2 FROM services WHERE port = 80`, r2, t1)
	exec(`INSERT INTO http_observations (service_id, url, technologies, run_id, observed_at)
		SELECT id, 'http://172.30.0.12:8080', '{Nginx,Apache HTTP Server}', $1, $2 FROM services WHERE port = 8080`, r2, t1)
	exec(`INSERT INTO http_observations (service_id, url, technologies, run_id, observed_at)
		SELECT id, 'http://172.30.0.12:9090', '{Jenkins}', $1, $2 FROM services WHERE port = 9090`, r2, t1)
	exec(`INSERT INTO dojo_findings (id, ip, title, severity, active) VALUES
		(1, '172.30.0.10', 'a', 'Critical', true), (2, '172.30.0.10', 'b', 'High', true),
		(3, '172.30.0.12', 'c', 'High', true), (4, '172.30.0.12', 'New device found', 'Info', true),
		(5, '172.30.0.10', 'closed', 'Critical', false), (6, NULL, 'No IP', 'Info', true)`)
	exec(`INSERT INTO cve_matches (ip, port, proto, product, cpe, version, cve_ids, hits, max_cvss, kev, distro, confidence, severity, matched_at, updated_at) VALUES
		('172.30.0.12', 8080, 'tcp', 'nginx', 'f5:nginx', '1.18.0', '{CVE-2021-23017}', '[]', 7.7, 0, false, 'high', 'High', now(), now()),
		('172.30.0.10', 80, 'tcp', 'Apache httpd', 'apache:http_server', '2.4.49', '{CVE-2021-42013,CVE-2021-41773}', '[]', 9.8, 2, false, 'high', 'Critical', now(), now())`)

	svc := auth.NewService(q, time.Hour)
	hash, _ := auth.HashPassword("viewer-pw")
	if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: "viewer", PasswordHash: hash, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(Deps{Pool: pool, Queries: q, Auth: svc}))
	defer srv.Close()

	get := func(cookie string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+"/api/dashboard", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	if code, _ := get(""); code != 401 {
		t.Fatalf("anonymous: %d, want 401", code)
	}

	req, _ := http.NewRequest("POST", srv.URL+"/api/auth/login", strings.NewReader(`{"username":"viewer","password":"viewer-pw"}`))
	req.Header.Set(auth.CSRFHeader, "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v %v", err, resp)
	}
	resp.Body.Close()
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			cookie = c.Value
		}
	}

	code, body := get(cookie)
	if code != 200 {
		t.Fatalf("GET /api/dashboard: %d %s", code, body)
	}
	var d dashboard.Dashboard
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}

	sev := map[string]int{}
	for _, s := range d.Findings.BySeverity {
		sev[s.Severity] = s.Count
	}
	if want := map[string]int{"Critical": 1, "High": 2, "Medium": 0, "Low": 0, "Info": 2}; !reflect.DeepEqual(sev, want) || d.Findings.Total != 5 {
		t.Errorf("findings %+v", d.Findings)
	}
	if want := (dashboard.Hosts{Active: 2, Unstable: 1, Inactive: 1, ServicesOpen: 2}); d.Hosts != want {
		t.Errorf("hosts %+v, want %+v", d.Hosts, want)
	}
	if d.Changes == nil || d.Changes.From.ID != r1 || d.Changes.To.ID != r2 {
		t.Fatalf("changes %+v", d.Changes)
	}
	if s := d.Changes.Summary; s.HostsNew != 1 || s.HostsGone != 1 {
		t.Errorf("changes summary %+v", s)
	}
	if d.LatestRun == nil || d.LatestRun.ID != r2 {
		t.Errorf("latest_run %+v", d.LatestRun)
	}
	if d.NewHostsTotal != 1 || len(d.NewHosts) != 1 || d.NewHosts[0].IP.String() != "172.30.0.12" ||
		!reflect.DeepEqual(d.NewHosts[0].Ports, []int32{8080}) {
		t.Errorf("new hosts %d %+v", d.NewHostsTotal, d.NewHosts)
	}
	if len(d.UnstableHosts) != 2 {
		t.Fatalf("unstable hosts %+v", d.UnstableHosts)
	}
	if u := d.UnstableHosts[0]; u.IP.String() != "172.30.0.11" || u.State != "unstable" || u.UpRuns != 1 || u.SeenRuns != 2 {
		t.Errorf("unstable[0] %+v", u)
	}
	if u := d.UnstableHosts[1]; u.IP.String() != "172.30.0.13" || u.State != "inactive" || u.SeenRuns != 0 {
		t.Errorf("unstable[1] %+v", u)
	}
	// latest observation per service only (PHP superseded), gone services ignored (Jenkins)
	wantTech := []dashboard.Technology{{Name: "Apache HTTP Server", Hosts: 2}, {Name: "Nginx", Hosts: 1}}
	if !reflect.DeepEqual(d.Technologies, wantTech) {
		t.Errorf("technologies %+v, want %+v", d.Technologies, wantTech)
	}
	if d.CVETotal != 2 || len(d.CVEMatches) != 2 || d.CVEMatches[0].Severity != "Critical" || d.CVEMatches[0].CVEs != 2 ||
		d.CVEMatches[0].KEV != 2 || d.CVEMatches[1].Port != 8080 {
		t.Errorf("cve %d %+v", d.CVETotal, d.CVEMatches)
	}
	if len(d.Runs) != 3 || d.Runs[0].ID != r3 || d.Runs[0].DurationMS != nil || d.Runs[1].ID != r2 {
		t.Fatalf("runs %+v", d.Runs)
	}
	if r := d.Runs[1]; r.Profile != "default" || *r.DurationMS != 90_000 || r.BatchesTotal != 2 || r.BatchesDone != 1 || r.HostsUp != 3 {
		t.Errorf("run %d: %+v", r2, r)
	}
}

// An empty database: every list is [] and the diff is null.
func TestDashboardAPIEmpty(t *testing.T) {
	pool := dbtest.Fresh(t)
	q := gen.New(pool)
	d, err := dashboard.Get(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	for _, s := range []string{`"changes":null`, `"latest_run":null`, `"new_hosts":[]`, `"unstable_hosts":[]`,
		`"technologies":[]`, `"cve_matches":[]`, `"runs":[]`, `"total":0`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("missing %s in %s", s, b)
		}
	}
}
