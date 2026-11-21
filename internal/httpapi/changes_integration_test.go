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
	"github.com/WH-HN2026/raven/internal/changes"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
)

const nmapRun1 = `<?xml version="1.0"?><nmaprun start="1700000000">
<host><status state="up"/><address addr="10.40.0.1" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
 <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18"/>
  <script id="http-title" output="Old"><elem key="title">Old</elem></script></port>
</ports></host>
<host><status state="up"/><address addr="10.40.0.2" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host>
<host><status state="up"/><address addr="10.40.0.3" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd"/></port>
 <port protocol="tcp" portid="25"><state state="open"/><service name="smtp" product="Postfix"/></port></ports></host>
</nmaprun>`

const nmapRun2 = `<?xml version="1.0"?><nmaprun start="1700086400">
<host><status state="up"/><address addr="10.40.0.1" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
 <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18"/>
  <script id="http-title" output="Old"><elem key="title">Old</elem></script></port>
 <port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
</ports></host>
<host><status state="down"/><address addr="10.40.0.2" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="10.40.0.3" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="25"><state state="open"/><service name="smtp" product="Postfix"/></port></ports></host>
<host><status state="up"/><address addr="10.40.0.4" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port></ports></host>
</nmaprun>`

// Two seeded runs in a real DB → GET /api/changes and the host timeline.
func TestChangesAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	runID := func(status string) int64 {
		t.Helper()
		var id int64
		err := pool.QueryRow(ctx, `INSERT INTO runs (profile_id, status, started_at, finished_at)
			SELECT id, $1, now(), now() FROM profiles WHERE name = 'default' RETURNING id`, status).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	r1, r2 := runID("done"), runID("done")
	exec(`UPDATE runs SET started_at = '2026-11-21T10:00:00Z' WHERE id IN ($1, $2)`, r1, r2)
	runID("running") // not finished: ignored by the defaults
	exec(`INSERT INTO run_observations (run_id, ip, port, up) VALUES
		($1, '10.40.0.1', NULL, true), ($1, '10.40.0.1', 22, true), ($1, '10.40.0.1', 80, true),
		($1, '10.40.0.2', NULL, true), ($1, '10.40.0.2', 443, true),
		($1, '10.40.0.3', NULL, true), ($1, '10.40.0.3', 21, true), ($1, '10.40.0.3', 25, true),
		($2, '10.40.0.1', NULL, true), ($2, '10.40.0.1', 22, true), ($2, '10.40.0.1', 80, true), ($2, '10.40.0.1', 8080, true),
		($2, '10.40.0.2', NULL, false),
		($2, '10.40.0.3', NULL, true), ($2, '10.40.0.3', 25, true),
		($2, '10.40.0.4', NULL, true), ($2, '10.40.0.4', 3306, true)`, r1, r2)
	exec(`INSERT INTO artifacts (run_id, scanner, content_enc) VALUES ($1, 'nmap', raven_enc($2)), ($3, 'nmap', raven_enc($4))`,
		r1, nmapRun1, r2, nmapRun2)
	exec(`INSERT INTO hosts (ip) VALUES ('10.40.0.1')`)
	exec(`INSERT INTO services (ip, port, proto, name) VALUES ('10.40.0.1', 80, 'tcp', 'http')`)
	exec(`INSERT INTO http_observations (service_id, url, title, technologies, run_id)
		SELECT id, 'http://10.40.0.1', 'Old', $1, $2 FROM services WHERE port = 80`, []string{"Nginx"}, r1)
	exec(`INSERT INTO http_observations (service_id, url, title, technologies, run_id)
		SELECT id, 'http://10.40.0.1', 'Old', $1, $2 FROM services WHERE port = 80`, []string{"Nginx", "PHP"}, r2)

	svc := auth.NewService(q, time.Hour)
	for _, u := range []string{"admin", "viewer"} {
		hash, _ := auth.HashPassword(u + "-pw")
		if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: u, PasswordHash: hash, Role: u}); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(NewRouter(Deps{Pool: pool, Queries: q, Auth: svc}))
	defer srv.Close()
	login := func(user string) string {
		req, _ := http.NewRequest("POST", srv.URL+"/api/auth/login", strings.NewReader(`{"username":"`+user+`","password":"`+user+`-pw"}`))
		req.Header.Set(auth.CSRFHeader, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("login %s: %v %v", user, err, resp)
		}
		resp.Body.Close()
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName {
				return c.Value
			}
		}
		t.Fatal("no session cookie")
		return ""
	}
	get := func(path, cookie string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
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
	viewer, admin := login("viewer"), login("admin")

	// defaults: to = latest done run, from = the done run before it
	for _, cookie := range []string{viewer, admin} {
		code, body := get("/api/changes", cookie)
		if code != 200 {
			t.Fatalf("GET /api/changes: %d %s", code, body)
		}
		var c changes.Changes
		if err := json.Unmarshal(body, &c); err != nil {
			t.Fatal(err)
		}
		if c.From.ID != r1 || c.To.ID != r2 {
			t.Fatalf("runs %d→%d, want %d→%d", c.From.ID, c.To.ID, r1, r2)
		}
		want := changes.Summary{HostsNew: 1, HostsGone: 1, ServicesNew: 1, ServicesGone: 1, ServicesChanged: 2}
		if c.Summary != want || c.Truncated {
			t.Fatalf("summary %+v truncated %v", c.Summary, c.Truncated)
		}
		h := c.HostsNew[0]
		if h.IP.String() != "10.40.0.4" || h.OtherRun != "not_scanned" || !reflect.DeepEqual(h.Ports, []uint16{3306}) {
			t.Fatalf("hosts_new %+v", c.HostsNew)
		}
		if g := c.HostsGone[0]; g.IP.String() != "10.40.0.2" || !reflect.DeepEqual(g.Ports, []uint16{443}) {
			t.Fatalf("hosts_gone %+v", c.HostsGone)
		}
		if s := c.ServicesNew[0]; s.Port != 8080 || s.Before != nil || s.After.Name != "http-proxy" {
			t.Fatalf("services_new %+v", c.ServicesNew)
		}
		if s := c.ServicesGone[0]; s.IP.String() != "10.40.0.3" || s.Port != 21 || s.Before.Product != "vsftpd" || s.After != nil {
			t.Fatalf("services_gone %+v", c.ServicesGone)
		}
		ch := c.ServicesChanged
		if ch[0].Port != 22 || !reflect.DeepEqual(ch[0].Fields, []string{"version"}) ||
			ch[0].Before.Version != "8.9" || ch[0].After.Version != "9.6" {
			t.Fatalf("changed[0] %+v %+v %+v", ch[0], ch[0].Before, ch[0].After)
		}
		if ch[1].Port != 80 || !reflect.DeepEqual(ch[1].Fields, []string{"technologies"}) ||
			!reflect.DeepEqual(ch[1].After.Technologies, []string{"Nginx", "PHP"}) || ch[1].After.Title != "Old" {
			t.Fatalf("changed[1] %+v %+v", ch[1], ch[1].After)
		}
	}

	itoa := func(n int64) string { b, _ := json.Marshal(n); return string(b) }
	for _, tc := range []struct {
		path   string
		cookie string
		want   int
		has    []string
	}{
		{"/api/changes", "", 401, nil},
		{"/api/changes/hosts/10.40.0.1", "", 401, nil},
		{"/api/changes?from=" + itoa(r2) + "&to=" + itoa(r1), viewer, 400, []string{`from must be older than to`}},
		{"/api/changes?from=" + itoa(r1), viewer, 200, []string{`"to":{"id":` + itoa(r2)}},
		{"/api/changes?to=" + itoa(r1), viewer, 404, []string{`"not_found"`}}, // no done run before r1
		{"/api/changes?from=9999&to=" + itoa(r1), viewer, 404, []string{`run 9999: run not found`}},
		{"/api/changes?from=" + itoa(r1) + "&to=" + itoa(r1), viewer, 400, []string{`same run`}},
		{"/api/changes?from=x", viewer, 400, []string{`"bad_request"`}},
		{"/api/changes?limit=1&from=" + itoa(r1) + "&to=" + itoa(r2), viewer, 200,
			[]string{`"truncated":true`, `"services_changed":2`, `"services_changed":[{"ip":"10.40.0.1","port":22`}},
		{"/api/changes/hosts/10.40.0.2", viewer, 200, []string{
			`"ports":[443]`, `"run":{"id":` + itoa(r2), `"up":false`, `"open_ports":[]`, `"up":true`, `"open_ports":[443]`}},
		{"/api/changes/hosts/10.99.0.1", viewer, 200, []string{`"ports":[]`, `"runs":[]`}},
		{"/api/changes/hosts/nope", viewer, 400, []string{`"bad_request"`}},
		{"/api/changes/hosts/10.40.0.1?runs=1", admin, 200, []string{`"ports":[22,80,8080]`, `"open_ports":[22,80,8080]`}},
	} {
		code, body := get(tc.path, tc.cookie)
		if code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.path, code, body, tc.want)
			continue
		}
		for _, s := range tc.has {
			if !strings.Contains(string(body), s) {
				t.Errorf("%s: %s lacks %s", tc.path, body, s)
			}
		}
	}

	// With different start times, chronology takes precedence over ID.
	exec(`UPDATE runs SET started_at = started_at - interval '1 microsecond' WHERE id = $1`, r2)
	code, body := get("/api/changes", viewer)
	if code != 200 || !strings.Contains(string(body), `"from":{"id":`+itoa(r2)) ||
		!strings.Contains(string(body), `"to":{"id":`+itoa(r1)) {
		t.Errorf("default diff with changed start times = %d %s, want %d → %d", code, body, r2, r1)
	}
	code, body = get("/api/changes?from="+itoa(r1)+"&to="+itoa(r2), viewer)
	if code != 400 || !strings.Contains(string(body), "from must be older than to") {
		t.Errorf("reverse by start time = %d %s, want 400", code, body)
	}
}
