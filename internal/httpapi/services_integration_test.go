//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/hosts"
	"github.com/WH-HN2026/raven/internal/signatures"
)

// Q4 HTTP integration test covering /api/services, /api/technologies,
// /api/signatures (severity/tags + tag filter), /api/findings (status + asset
// filters), and /api/hosts/{ip} (edited_by + edited_at).
func TestQ4EndpointsAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	svc := auth.NewService(q, time.Hour)

	for _, u := range []struct{ name, role string }{{"viewer", "viewer"}, {"operator", "operator"}} {
		hash, _ := auth.HashPassword(u.name + "-pw")
		if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: u.name, PasswordHash: hash, Role: u.role}); err != nil {
			t.Fatal(err)
		}
	}
	signatures.LoadBuiltins(ctx, pool)

	for _, stmt := range []string{
		`INSERT INTO hosts (ip, hostnames, state) VALUES ('10.40.0.10', '{wp.lab}', 'active'), ('10.40.0.11', '{ssh.lab}', 'active')`,
		`INSERT INTO services (ip, port, proto, name, product, version, state) VALUES
			('10.40.0.10', 80, 'tcp', 'http', 'nginx', '1.25.3', 'open'),
			('10.40.0.11', 22, 'tcp', 'ssh', 'OpenSSH', '7.4', 'open')`,
		`INSERT INTO http_observations (service_id, url, status, title, technologies, observed_at)
		 SELECT id, 'http://10.40.0.10/', 200, 'Blog', '{WordPress:6.4,PHP:8.2}', now()
		 FROM services WHERE ip = '10.40.0.10' AND port = 80`,
		`INSERT INTO cve_matches (ip, port, proto, product, cpe, version, cve_ids, hits, max_cvss, kev, distro, confidence, severity, matched_at, updated_at)
		 VALUES ('10.40.0.11', 22, 'tcp', 'OpenSSH', 'openbsd:openssh', '7.4', '{CVE-2018-15473}', '[{"id":"CVE-2018-15473","cvss":5.3,"kev":false,"epss":0.5}]', 5.3, 0, false, 'high', 'Medium', now(), now())`,
		`INSERT INTO dojo_assets (id, name, ip) VALUES (100, '10.40.0.10', '10.40.0.10'), (101, '10.40.0.11', '10.40.0.11')`,
		`INSERT INTO dojo_findings (id, asset_id, ip, title, severity, active, verified, false_p, out_of_scope, risk_accepted, duplicate, is_mitigated, scanner) VALUES
			(1, 100, '10.40.0.10', 'Verified issue', 'High', true, true, false, false, false, false, false, 'nuclei'),
			(2, 100, '10.40.0.10', 'False positive issue', 'Low', false, false, true, false, false, false, false, 'nuclei'),
			(3, 101, '10.40.0.11', 'Out of scope issue', 'Medium', false, false, false, true, false, false, false, 'nmap'),
			(4, 101, '10.40.0.11', 'Risk accepted issue', 'High', false, false, false, false, true, false, false, 'nmap'),
			(5, 101, '10.40.0.11', 'Duplicate issue', 'Info', false, false, false, false, false, true, false, 'nmap'),
			(6, 100, '10.40.0.10', 'Mitigated issue', 'Critical', false, false, false, false, false, false, true, 'raven')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
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
		defer resp.Body.Close()
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName {
				return c.Value
			}
		}
		t.Fatal("missing cookie")
		return ""
	}
	do := func(method, path, cookie, body string) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		req.Header.Set(auth.CSRFHeader, "1")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	viewer, operator := login("viewer"), login("operator")

	// 1. /api/services and /api/technologies
	code, _ := do("GET", "/api/services", "", "")
	if code != 401 {
		t.Fatalf("unauth /api/services = %d, want 401", code)
	}
	code, body := do("GET", "/api/services?technology=WordPress&version=6.4", viewer, "")
	if code != 200 {
		t.Fatalf("GET /api/services = %d %s", code, body)
	}
	var svcResp struct {
		Items []hosts.ServiceItem `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &svcResp); err != nil || svcResp.Total != 1 || svcResp.Items[0].Port != 80 {
		t.Fatalf("services resp = %+v err=%v", svcResp, err)
	}
	code, _ = do("GET", "/api/services?sort=bogus", viewer, "")
	if code != 400 {
		t.Fatalf("bad sort = %d, want 400", code)
	}

	code, body = do("GET", "/api/technologies?sort=cves&order=desc", viewer, "")
	if code != 200 {
		t.Fatalf("GET /api/technologies = %d %s", code, body)
	}
	var techResp struct {
		Items []hosts.TechnologySummary `json:"items"`
		Total int64                     `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &techResp); err != nil || techResp.Total < 3 || techResp.Items[0].Technology != "OpenSSH" || techResp.Items[0].CVECount != 1 {
		t.Fatalf("tech resp = %+v err=%v", techResp, err)
	}

	// 2. /api/signatures exposes severity + tags and filters by tag
	code, body = do("GET", "/api/signatures?tag=panel&limit=100", viewer, "")
	if code != 200 {
		t.Fatalf("GET /api/signatures?tag=panel = %d %s", code, body)
	}
	var sigResp struct {
		Items []signatures.Signature `json:"items"`
		Total int64                  `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &sigResp); err != nil || sigResp.Total == 0 {
		t.Fatalf("sig resp = %+v err=%v", sigResp, err)
	}
	for _, s := range sigResp.Items {
		if s.Severity == "" || len(s.Tags) == 0 {
			t.Fatalf("signature missing severity/tags: %+v", s)
		}
	}

	// 3. /api/findings status + asset filters
	for _, tc := range []struct {
		query string
		want  []int64
	}{
		{"verified=true", []int64{1}},
		{"false_p=true", []int64{2}},
		{"out_of_scope=true", []int64{3}},
		{"risk_accepted=true", []int64{4}},
		{"duplicate=true", []int64{5}},
		{"is_mitigated=true", []int64{6}},
		{"asset_id=101", []int64{4, 3, 5}},
		{"asset=10.40.0.10&severity=Critical", []int64{6}},
	} {
		code, body = do("GET", "/api/findings?"+tc.query, viewer, "")
		if code != 200 {
			t.Fatalf("findings %s = %d %s", tc.query, code, body)
		}
		var fResp struct {
			Items []dojo.MirrorFinding `json:"items"`
			Total int64                `json:"total"`
		}
		if err := json.Unmarshal([]byte(body), &fResp); err != nil {
			t.Fatal(err)
		}
		got := make([]int64, len(fResp.Items))
		for i, it := range fResp.Items {
			got[i] = it.ID
		}
		if len(got) != len(tc.want) {
			t.Fatalf("findings %s got ids %v, want %v", tc.query, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("findings %s got ids %v, want %v", tc.query, got, tc.want)
			}
		}
	}

	// 4. PATCH /api/hosts/{ip} sets edited_by and edited_at
	code, body = do("PATCH", "/api/hosts/10.40.0.10", operator, `{"owner":"web ops"}`)
	if code != 200 {
		t.Fatalf("PATCH host = %d %s", code, body)
	}
	if !strings.Contains(body, `"edited_by":"operator"`) || !strings.Contains(body, `"edited_at":"20`) {
		t.Fatalf("PATCH host missing edited_by/edited_at: %s", body)
	}
}
