//go:build integration

package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
)

// Hosts API over HTTP: a viewer can read the list and the decrypted detail,
// bad filters are 400, unknown hosts 404, no session 401, PATCH is still a stub.
func TestHostsAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	svc := auth.NewService(q, time.Hour)
	hash, _ := auth.HashPassword("viewer-pw")
	if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: "viewer", PasswordHash: hash, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`INSERT INTO hosts (ip, hostnames, user_tags) VALUES ('10.30.0.5', '{api.lab}', '{lab}')`,
		`INSERT INTO services (ip, port, proto, name, product, banner_enc, overrides)
		 VALUES ('10.30.0.5', 8080, 'tcp', 'http', 'Tomcat', asi_enc('Apache-Coyote/1.1'), '{"version":"9.0"}')`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(NewRouter(Deps{Pool: pool, Queries: q, Auth: svc}))
	defer srv.Close()

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

	do := func(method, path string, withCookie bool) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader("{}"))
		req.Header.Set(auth.CSRFHeader, "1")
		if withCookie {
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
	for _, tc := range []struct {
		method, path string
		cookie       bool
		want         int
		has          []string
	}{
		{"GET", "/api/hosts", false, 401, nil},
		{"GET", "/api/hosts?tag=lab&port=8080", true, 200, []string{`"total":1`, `"ip":"10.30.0.5"`, `"open_ports":[8080]`, `"open_service_count":1`}},
		{"GET", "/api/hosts?tag=nope", true, 200, []string{`"items":[]`, `"total":0`}},
		{"GET", "/api/hosts?port=x", true, 400, []string{`"bad_request"`}},
		{"GET", "/api/hosts?state=gone", true, 400, []string{`"bad_request"`}},
		{"GET", "/api/hosts/10.30.0.5", true, 200, []string{
			`"banner":"Apache-Coyote/1.1"`, `"version":"9.0"`, `"overridden":["version"]`,
			`"scan":{"name":"http","product":"Tomcat","version":""}`, `"http":[]`, `"timeline":[]`, `"notes":""`,
		}},
		{"GET", "/api/hosts/10.30.0.9", true, 404, []string{`"not_found"`}},
		{"GET", "/api/hosts/not-an-ip", true, 400, []string{`"bad_request"`}},
		{"PATCH", "/api/hosts/10.30.0.5", true, 403, nil}, // viewer lacks hosts:edit
	} {
		code, body := do(tc.method, tc.path, tc.cookie)
		if code != tc.want {
			t.Fatalf("%s %s = %d %s, want %d", tc.method, tc.path, code, body, tc.want)
		}
		for _, h := range tc.has {
			if !strings.Contains(body, h) {
				t.Fatalf("%s %s = %s, missing %s", tc.method, tc.path, body, h)
			}
		}
	}
}
