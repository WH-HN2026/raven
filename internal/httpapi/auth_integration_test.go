//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
)

// End-to-end auth against a real DB: bootstrap admin, login, me, RBAC on a
// stubbed mutation for admin vs viewer, logout, audit_log rows.
func TestAuthFlow(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	svc := auth.NewService(q, time.Hour)
	if err := svc.EnsureBootstrapAdmin(ctx, "admin", "admin-pw"); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnsureBootstrapAdmin(ctx, "admin2", "x"); err != nil { // no-op: admin exists
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("viewer-pw")
	if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: "viewer", PasswordHash: hash, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(Deps{Pool: pool, Queries: q, Auth: svc}))
	defer srv.Close()

	do := func(method, path, cookie, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set(auth.CSRFHeader, "1")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	login := func(user, pw string) string {
		t.Helper()
		resp := do("POST", "/api/auth/login", "", `{"username":"`+user+`","password":"`+pw+`"}`)
		if resp.StatusCode != 200 {
			t.Fatalf("login %s: %d", user, resp.StatusCode)
		}
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName {
				if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
					t.Fatalf("cookie flags: %+v", c)
				}
				return c.Value
			}
		}
		t.Fatal("no session cookie")
		return ""
	}

	if r := do("POST", "/api/auth/login", "", `{"username":"admin","password":"wrong"}`); r.StatusCode != 401 {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	admin := login("admin", "admin-pw")
	viewer := login("viewer", "viewer-pw")

	var me struct {
		User        auth.User `json:"user"`
		Permissions []string  `json:"permissions"`
	}
	if err := json.NewDecoder(do("GET", "/api/auth/me", viewer, "").Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.User.Role != auth.RoleViewer || len(me.Permissions) != 2 {
		t.Fatalf("viewer me = %+v", me)
	}
	if r := do("POST", "/api/targets", viewer, "{}"); r.StatusCode != 403 {
		t.Fatalf("viewer POST /api/targets = %d, want 403", r.StatusCode)
	}
	if r := do("POST", "/api/targets", admin, "{}"); r.StatusCode != 501 {
		t.Fatalf("admin POST /api/targets = %d, want 501 (stub)", r.StatusCode)
	}
	if r := do("POST", "/api/auth/logout", admin, ""); r.StatusCode != 204 {
		t.Fatalf("logout = %d", r.StatusCode)
	}
	if r := do("GET", "/api/auth/me", admin, ""); r.StatusCode != 401 {
		t.Fatalf("me after logout = %d", r.StatusCode)
	}

	var actions []string
	rows, err := pool.Query(ctx, "SELECT action FROM audit_log ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	want := "user.create,auth.login_failed,auth.login,auth.login,auth.logout"
	if got := strings.Join(actions, ","); got != want {
		t.Fatalf("audit_log = %s, want %s", got, want)
	}
}
