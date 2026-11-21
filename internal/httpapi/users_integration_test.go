//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
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

// Users API against a real DB: CRUD as admin, RBAC for editor/viewer, the
// self/last-admin rules, session revocation, own password change, audit_log.
func TestUsersAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	svc := auth.NewService(q, time.Hour)
	if err := svc.EnsureBootstrapAdmin(ctx, "admin", "admin password 1"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(Deps{Pool: pool, Queries: q, Auth: svc}))
	defer srv.Close()

	do := func(method, path, cookie, body string) (int, string) {
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
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	expect := func(want int, method, path, cookie, body string) string {
		t.Helper()
		code, resp := do(method, path, cookie, body)
		if code != want {
			t.Fatalf("%s %s = %d %s, want %d", method, path, code, resp, want)
		}
		return resp
	}
	login := func(user, pw string) string {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/api/auth/login",
			strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pw)))
		req.Header.Set(auth.CSRFHeader, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("login %s: %d", user, resp.StatusCode)
		}
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName {
				return c.Value
			}
		}
		t.Fatal("no session cookie")
		return ""
	}
	create := func(cookie, user, role string) int64 {
		t.Helper()
		body := expect(201, "POST", "/api/users", cookie,
			fmt.Sprintf(`{"username":%q,"password":"%s password 1","role":%q}`, user, user, role))
		var u struct{ ID int64 }
		_ = json.Unmarshal([]byte(body), &u)
		return u.ID
	}

	admin := login("admin", "admin password 1")
	adminID := int64(1)

	// Create + validation.
	editorID := create(admin, "ed", "editor")
	viewerID := create(admin, "vi", "viewer")
	expect(409, "POST", "/api/users", admin, `{"username":"ed","password":"another password","role":"viewer"}`)
	expect(400, "POST", "/api/users", admin, `{"username":"shorty","password":"elevenchars","role":"viewer"}`)
	expect(400, "POST", "/api/users", admin, `{"username":"x","password":"long enough password","role":"root"}`)
	expect(400, "POST", "/api/users", admin, `{"username":"bad name","password":"long enough password","role":"viewer"}`)

	// List never returns password hashes.
	list := expect(200, "GET", "/api/users", admin, "")
	if strings.Contains(list, "password") || strings.Contains(list, "argon2") {
		t.Fatalf("list leaks password data: %s", list)
	}
	var page struct {
		Items []struct {
			Username string
			Role     string
		}
		Total int
	}
	_ = json.Unmarshal([]byte(list), &page)
	if page.Total != 3 || len(page.Items) != 3 || page.Items[0].Username != "admin" {
		t.Fatalf("list = %s", list)
	}

	// RBAC: editor and viewer get 403 everywhere in /users.
	editor := login("ed", "ed password 1")
	viewer := login("vi", "vi password 1")
	for _, c := range []string{editor, viewer} {
		expect(403, "GET", "/api/users", c, "")
		expect(403, "POST", "/api/users", c, `{"username":"z","password":"long enough password","role":"admin"}`)
		expect(403, "PATCH", fmt.Sprintf("/api/users/%d", viewerID), c, `{"role":"admin"}`)
		expect(403, "DELETE", fmt.Sprintf("/api/users/%d", viewerID), c, "")
	}

	// Self rules and last admin.
	self := fmt.Sprintf("/api/users/%d", adminID)
	expect(409, "PATCH", self, admin, `{"role":"editor"}`)
	expect(409, "PATCH", self, admin, `{"disabled":true}`)
	expect(409, "DELETE", self, admin, "")
	expect(404, "PATCH", "/api/users/9999", admin, `{"role":"editor"}`)

	// Promote editor to admin, then that admin can't remove the bootstrap
	// admin's rights only if it's the last one: demoting admin #1 works now.
	expect(200, "PATCH", fmt.Sprintf("/api/users/%d", editorID), admin, `{"role":"admin"}`)
	expect(401, "GET", "/api/auth/me", editor, "") // role change revoked the session
	ed2 := login("ed", "ed password 1")
	expect(200, "PATCH", self, ed2, `{"role":"operator"}`)
	expect(401, "GET", "/api/auth/me", admin, "")
	// ed is now the only enabled admin. Over HTTP the actor is always an
	// enabled admin, so the last-admin rule only shows through the self rule
	// here; the rule itself is unit-tested in internal/users.
	expect(409, "PATCH", fmt.Sprintf("/api/users/%d", editorID), ed2, `{"disabled":true}`)

	// Disabling revokes the session and blocks login.
	expect(200, "GET", "/api/auth/me", viewer, "")
	expect(200, "PATCH", fmt.Sprintf("/api/users/%d", viewerID), ed2, `{"disabled":true}`)
	expect(401, "GET", "/api/auth/me", viewer, "")
	if code, _ := do("POST", "/api/auth/login", "", `{"username":"vi","password":"vi password 1"}`); code != 401 {
		t.Fatalf("disabled user login = %d, want 401", code)
	}

	// Password reset by an admin revokes sessions; the new password works.
	op := login("admin", "admin password 1") // admin #1 is now an operator
	expect(200, "PATCH", self, ed2, `{"password":"reset password 1"}`)
	expect(401, "GET", "/api/auth/me", op, "")
	op = login("admin", "reset password 1")

	// Own password change: current password required; other sessions revoked.
	op2 := login("admin", "reset password 1")
	expect(400, "PATCH", "/api/auth/me/password", op, `{"current_password":"wrong","new_password":"changed password 1"}`)
	expect(400, "PATCH", "/api/auth/me/password", op, `{"current_password":"reset password 1","new_password":"short"}`)
	expect(204, "PATCH", "/api/auth/me/password", op, `{"current_password":"reset password 1","new_password":"changed password 1"}`)
	expect(200, "GET", "/api/auth/me", op, "")
	expect(401, "GET", "/api/auth/me", op2, "")
	login("admin", "changed password 1")

	// Delete.
	expect(204, "DELETE", fmt.Sprintf("/api/users/%d", viewerID), ed2, "")
	expect(404, "DELETE", fmt.Sprintf("/api/users/%d", viewerID), ed2, "")

	// Audit: every mutation recorded with its actor, no secrets in diffs.
	rows, err := pool.Query(ctx, "SELECT action, coalesce(user_id, 0), diff::text FROM audit_log WHERE action LIKE 'user.%' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var action, diff string
		var uid int64
		if err := rows.Scan(&action, &uid, &diff); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(diff, "password 1") || strings.Contains(diff, "argon2") {
			t.Fatalf("audit diff leaks a secret: %s", diff)
		}
		got = append(got, fmt.Sprintf("%s:%d", action, uid))
	}
	want := []string{
		"user.create:0", // bootstrap
		"user.create:1", "user.create:1",
		"user.update:1",                         // promote ed
		fmt.Sprintf("user.update:%d", editorID), // demote admin #1
		fmt.Sprintf("user.update:%d", editorID), // disable vi
		fmt.Sprintf("user.update:%d", editorID), // reset #1's password
		"user.password_change_failed:1",         // wrong current password
		"user.password_change:1",                // own change
		fmt.Sprintf("user.delete:%d", editorID), // delete vi
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit = %v\nwant    %v", got, want)
	}
}
