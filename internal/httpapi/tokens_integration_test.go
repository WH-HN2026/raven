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

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
)

// API tokens HTTP API against a real DB: CRUD as admin, RBAC for viewer/operator/editor,
// no plaintext token leakage on GET or in audit_log.
func TestTokensAPI(t *testing.T) {
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
	createUser := func(cookie, user, role string) int64 {
		t.Helper()
		body := expect(201, "POST", "/api/users", cookie,
			fmt.Sprintf(`{"username":%q,"password":"%s password 1","role":%q}`, user, user, role))
		var u struct{ ID int64 }
		_ = json.Unmarshal([]byte(body), &u)
		return u.ID
	}

	admin := login("admin", "admin password 1")
	viewerID := createUser(admin, "vi", "viewer")
	createUser(admin, "op", "operator")
	createUser(admin, "ed", "editor")

	// Validation.
	expect(400, "POST", "/api/tokens", admin, `{"name":"   "}`)
	expect(404, "POST", "/api/tokens", admin, `{"name":"ghost","user_id":99999}`)

	// Admin creates a token defaulting to self, and one scoped to viewer.
	selfResp := expect(201, "POST", "/api/tokens", admin, `{"name":"admin-mcp"}`)
	var selfTok struct {
		ID       int64  `json:"id"`
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Name     string `json:"name"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal([]byte(selfResp), &selfTok); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(selfTok.Token, "rvn_") || selfTok.Username != "admin" || selfTok.Role != "admin" {
		t.Fatalf("self token = %+v", selfTok)
	}

	viewerResp := expect(201, "POST", "/api/tokens", admin, fmt.Sprintf(`{"name":"viewer-mcp","user_id":%d}`, viewerID))
	var viewerTok struct {
		ID       int64  `json:"id"`
		UserID   int64  `json:"user_id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Name     string `json:"name"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal([]byte(viewerResp), &viewerTok); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(viewerTok.Token, "rvn_") || viewerTok.UserID != viewerID || viewerTok.Username != "vi" || viewerTok.Role != "viewer" {
		t.Fatalf("viewer token = %+v", viewerTok)
	}

	// GET /api/tokens lists metadata only, NEVER token or token_hash.
	listBody := expect(200, "GET", "/api/tokens", admin, "")
	if strings.Contains(listBody, selfTok.Token) || strings.Contains(listBody, viewerTok.Token) || strings.Contains(listBody, "token_hash") {
		t.Fatalf("GET /api/tokens leaked secret: %s", listBody)
	}
	var page struct {
		Items []struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal([]byte(listBody), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("GET /api/tokens = %s", listBody)
	}

	// RBAC: viewer, operator, editor all receive 403 on all /api/tokens routes.
	for _, u := range []string{"vi", "op", "ed"} {
		c := login(u, u+" password 1")
		expect(403, "GET", "/api/tokens", c, "")
		expect(403, "POST", "/api/tokens", c, `{"name":"nope"}`)
		expect(403, "DELETE", fmt.Sprintf("/api/tokens/%d", viewerTok.ID), c, "")
	}

	// Revoke.
	expect(204, "DELETE", fmt.Sprintf("/api/tokens/%d", viewerTok.ID), admin, "")
	expect(404, "DELETE", fmt.Sprintf("/api/tokens/%d", viewerTok.ID), admin, "")

	// Verify audit_log entries exist and contain no plaintext token.
	rows, err := pool.Query(ctx, `SELECT action, coalesce(user_id, 0), diff::text FROM audit_log WHERE action LIKE 'token.%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action, diff string
		var uid int64
		if err := rows.Scan(&action, &uid, &diff); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(diff, selfTok.Token) || strings.Contains(diff, viewerTok.Token) {
			t.Fatalf("audit diff leaks plaintext token: %s", diff)
		}
		got = append(got, fmt.Sprintf("%s:%d", action, uid))
	}
	want := []string{"token.create:1", "token.create:1", "token.revoke:1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit = %v, want %v", got, want)
	}
}
