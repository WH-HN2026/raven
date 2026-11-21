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
	"github.com/WH-HN2026/raven/internal/signatures"
)

// Signatures API against a real DB: built-in pack seeding, RBAC (viewer 403),
// create/validate/update/delete as editor, invalid templates stored disabled,
// built-ins can be disabled but not edited or deleted, audit rows, and the
// 501 test stub.
func TestSignaturesAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	svc := auth.NewService(q, time.Hour)
	for _, u := range []struct{ name, role string }{{"viewer", "viewer"}, {"editor", "editor"}} {
		hash, _ := auth.HashPassword(u.name + "-pw")
		if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: u.name, PasswordHash: hash, Role: u.role}); err != nil {
			t.Fatal(err)
		}
	}
	signatures.LoadBuiltins(ctx, pool)
	pack, err := signatures.Pack()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(Deps{Pool: pool, Queries: q, Auth: svc}))
	defer srv.Close()

	do := func(method, path, cookie string, body any) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		req.Header.Set(auth.CSRFHeader, "1")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	expect := func(want int, method, path, cookie string, body any) string {
		t.Helper()
		code, resp := do(method, path, cookie, body)
		if code != want {
			t.Fatalf("%s %s = %d %s, want %d", method, path, code, resp, want)
		}
		return resp
	}
	login := func(user string) string {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/api/auth/login",
			strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, user, user+"-pw")))
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
		t.Fatal("no session cookie")
		return ""
	}
	decode := func(s string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(s), v); err != nil {
			t.Fatalf("decode %s: %v", s, err)
		}
	}
	viewer, editor := login("viewer"), login("editor")

	// Built-in pack seeded: all enabled and valid, listed first.
	var page struct {
		Items []gen.Signature `json:"items"`
		Total int64           `json:"total"`
	}
	decode(expect(200, "GET", "/api/signatures?limit=1000", viewer, nil), &page)
	if int(page.Total) != len(pack) || len(pack) < 30 {
		t.Fatalf("total %d, pack %d", page.Total, len(pack))
	}
	builtin := page.Items[0]
	for _, s := range page.Items {
		if !s.Builtin || !s.Valid || !s.Enabled {
			t.Fatalf("built-in not valid+enabled: %+v", s)
		}
	}

	good := strings.ReplaceAll(`id: lab-staging-banner
info:
  name: Lab staging banner
  severity: low
  tags: lab,staging
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["STAGING"]
`, "\t", "  ")
	evil := strings.Replace(good, "id: lab-staging-banner", "id: lab-evil", 1)
	evil = strings.Replace(evil, "method: GET", "method: POST", 1)

	// Viewer: read yes, mutations 403.
	expect(403, "POST", "/api/signatures", viewer, map[string]any{"template_yaml": good})
	expect(403, "POST", "/api/signatures/validate", viewer, map[string]any{"template_yaml": good})
	expect(403, "PUT", fmt.Sprintf("/api/signatures/%d", builtin.ID), viewer, map[string]any{"enabled": false})
	expect(403, "DELETE", fmt.Sprintf("/api/signatures/%d", builtin.ID), viewer, nil)

	// Validate without saving.
	var v struct {
		Valid  bool               `json:"valid"`
		Errors []string           `json:"errors"`
		Issues []signatures.Issue `json:"issues"`
		ID     string             `json:"id"`
	}
	decode(expect(200, "POST", "/api/signatures/validate", editor, map[string]any{"template_yaml": evil}), &v)
	if v.Valid || len(v.Issues) == 0 || v.Issues[0].Line != 7 || !strings.Contains(v.Errors[0], "line 7: method POST") {
		t.Fatalf("validate evil: %+v", v)
	}

	// Create good (enabled by default), duplicate id → 409.
	var sig gen.Signature
	decode(expect(201, "POST", "/api/signatures", editor, map[string]any{"template_yaml": good}), &sig)
	if sig.Name != "lab-staging-banner" || !sig.Valid || !sig.Enabled || sig.Builtin {
		t.Fatalf("created: %+v", sig)
	}
	expect(409, "POST", "/api/signatures", editor, map[string]any{"template_yaml": good})
	// A template without an id can't be stored.
	expect(400, "POST", "/api/signatures", editor, map[string]any{"template_yaml": "info: {name: x}"})

	// Invalid template is stored, disabled, with its error; enabling it is 400.
	var bad gen.Signature
	decode(expect(201, "POST", "/api/signatures", editor, map[string]any{"template_yaml": evil, "enabled": true}), &bad)
	if bad.Valid || bad.Enabled || !strings.Contains(bad.ValidationError, "line 7: method POST is not allowed") {
		t.Fatalf("invalid stored: %+v", bad)
	}
	expect(400, "PUT", fmt.Sprintf("/api/signatures/%d", bad.ID), editor, map[string]any{"enabled": true})
	// Fixing it makes it valid; then it can be enabled.
	fixed := strings.Replace(evil, "method: POST", "method: HEAD", 1)
	decode(expect(200, "PUT", fmt.Sprintf("/api/signatures/%d", bad.ID), editor, map[string]any{"template_yaml": fixed, "enabled": true}), &bad)
	if !bad.Valid || !bad.Enabled || bad.ValidationError != "" {
		t.Fatalf("fixed: %+v", bad)
	}

	// Built-in: may be disabled, not edited, not deleted.
	expect(403, "PUT", fmt.Sprintf("/api/signatures/%d", builtin.ID), editor, map[string]any{"template_yaml": good})
	decode(expect(200, "PUT", fmt.Sprintf("/api/signatures/%d", builtin.ID), editor, map[string]any{"enabled": false}), &sig)
	if sig.Enabled {
		t.Fatal("built-in still enabled")
	}
	expect(403, "DELETE", fmt.Sprintf("/api/signatures/%d", builtin.ID), editor, nil)

	// Delete a user signature.
	expect(204, "DELETE", fmt.Sprintf("/api/signatures/%d", bad.ID), editor, nil)
	expect(404, "GET", fmt.Sprintf("/api/signatures/%d", bad.ID), viewer, nil)

	// Test-against-URL is a stub until S4.
	expect(501, "POST", fmt.Sprintf("/api/signatures/%d/test", builtin.ID), editor, map[string]any{"url": "http://127.0.0.1/"})

	// Re-loading the pack keeps the user's choice and writes no audit row.
	signatures.LoadBuiltins(ctx, pool)
	decode(expect(200, "GET", fmt.Sprintf("/api/signatures/%d", builtin.ID), viewer, nil), &sig)
	if sig.Enabled {
		t.Fatal("reload re-enabled a disabled built-in")
	}

	rows, err := q.ListAudit(ctx, gen.ListAuditParams{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range rows {
		got[r.Action]++
	}
	want := map[string]int{"signatures.sync_builtin": 1, "signatures.create": 2, "signatures.update": 2, "signatures.delete": 1}
	for a, n := range want {
		if got[a] != n {
			t.Errorf("audit %s = %d, want %d (all: %v)", a, got[a], n, got)
		}
	}
}
