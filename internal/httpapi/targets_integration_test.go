//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/targets"
)

// Targets + scope API against a real DB: manual POST, CSV upload (dry run
// and real), list, delete, scope with the global-only permission, RBAC
// for viewer/editor, audit rows, and the S3 entry point ScanList.
func TestTargetsAndScopeAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	svc := auth.NewService(q, time.Hour)
	if err := svc.EnsureBootstrapAdmin(ctx, "admin", "admin-pw"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct{ name, role string }{{"viewer", "viewer"}, {"editor", "editor"}} {
		hash, _ := auth.HashPassword(u.name + "-pw")
		if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: u.name, PasswordHash: hash, Role: u.role}); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(NewRouter(Deps{Pool: pool, Queries: q, Auth: svc}))
	defer srv.Close()

	do := func(method, path, cookie, ctype string, body io.Reader) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, body)
		req.Header.Set(auth.CSRFHeader, "1")
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
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
	js := func(method, path, cookie, body string) (int, string) {
		return do(method, path, cookie, "application/json", strings.NewReader(body))
	}
	login := func(user string) string {
		t.Helper()
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
		t.Fatal("no cookie")
		return ""
	}
	upload := func(cookie, query, name, content string) (int, string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", name)
		_, _ = fw.Write([]byte(content))
		_ = mw.Close()
		return do("POST", "/api/targets/upload"+query, cookie, mw.FormDataContentType(), &buf)
	}
	expect := func(what string, code int, body string, want int, has string) {
		t.Helper()
		if code != want || !strings.Contains(body, has) {
			t.Fatalf("%s = %d %s, want %d containing %q", what, code, body, want, has)
		}
	}
	admin, viewer, editor := login("admin"), login("viewer"), login("editor")

	// manual targets
	code, body := js("POST", "/api/targets", admin, `{"targets":[{"value":"10.0.0.1","tags":["web"]},{"value":"10.0.1.0/24"},{"value":"wordpress.lab","note":"cms"}]}`)
	expect("admin POST 3 targets", code, body, 201, `"total":3`)
	code, body = js("POST", "/api/targets", admin, `{"targets":[{"value":"10.0.0.2"},{"value":"10.0.0.0/7"}]}`)
	expect("POST with a /7", code, body, 400, `"line":2`)
	code, body = js("POST", "/api/targets", admin, `{"targets":[{"value":"10.0.0.2"},{"value":"WORDPRESS.LAB","note":"replacement"}]}`)
	expect("duplicate existing target rolls back a batch", code, body, 409, `"message":"Target already exists"`)
	code, body = js("POST", "/api/targets", admin, `{"targets":[{"value":"10.0.0.2"},{"value":"10.0.0.2"}]}`)
	expect("duplicate within batch", code, body, 409, `"message":"Target already exists"`)
	code, body = js("POST", "/api/targets", viewer, `{"targets":[{"value":"10.0.0.9"}]}`)
	expect("viewer POST", code, body, 403, "forbidden")

	// CSV upload: dry run preview with the bad line, then the real import
	csv := "value,tags,note\n10.0.0.1,db,\n10.0.2.0/28,lab;dmz,lab net\nnot a target!,,\nstaging.lab,,\n"
	code, body = upload(admin, "?dry_run=true", "targets.csv", csv)
	expect("dry run", code, body, 200, `"errors":[{"line":4,"message":"invalid value \"not a target!\": not an IP, CIDR or domain"}]`)
	if !strings.Contains(body, `"dry_run":true`) || !strings.Contains(body, `"created":0`) {
		t.Fatalf("dry run body %s", body)
	}
	if code, body = js("GET", "/api/targets", admin, ""); !strings.Contains(body, `"total":3`) {
		t.Fatalf("dry run wrote rows: %d %s", code, body)
	}
	code, body = upload(viewer, "", "targets.csv", csv)
	expect("viewer upload", code, body, 403, "forbidden")
	code, body = upload(admin, "", "targets.csv", csv)
	expect("import", code, body, 200, `"created":3`)

	code, body = js("GET", "/api/targets?limit=2&offset=0", viewer, "")
	expect("viewer list", code, body, 200, `"total":5`)
	var page struct {
		Items []gen.Target `json:"items"`
	}
	_ = json.Unmarshal([]byte(body), &page)
	if len(page.Items) != 2 || page.Items[0].Value != "10.0.0.1" || strings.Join(page.Items[0].Tags, ",") != "db,web" {
		t.Fatalf("page = %+v", page.Items)
	}

	// scope: global entries need scope:global (admin yes, editor no)
	code, body = js("POST", "/api/scope", editor, `{"value":"10.0.1.128/25","list":"exclude"}`)
	expect("editor global exclude", code, body, 403, "scope:global")
	code, body = js("POST", "/api/scope", admin, `{"value":"10.0.1.128/25","list":"exclude","note":"blacklist"}`)
	expect("admin global exclude", code, body, 201, `"kind":"cidr"`)
	var excl gen.ScopeEntry
	_ = json.Unmarshal([]byte(body), &excl)
	code, body = js("POST", "/api/scope", admin, `{"value":"10.0.1.128/25","list":"exclude"}`)
	expect("duplicate scope entry", code, body, 409, `"message":"Target already exists"`)
	code, body = js("POST", "/api/scope", admin, `{"value":"10.0.1.1","list":"include","profile_id":999}`)
	expect("unknown profile", code, body, 400, "profile 999")
	code, body = js("GET", "/api/scope", viewer, "")
	expect("viewer scope list", code, body, 200, `"total":1`)
	code, body = js("DELETE", "/api/scope/"+itoa(excl.ID), editor, "")
	expect("editor delete global", code, body, 403, "scope:global")

	// the S3 entry point: the blacklist cuts the upper half of 10.0.1.0/24
	sl, err := (&targets.Store{Pool: pool}).ScanList(ctx, 0, fakeResolver{}, targets.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.1 + 10.0.1.0/25 (128) + 10.0.2.0/28 (16) + wordpress/staging → 10.9.9.9
	if len(sl.IPs) != 146 || sl.Stats.Excluded != 128 {
		t.Fatalf("scan list %d IPs, %+v, warnings %v", len(sl.IPs), sl.Stats, sl.Warnings)
	}

	code, body = js("DELETE", "/api/scope/"+itoa(excl.ID), admin, "")
	expect("admin delete global", code, body, 204, "")
	code, body = js("DELETE", "/api/targets/"+itoa(page.Items[1].ID), viewer, "")
	expect("viewer delete target", code, body, 403, "")
	code, body = js("DELETE", "/api/targets/"+itoa(page.Items[1].ID), editor, "")
	expect("editor delete target", code, body, 204, "")
	code, body = js("DELETE", "/api/targets/"+itoa(page.Items[1].ID), editor, "")
	expect("delete again", code, body, 404, "not_found")

	var actions []string
	rows, err := pool.Query(ctx, "SELECT action || ':' || coalesce(user_id::text, '-') FROM audit_log WHERE action LIKE 'targets.%' OR action LIKE 'scope.%' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	want := "targets.add:1,targets.add:1,scope.add:1,scope.delete:1,targets.delete:3"
	if got := strings.Join(actions, ","); got != want {
		t.Fatalf("audit_log = %s, want %s", got, want)
	}
}

type fakeResolver struct{}

func (fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
