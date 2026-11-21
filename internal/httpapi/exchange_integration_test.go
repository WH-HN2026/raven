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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

func TestExchangeAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	authSvc := auth.NewService(q, time.Hour)

	createUser := func(username, password, role string) string {
		t.Helper()
		hash, _ := auth.HashPassword(password)
		if _, err := q.CreateUser(ctx, gen.CreateUserParams{Username: username, PasswordHash: hash, Role: role}); err != nil {
			t.Fatal(err)
		}
		return password
	}
	createUser("viewer", "viewer-pw-1234", "viewer")
	createUser("editor", "editor-pw-1234", "editor")

	pipe, err := pipeline.New(pool, pipeline.Config{Scanner: nmap.New(nmap.Config{})})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(Deps{
		Pool: pool, Queries: q, Auth: authSvc, Pipeline: pipe, DojoPublicURL: "http://dojo.local",
	}))
	defer srv.Close()

	login := func(username, password string) string {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+"/api/auth/login", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
		req.Header.Set(auth.CSRFHeader, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("login %s: err=%v status=%v", username, err, resp)
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
	viewerCookie := login("viewer", "viewer-pw-1234")
	editorCookie := login("editor", "editor-pw-1234")

	upload := func(cookie, kind, profile, filename string, data []byte) (int, string) {
		t.Helper()
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		if kind != "" {
			_ = w.WriteField("kind", kind)
		}
		if profile != "" {
			_ = w.WriteField("profile", profile)
		}
		fw, err := w.CreateFormFile("file", filename)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(data)
		_ = w.Close()

		req, _ := http.NewRequest("POST", srv.URL+"/api/import/results", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
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

	get := func(cookie, path string) (int, http.Header, string) {
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
		return resp.StatusCode, resp.Header, string(b)
	}

	sampleJSON, err := os.ReadFile("../exchange/testdata/sample_results.json")
	if err != nil {
		t.Fatal(err)
	}

	// Viewer MUST get 403 on import!
	if code, body := upload(viewerCookie, "results-json", "default", "sample.json", sampleJSON); code != http.StatusForbidden {
		t.Fatalf("viewer import = %d %s, want 403", code, body)
	}
	// Anonymous gets 401.
	if code, body := upload("", "results-json", "default", "sample.json", sampleJSON); code != http.StatusUnauthorized {
		t.Fatalf("anon import = %d %s, want 401", code, body)
	}

	// Editor imports run 1 and run 2 (with a version change).
	code, body1 := upload(editorCookie, "results-json", "default", "run1.json", sampleJSON)
	if code != http.StatusAccepted {
		t.Fatalf("editor import run1 = %d %s, want 202", code, body1)
	}
	var run1 pipeline.Run
	if err := json.Unmarshal([]byte(body1), &run1); err != nil || run1.Status != "done" || run1.HostsUp != 2 {
		t.Fatalf("run1 = %s (err=%v)", body1, err)
	}

	sampleJSON2 := bytes.ReplaceAll(sampleJSON, []byte("1.24.0"), []byte("1.25.0"))
	code, body2 := upload(editorCookie, "results-json", "default", "run2.json", sampleJSON2)
	if code != http.StatusAccepted {
		t.Fatalf("editor import run2 = %d %s, want 202", code, body2)
	}

	// Viewer CAN export hosts as CSV and changes as JSON.
	code, hdr, csvBody := get(viewerCookie, "/api/export/hosts?format=csv&port=80")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.Contains(csvBody, "172.30.0.10") || strings.Contains(csvBody, "172.30.0.11") {
		t.Fatalf("export hosts csv = %d ct=%q body:\n%s", code, hdr.Get("Content-Type"), csvBody)
	}

	code, hdr, chBody := get(viewerCookie, "/api/export/changes?format=json")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") || !strings.Contains(chBody, `"1.25.0"`) {
		t.Fatalf("export changes json = %d ct=%q body:\n%s", code, hdr.Get("Content-Type"), chBody)
	}

	// Invalid export kind/format -> 400.
	if code, _, _ := get(viewerCookie, "/api/export/nope?format=json"); code != http.StatusBadRequest {
		t.Fatalf("bad export kind = %d, want 400", code)
	}
	if code, _, _ := get(viewerCookie, "/api/export/hosts?format=xml"); code != http.StatusBadRequest {
		t.Fatalf("bad export format = %d, want 400", code)
	}
}
