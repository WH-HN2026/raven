package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/WH-HN2026/raven/internal/auth"
)

func TestRouter(t *testing.T) {
	h := NewRouter(Deps{Auth: auth.NewService(nil, 0)})
	tests := []struct {
		name, method, path string
		csrf               bool
		want               int
		bodyHas            string
	}{
		{"healthz", "GET", "/api/healthz", false, 200, `"status":"ok"`},
		{"unknown api path is JSON 404", "GET", "/api/nope", false, 404, `"code":"not_found"`},
		{"me needs a session", "GET", "/api/auth/me", false, 401, `"unauthenticated"`},
		{"mutation without CSRF header", "POST", "/api/targets", false, 403, `"csrf"`},
		{"login without CSRF header", "POST", "/api/auth/login", false, 403, `"csrf"`},
		{"mutation without session", "POST", "/api/targets", true, 401, `"unauthenticated"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader("{}"))
			if tt.csrf {
				req.Header.Set(auth.CSRFHeader, "1")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want || !strings.Contains(rec.Body.String(), tt.bodyHas) {
				t.Fatalf("got %d %q, want %d containing %q", rec.Code, rec.Body, tt.want, tt.bodyHas)
			}
		})
	}
}

func TestSPAFallback(t *testing.T) {
	h := NewRouter(Deps{Auth: auth.NewService(nil, 0)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/hosts/10.0.0.1", nil))
	// 200 with index.html once the SPA is built, 503 with a hint before.
	switch rec.Code {
	case http.StatusOK:
		if !strings.Contains(rec.Body.String(), "<div id=\"root\">") {
			t.Fatalf("fallback did not serve index.html: %s", rec.Body)
		}
	case http.StatusServiceUnavailable:
		if !strings.Contains(rec.Body.String(), "make build") {
			t.Fatalf("unexpected body %q", rec.Body)
		}
	default:
		t.Fatalf("status %d", rec.Code)
	}
}
