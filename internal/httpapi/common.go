package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/httpx"
)

func (a *api) healthz(w http.ResponseWriter, r *http.Request) {
	status, code := "ok", http.StatusOK
	if a.Pool != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := a.Pool.Ping(ctx); err != nil {
			status, code = "db_unavailable", http.StatusServiceUnavailable
		}
	}
	httpx.JSON(w, code, map[string]string{"status": status})
}

// stub registers an endpoint from api/openapi.yaml that a later task
// implements: it already enforces its permission, then answers 501.
func stub(r chi.Router, method, pattern string, perm auth.Permission) {
	r.With(auth.Require(perm)).MethodFunc(method, pattern, func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusNotImplemented, "not_implemented", "not implemented yet")
	})
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if r.URL.Path == "/api/healthz" {
			return
		}
		slog.Debug("http", "method", r.Method, "path", r.URL.Path, "status", ww.Status(), "dur", time.Since(start))
	})
}
