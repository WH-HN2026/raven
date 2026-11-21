// Package httpapi is the thin HTTP layer: parse → call the domain package →
// write JSON. Each area mounts its routes from its own file; keep this file
// to one mount line per area.
package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/pipeline"
)

// Deps are the services handlers call.
type Deps struct {
	Pool          *pgxpool.Pool
	Queries       *gen.Queries
	Auth          *auth.Service
	CookieSecure  bool
	DojoPublicURL string            // browser base URL of Dojo, for finding links
	Pipeline      *pipeline.Service // nil = runs API answers 503
	Dojo          *dojo.Lazy        // write-through client; unset = finding edits answer 503
	DojoPush      *dojo.PushService // optional: provides Pusher for .nessus imports
}

type api struct{ Deps }

func NewRouter(d Deps) http.Handler {
	a := &api{d}
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.Recoverer, requestLog)

	r.Route("/api", func(r chi.Router) {
		r.Use(auth.CSRF, auth.Sessions(d.Auth))
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			httpx.Error(w, http.StatusNotFound, "not_found", "no such endpoint")
		})
		r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			httpx.Error(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		})
		r.Get("/healthz", a.healthz)

		a.mountAuth(r)
		a.mountTargets(r)
		a.mountScope(r)
		a.mountRuns(r)
		a.mountHosts(r)
		a.mountServices(r)
		a.mountCVE(r)
		a.mountFindings(r)
		a.mountChanges(r)
		a.mountProfiles(r)
		a.mountSchedules(r)
		a.mountSignatures(r)
		a.mountExchange(r)
		a.mountUsers(r)
		a.mountDashboard(r)
	})

	r.Handle("/*", spaHandler())
	return r
}
