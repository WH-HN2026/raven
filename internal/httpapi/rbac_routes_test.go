package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
)

// public marks a route that needs no session.
const public auth.Permission = ""

// routePerms is the single table of every mounted /api route and the
// permission it must require. A new route must be added here, or
// TestRoutePermissions fails.
var routePerms = map[string]auth.Permission{
	"GET /api/healthz":     public,
	"POST /api/auth/login": public,

	"POST /api/auth/logout":       auth.PermRead,
	"GET /api/auth/me":            auth.PermRead,
	"PATCH /api/auth/me/password": auth.PermRead,

	"GET /api/targets":         auth.PermRead,
	"POST /api/targets":        auth.PermTargetsWrite,
	"POST /api/targets/upload": auth.PermImport,
	"DELETE /api/targets/{id}": auth.PermTargetsWrite,
	"GET /api/scope":           auth.PermRead,
	"POST /api/scope":          auth.PermScopeWrite,
	"DELETE /api/scope/{id}":   auth.PermScopeWrite,

	"GET /api/runs":              auth.PermRead,
	"POST /api/runs":             auth.PermRunsControl,
	"GET /api/runs/{id}":         auth.PermRead,
	"GET /api/runs/{id}/batches": auth.PermRead,
	"POST /api/runs/{id}/stop":   auth.PermRunsControl,

	"GET /api/hosts":           auth.PermRead,
	"GET /api/hosts/{ip}":      auth.PermRead,
	"PATCH /api/hosts/{ip}":    auth.PermHostsEdit,
	"GET /api/services":        auth.PermRead,
	"GET /api/technologies":    auth.PermRead,
	"PATCH /api/services/{id}": auth.PermHostsEdit,
	"GET /api/cve-matches":     auth.PermRead,

	"GET /api/findings":             auth.PermRead,
	"PATCH /api/findings/{id}":      auth.PermFindingsEdit,
	"POST /api/findings/{id}/notes": auth.PermFindingsEdit,

	"GET /api/changes":            auth.PermRead,
	"GET /api/changes/hosts/{ip}": auth.PermRead,

	"GET /api/dashboard": auth.PermRead,

	"GET /api/stages":           auth.PermRead,
	"GET /api/profiles":         auth.PermRead,
	"POST /api/profiles":        auth.PermProfilesWrite, // + auth.PermScanAggressive for aggressive stages
	"PUT /api/profiles/{id}":    auth.PermProfilesWrite, // + auth.PermScanAggressive for aggressive profiles/stages
	"DELETE /api/profiles/{id}": auth.PermProfilesWrite, // + auth.PermScanAggressive for aggressive profiles

	"GET /api/schedules":         auth.PermRead,
	"POST /api/schedules":        auth.PermSchedulesWrite, // + auth.PermScanAggressive for aggressive profiles
	"PUT /api/schedules/{id}":    auth.PermSchedulesWrite, // + auth.PermScanAggressive for aggressive profiles
	"DELETE /api/schedules/{id}": auth.PermSchedulesWrite, // + auth.PermScanAggressive for aggressive profiles

	"GET /api/signatures":            auth.PermRead,
	"POST /api/signatures":           auth.PermSignaturesWrite,
	"PUT /api/signatures/{id}":       auth.PermSignaturesWrite,
	"DELETE /api/signatures/{id}":    auth.PermSignaturesWrite,
	"POST /api/signatures/validate":  auth.PermSignaturesWrite,
	"GET /api/signatures/{id}":       auth.PermRead,
	"POST /api/signatures/{id}/test": auth.PermSignaturesWrite,

	"POST /api/import/results": auth.PermImport,
	"GET /api/export/{kind}":   auth.PermExport,

	"GET /api/users":         auth.PermUsersAdmin,
	"POST /api/users":        auth.PermUsersAdmin,
	"PATCH /api/users/{id}":  auth.PermUsersAdmin,
	"DELETE /api/users/{id}": auth.PermUsersAdmin,
}

var urlParam = regexp.MustCompile(`\{[^}]*\}`)

// TestRoutePermissions walks the real router and, for every /api route and
// every role (plus anonymous), checks that the request is rejected with
// 401/403 exactly when the role lacks the route's permission. Allowed
// requests reach handlers backed by an unreachable DB, so they fail in some
// other way (400/404/500/501/503); only "not 401/403" is asserted for them.
func TestRoutePermissions(t *testing.T) {
	// Lazy pool to a closed port: handlers that reach the DB fail fast.
	pool, err := pgxpool.New(context.Background(), "postgres://x:x@127.0.0.1:1/x?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := gen.New(pool)
	h := NewRouter(Deps{Pool: pool, Queries: q, Auth: auth.NewService(q, 0)})

	mounted := map[string]bool{}
	err = chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if strings.HasPrefix(route, "/api/") {
			mounted[method+" "+route] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for k := range mounted {
		if _, ok := routePerms[k]; !ok {
			t.Errorf("route %q is mounted but not in routePerms: declare its permission in this test", k)
		}
	}
	for k := range routePerms {
		if !mounted[k] {
			t.Errorf("routePerms has %q, which is not mounted", k)
		}
	}

	roles := []auth.Role{"", auth.RoleViewer, auth.RoleOperator, auth.RoleEditor, auth.RoleAdmin}
	for key, perm := range routePerms {
		if !mounted[key] {
			continue
		}
		method, route, _ := strings.Cut(key, " ")
		path := urlParam.ReplaceAllString(route, "1")
		for i, role := range roles {
			name := string(role)
			if role == "" {
				name = "anonymous"
			}
			t.Run(key+"/"+name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				req := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader("{}"))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(auth.CSRFHeader, "1")
				if role != "" {
					// No cookie: Sessions leaves this user in place.
					req = req.WithContext(auth.WithUser(ctx, &auth.User{ID: int64(i), Username: name, Role: role}))
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				switch {
				case perm == public:
					if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
						if !strings.Contains(rec.Body.String(), "invalid_credentials") {
							t.Fatalf("public route: got %d %s", rec.Code, rec.Body)
						}
					}
				case role == "":
					if rec.Code != http.StatusUnauthorized {
						t.Fatalf("anonymous: got %d %s, want 401", rec.Code, rec.Body)
					}
				case !auth.Can(role, perm):
					if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "missing permission") {
						t.Fatalf("%s lacks %s: got %d %s, want 403", role, perm, rec.Code, rec.Body)
					}
				default:
					// A handler may still answer 403 for a finer, domain-level
					// rule (e.g. global scope entries need scope:global); only
					// Require's rejection ("missing permission") is a failure.
					if rec.Code == http.StatusUnauthorized ||
						(rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "missing permission")) {
						t.Fatalf("%s has %s: got %d %s, want neither 401 nor 403", role, perm, rec.Code, rec.Body)
					}
				}
			})
		}
	}
}
