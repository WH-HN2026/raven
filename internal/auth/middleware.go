package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/WH-HN2026/raven/internal/httpx"
)

const (
	// CookieName is the session cookie (HttpOnly, SameSite=Strict).
	CookieName = "raven_session"
	// CSRFHeader must be present (value "1") on every unsafe request to /api.
	CSRFHeader = "X-RAVEN-CSRF"
)

type ctxKey struct{}

// UserFrom returns the authenticated user, or nil.
func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}

// WithUser returns ctx carrying u (used by the session middleware and tests).
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// SessionLookup resolves a session token to its user (nil if invalid).
type SessionLookup interface {
	UserForToken(ctx context.Context, token string) (*User, error)
}

// Sessions loads the user from the session cookie, if any, into the context.
// It never rejects a request; Require does.
func Sessions(store SessionLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(CookieName)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			u, err := store.UserForToken(r.Context(), c.Value)
			if err != nil {
				slog.Error("session lookup", "err", err)
				httpx.Error(w, http.StatusInternalServerError, "internal", "session lookup failed")
				return
			}
			if u != nil {
				r = r.WithContext(WithUser(r.Context(), u))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRF protection design: the session cookie is SameSite=Strict, and every
// unsafe request (POST/PUT/PATCH/DELETE) to /api — login included — must
// carry the custom header "X-RAVEN-CSRF: 1". Browsers can't add a custom header
// to a cross-origin request without a CORS preflight, which we never allow
// (no CORS headers are sent), so a forged form/fetch from another site fails
// here even if SameSite were bypassed. No token to store or rotate.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get(CSRFHeader) != "1" {
				httpx.Error(w, http.StatusForbidden, "csrf", "missing "+CSRFHeader+" header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Require rejects requests without a session (401) or whose role lacks perm (403).
func Require(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := UserFrom(r.Context())
			if u == nil {
				httpx.Error(w, http.StatusUnauthorized, "unauthenticated", "login required")
				return
			}
			if !Can(u.Role, perm) {
				httpx.Error(w, http.StatusForbidden, "forbidden", "missing permission "+string(perm))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
