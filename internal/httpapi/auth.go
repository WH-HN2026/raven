package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/httpx"
)

func (a *api) mountAuth(r chi.Router) {
	r.Post("/auth/login", a.login) // public; CSRF header still required
	r.With(auth.Require(auth.PermRead)).Post("/auth/logout", a.logout)
	r.With(auth.Require(auth.PermRead)).Get("/auth/me", a.me)
	r.With(auth.Require(auth.PermRead)).Patch("/auth/me/password", a.changeOwnPassword)
}

type meResponse struct {
	User        auth.User         `json:"user"`
	Permissions []auth.Permission `json:"permissions"`
}

func newMe(u auth.User) meResponse {
	return meResponse{User: u, Permissions: auth.Permissions(u.Role)}
}

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	token, u, err := a.Auth.Login(r.Context(), in.Username, in.Password)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		httpx.Error(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	if err != nil {
		slog.Error("login", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "login failed")
		return
	}
	http.SetCookie(w, a.sessionCookie(token, 0))
	httpx.JSON(w, http.StatusOK, newMe(u))
}

func (a *api) logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(auth.CookieName)
	if err == nil {
		if err := a.Auth.Logout(r.Context(), c.Value, *auth.UserFrom(r.Context())); err != nil {
			slog.Error("logout", "err", err)
			httpx.Error(w, http.StatusInternalServerError, "internal", "logout failed")
			return
		}
	}
	http.SetCookie(w, a.sessionCookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) me(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, newMe(*auth.UserFrom(r.Context())))
}

// sessionCookie: session-lifetime cookie (maxAge 0) or deletion (maxAge -1).
// The server-side expiry in the sessions table is authoritative.
func (a *api) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     auth.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	}
}
