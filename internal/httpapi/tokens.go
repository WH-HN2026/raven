package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/users"
)

// API token administration for MCP (task MCP1). Logic lives in internal/users.
func (a *api) mountTokens(r chi.Router) {
	r.With(auth.Require(auth.PermTokensAdmin)).Get("/tokens", a.listAPITokens)
	r.With(auth.Require(auth.PermTokensAdmin)).Post("/tokens", a.createAPIToken)
	r.With(auth.Require(auth.PermTokensAdmin)).Delete("/tokens/{id}", a.deleteAPIToken)
}

func (a *api) listAPITokens(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	items, total, err := a.userStore().ListAPITokens(r.Context(), limit, offset)
	if err != nil {
		usersError(w, "list api tokens", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[users.APIToken]{Items: items, Total: total})
}

func (a *api) createAPIToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string `json:"name"`
		UserID *int64 `json:"user_id"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	tok, err := a.userStore().CreateAPIToken(r.Context(), auth.UserFrom(r.Context()), in.Name, in.UserID)
	if err != nil {
		usersError(w, "create api token", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, tok)
}

func (a *api) deleteAPIToken(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := a.userStore().RevokeAPIToken(r.Context(), auth.UserFrom(r.Context()), id); err != nil {
		usersError(w, "revoke api token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
