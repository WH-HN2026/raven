package httpapi

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/targets"
)

// Scope include/exclude lists (task S1). Global entries (profile_id null)
// additionally need auth.PermGlobalScope, checked in internal/targets.
func (a *api) mountScope(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/scope", a.listScope)
	r.With(auth.Require(auth.PermScopeWrite)).Post("/scope", a.createScopeEntry)
	r.With(auth.Require(auth.PermScopeWrite)).Delete("/scope/{id}", a.deleteScopeEntry)
}

func (a *api) listScope(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	var profileID *int64
	if v := r.URL.Query().Get("profile_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid profile_id")
			return
		}
		profileID = &id
	}
	items, total, err := a.targetStore().ListScope(r.Context(), profileID, limit, offset)
	if err != nil {
		targetsError(w, "list scope", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[gen.ScopeEntry]{Items: items, Total: total})
}

func (a *api) createScopeEntry(w http.ResponseWriter, r *http.Request) {
	var in targets.ScopeInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	e, err := a.targetStore().AddScopeEntry(r.Context(), auth.UserFrom(r.Context()), in)
	if err != nil {
		targetsError(w, "add scope entry", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, e)
}

func (a *api) deleteScopeEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := a.targetStore().DeleteScopeEntry(r.Context(), auth.UserFrom(r.Context()), id); err != nil {
		targetsError(w, "delete scope entry", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
