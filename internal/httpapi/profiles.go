package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/scheduler"
)

func (a *api) mountProfiles(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/profiles", a.listProfiles)
	r.With(auth.Require(auth.PermProfilesWrite)).Post("/profiles", a.createProfile)
	r.With(auth.Require(auth.PermProfilesWrite)).Put("/profiles/{id}", a.updateProfile)
	r.With(auth.Require(auth.PermProfilesWrite)).Delete("/profiles/{id}", a.deleteProfile)
}

func (a *api) listProfiles(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	items, err := a.Queries.ListProfiles(r.Context(), gen.ListProfilesParams{Limit: limit, Offset: offset})
	if err != nil {
		scanConfigError(w, "list profiles", err)
		return
	}
	total, err := a.Queries.CountProfiles(r.Context())
	if err != nil {
		scanConfigError(w, "count profiles", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[gen.Profile]{Items: items, Total: total})
}

func (a *api) createProfile(w http.ResponseWriter, r *http.Request) {
	var in scheduler.ProfileInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	profile, err := a.scanConfig().CreateProfile(ctx, auth.UserFrom(ctx).ID, in)
	if err != nil {
		scanConfigError(w, "create profile", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, profile)
}

func (a *api) updateProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in scheduler.ProfileInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	profile, err := a.scanConfig().UpdateProfile(ctx, auth.UserFrom(ctx).ID, id, in)
	if err != nil {
		scanConfigError(w, "update profile", err)
		return
	}
	httpx.JSON(w, http.StatusOK, profile)
}

func (a *api) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := a.scanConfig().DeleteProfile(ctx, auth.UserFrom(ctx).ID, id); err != nil {
		scanConfigError(w, "delete profile", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
