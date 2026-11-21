package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scheduler"
)

func (a *api) mountProfiles(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/stages", a.listStages)
	r.With(auth.Require(auth.PermRead)).Get("/profiles", a.listProfiles)
	r.With(auth.Require(auth.PermProfilesWrite)).Post("/profiles", a.createProfile)
	r.With(auth.Require(auth.PermProfilesWrite)).Put("/profiles/{id}", a.updateProfile)
	r.With(auth.Require(auth.PermProfilesWrite)).Delete("/profiles/{id}", a.deleteProfile)
}

func (a *api) listStages(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, struct {
		Stages  []pipeline.StageDef   `json:"stages"`
		Presets pipeline.StagePresets `json:"presets"`
	}{
		Stages:  pipeline.Stages(),
		Presets: pipeline.Presets(),
	})
}

type profileView struct {
	gen.Profile
	Aggressive bool `json:"aggressive"`
}

func toProfileView(p gen.Profile) profileView {
	return profileView{Profile: p, Aggressive: pipeline.IsAggressive(p.Stages)}
}

func (a *api) listProfiles(w http.ResponseWriter, r *http.Request) {
	order, ok := listOrder(w, r, "name", "ports", "nmap_rate", "nuclei_rate", "nuclei_tags", "miss_threshold", "batch", "enabled")
	if !ok {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	rows, err := a.Queries.ListProfiles(r.Context(), gen.ListProfilesParams{SortKey: order.Key(), Lim: limit, Off: offset})
	if err != nil {
		scanConfigError(w, "list profiles", err)
		return
	}
	total, err := a.Queries.CountProfiles(r.Context())
	if err != nil {
		scanConfigError(w, "count profiles", err)
		return
	}
	items := make([]profileView, len(rows))
	for i, p := range rows {
		items[i] = toProfileView(p)
	}
	httpx.JSON(w, http.StatusOK, list[profileView]{Items: items, Total: total})
}

func (a *api) createProfile(w http.ResponseWriter, r *http.Request) {
	var in scheduler.ProfileInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	profile, err := a.scanConfig().CreateProfile(ctx, auth.UserFrom(ctx), in)
	if err != nil {
		scanConfigError(w, "create profile", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, toProfileView(profile))
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
	profile, err := a.scanConfig().UpdateProfile(ctx, auth.UserFrom(ctx), id, in)
	if err != nil {
		scanConfigError(w, "update profile", err)
		return
	}
	httpx.JSON(w, http.StatusOK, toProfileView(profile))
}

func (a *api) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := a.scanConfig().DeleteProfile(ctx, auth.UserFrom(ctx), id); err != nil {
		scanConfigError(w, "delete profile", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
