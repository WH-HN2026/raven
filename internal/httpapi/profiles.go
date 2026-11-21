package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
)

// Scan profiles (task W7). The read-only list exists for the Runs page (W2).
func (a *api) mountProfiles(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/profiles", a.listProfiles)
	stub(r, "POST", "/profiles", auth.PermProfilesWrite)
	stub(r, "PUT", "/profiles/{id}", auth.PermProfilesWrite)
	stub(r, "DELETE", "/profiles/{id}", auth.PermProfilesWrite)
}

func (a *api) listProfiles(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	items, err := a.Queries.ListProfiles(r.Context(), gen.ListProfilesParams{Limit: limit, Offset: offset})
	if err != nil {
		slog.Error("list profiles", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "list profiles failed")
		return
	}
	total, err := a.Queries.CountProfiles(r.Context())
	if err != nil {
		slog.Error("count profiles", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "list profiles failed")
		return
	}
	httpx.JSON(w, http.StatusOK, list[gen.Profile]{Items: items, Total: total})
}
