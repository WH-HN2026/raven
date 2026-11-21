package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dashboard"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
)

// Dashboard overview (task W4), read-only.
func (a *api) mountDashboard(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/dashboard", a.getDashboard)
}

func (a *api) getDashboard(w http.ResponseWriter, r *http.Request) {
	d, err := dashboard.Get(r.Context(), a.Queries)
	if err != nil {
		slog.Error("dashboard", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "dashboard failed")
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}
