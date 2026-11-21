package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Run diff (task C1/W6).
func (a *api) mountChanges(r chi.Router) {
	stub(r, "GET", "/changes", auth.PermRead)
}
