package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Scan profiles (task W7).
func (a *api) mountProfiles(r chi.Router) {
	stub(r, "GET", "/profiles", auth.PermRead)
	stub(r, "POST", "/profiles", auth.PermProfilesWrite)
	stub(r, "PUT", "/profiles/{id}", auth.PermProfilesWrite)
	stub(r, "DELETE", "/profiles/{id}", auth.PermProfilesWrite)
}
