package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Findings from the Dojo mirror (task D3/D6/W5).
func (a *api) mountFindings(r chi.Router) {
	stub(r, "GET", "/findings", auth.PermRead)
	stub(r, "PATCH", "/findings/{id}", auth.PermFindingsEdit)
	stub(r, "POST", "/findings/{id}/notes", auth.PermFindingsEdit)
}
