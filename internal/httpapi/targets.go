package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Targets (task S1/W1). Stubs until implemented.
func (a *api) mountTargets(r chi.Router) {
	stub(r, "GET", "/targets", auth.PermRead)
	stub(r, "POST", "/targets", auth.PermTargetsWrite)
	stub(r, "POST", "/targets/upload", auth.PermImport)
	stub(r, "DELETE", "/targets/{id}", auth.PermTargetsWrite)
}
