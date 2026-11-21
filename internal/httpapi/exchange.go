package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Import / export (task P3).
func (a *api) mountExchange(r chi.Router) {
	stub(r, "POST", "/import/results", auth.PermImport)
	stub(r, "GET", "/export/{kind}", auth.PermExport)
}
