package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Custom nuclei signatures (task C2/W8).
func (a *api) mountSignatures(r chi.Router) {
	stub(r, "GET", "/signatures", auth.PermRead)
	stub(r, "POST", "/signatures", auth.PermSignaturesWrite)
	stub(r, "PUT", "/signatures/{id}", auth.PermSignaturesWrite)
	stub(r, "DELETE", "/signatures/{id}", auth.PermSignaturesWrite)
	stub(r, "POST", "/signatures/validate", auth.PermSignaturesWrite)
}
