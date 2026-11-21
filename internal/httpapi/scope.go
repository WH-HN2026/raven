package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Scope include/exclude lists (task S1/W1). Global entries (profile_id null)
// additionally need auth.PermGlobalScope, checked in the handler.
func (a *api) mountScope(r chi.Router) {
	stub(r, "GET", "/scope", auth.PermRead)
	stub(r, "POST", "/scope", auth.PermScopeWrite)
	stub(r, "DELETE", "/scope/{id}", auth.PermScopeWrite)
}
