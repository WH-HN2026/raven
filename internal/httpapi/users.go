package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// User administration (task P2/W9).
func (a *api) mountUsers(r chi.Router) {
	stub(r, "GET", "/users", auth.PermUsersAdmin)
	stub(r, "POST", "/users", auth.PermUsersAdmin)
	stub(r, "PATCH", "/users/{id}", auth.PermUsersAdmin)
	stub(r, "DELETE", "/users/{id}", auth.PermUsersAdmin)
}
