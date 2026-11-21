package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Hosts, services and HTTP observations (task S3/W3/W10).
func (a *api) mountHosts(r chi.Router) {
	stub(r, "GET", "/hosts", auth.PermRead)
	stub(r, "GET", "/hosts/{ip}", auth.PermRead)
	stub(r, "PATCH", "/hosts/{ip}", auth.PermHostsEdit)
	stub(r, "GET", "/services", auth.PermRead)
	stub(r, "PATCH", "/services/{id}", auth.PermHostsEdit)
}
