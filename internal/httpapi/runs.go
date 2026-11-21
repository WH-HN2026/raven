package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Runs and batches (task S3/W2).
func (a *api) mountRuns(r chi.Router) {
	stub(r, "GET", "/runs", auth.PermRead)
	stub(r, "POST", "/runs", auth.PermRunsControl)
	stub(r, "GET", "/runs/{id}", auth.PermRead)
	stub(r, "GET", "/runs/{id}/batches", auth.PermRead)
	stub(r, "POST", "/runs/{id}/stop", auth.PermRunsControl)
}
