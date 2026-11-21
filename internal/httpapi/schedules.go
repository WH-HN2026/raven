package httpapi

import (
	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

// Schedules from the UI and Dojo (task P1/D5/W7).
func (a *api) mountSchedules(r chi.Router) {
	stub(r, "GET", "/schedules", auth.PermRead)
	stub(r, "POST", "/schedules", auth.PermSchedulesWrite)
	stub(r, "PUT", "/schedules/{id}", auth.PermSchedulesWrite)
	stub(r, "DELETE", "/schedules/{id}", auth.PermSchedulesWrite)
}
