package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scheduler"
)

func (a *api) mountSchedules(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/schedules", a.listSchedules)
	r.With(auth.Require(auth.PermSchedulesWrite)).Post("/schedules", a.createSchedule)
	r.With(auth.Require(auth.PermSchedulesWrite)).Put("/schedules/{id}", a.updateSchedule)
	r.With(auth.Require(auth.PermSchedulesWrite)).Delete("/schedules/{id}", a.deleteSchedule)
}

func (a *api) scanConfig() scheduler.ConfigStore {
	return scheduler.ConfigStore{
		Pool:           a.Pool,
		ValidateStages: pipeline.Validate,
		DefaultStages:  pipeline.DefaultStages,
		IsAggressive:   pipeline.IsAggressive,
	}
}

type scheduleView struct {
	gen.Schedule
	DojoURL string `json:"dojo_url"`
}

func (a *api) scheduleView(s gen.Schedule) scheduleView {
	var u string
	if s.Source == "dojo" && s.DojoEngagementID != nil {
		u = dojo.EngagementURL(a.DojoPublicURL, *s.DojoEngagementID)
	}
	return scheduleView{Schedule: s, DojoURL: u}
}

func scanConfigError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, scheduler.ErrForbidden):
		httpx.Error(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, scheduler.ErrInvalid):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, scheduler.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, scheduler.ErrConflict):
		httpx.Error(w, http.StatusConflict, "conflict", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", op+" failed")
	}
}

func (a *api) listSchedules(w http.ResponseWriter, r *http.Request) {
	order, ok := listOrder(w, r, "name", "profile", "source", "repeats", "window", "next_window", "timezone", "enabled")
	if !ok {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	rows, total, err := a.scanConfig().ListSchedules(ctx, limit, offset, order)
	if err != nil {
		scanConfigError(w, "list schedules", err)
		return
	}
	items := make([]scheduleView, len(rows))
	for i, s := range rows {
		items[i] = a.scheduleView(s)
	}
	httpx.JSON(w, http.StatusOK, list[scheduleView]{Items: items, Total: total})
}

func (a *api) createSchedule(w http.ResponseWriter, r *http.Request) {
	var in scheduler.ScheduleInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	schedule, err := a.scanConfig().CreateSchedule(ctx, auth.UserFrom(ctx), in)
	if err != nil {
		scanConfigError(w, "create schedule", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, a.scheduleView(schedule))
}

func (a *api) updateSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in scheduler.ScheduleInput
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	schedule, err := a.scanConfig().UpdateSchedule(ctx, auth.UserFrom(ctx), id, in)
	if err != nil {
		scanConfigError(w, "update schedule", err)
		return
	}
	httpx.JSON(w, http.StatusOK, a.scheduleView(schedule))
}

func (a *api) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := a.scanConfig().DeleteSchedule(ctx, auth.UserFrom(ctx), id); err != nil {
		scanConfigError(w, "delete schedule", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
