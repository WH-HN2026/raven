package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/pipeline"
)

// Runs and batches (task S3). Logic lives in internal/pipeline.
func (a *api) mountRuns(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/runs", a.listRuns)
	r.With(auth.Require(auth.PermRunsControl)).Post("/runs", a.startRun)
	r.With(auth.Require(auth.PermRead)).Get("/runs/{id}", a.getRun)
	r.With(auth.Require(auth.PermRead)).Get("/runs/{id}/batches", a.listRunBatches)
	r.With(auth.Require(auth.PermRunsControl)).Post("/runs/{id}/stop", a.stopRun)
}

func runsError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, pipeline.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, pipeline.ErrConflict):
		httpx.Error(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, pipeline.ErrInvalid):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", op+" failed")
	}
}

// pipelineReady answers 503 when the server runs without scan workers.
func (a *api) pipelineReady(w http.ResponseWriter) bool {
	if a.Pipeline == nil {
		httpx.Error(w, http.StatusServiceUnavailable, "unavailable", "scan pipeline is not running")
		return false
	}
	return true
}

func (a *api) listRuns(w http.ResponseWriter, r *http.Request) {
	if !a.pipelineReady(w) {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	var profileID *int64
	if v := r.URL.Query().Get("profile_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid profile_id")
			return
		}
		profileID = &n
	}
	items, total, err := a.Pipeline.ListRuns(r.Context(), profileID, limit, offset)
	if err != nil {
		runsError(w, "list runs", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[pipeline.Run]{Items: items, Total: total})
}

func (a *api) startRun(w http.ResponseWriter, r *http.Request) {
	if !a.pipelineReady(w) {
		return
	}
	var in struct {
		ProfileID int64 `json:"profile_id"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	run, err := a.Pipeline.StartRun(r.Context(), auth.UserFrom(r.Context()), in.ProfileID)
	if err != nil {
		runsError(w, "start run", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, run)
}

func (a *api) getRun(w http.ResponseWriter, r *http.Request) {
	if !a.pipelineReady(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	run, err := a.Pipeline.GetRun(r.Context(), id)
	if err != nil {
		runsError(w, "get run", err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

func (a *api) listRunBatches(w http.ResponseWriter, r *http.Request) {
	if !a.pipelineReady(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	items, err := a.Pipeline.ListBatches(r.Context(), id)
	if err != nil {
		runsError(w, "list batches", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[pipeline.Batch]{Items: items, Total: int64(len(items))})
}

func (a *api) stopRun(w http.ResponseWriter, r *http.Request) {
	if !a.pipelineReady(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	run, err := a.Pipeline.StopRun(r.Context(), auth.UserFrom(r.Context()), id)
	if err != nil {
		runsError(w, "stop run", err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}
