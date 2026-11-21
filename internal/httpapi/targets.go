package httpapi

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/targets"
)

// Targets (task S1). Logic lives in internal/targets.
func (a *api) mountTargets(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/targets", a.listTargets)
	r.With(auth.Require(auth.PermTargetsWrite)).Post("/targets", a.createTargets)
	r.With(auth.Require(auth.PermImport)).Post("/targets/upload", a.uploadTargets)
	r.With(auth.Require(auth.PermTargetsWrite)).Delete("/targets/{id}", a.deleteTarget)
}

func (a *api) targetStore() *targets.Store { return &targets.Store{Pool: a.Pool} }

type list[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
}

// pageParams reads ?limit=&offset= (default 50, max 1000).
func pageParams(w http.ResponseWriter, r *http.Request) (limit, offset int32, ok bool) {
	limit = 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 1 || n > 1000 {
			httpx.Error(w, http.StatusBadRequest, "bad_request", "limit must be 1..1000")
			return 0, 0, false
		}
		limit = int32(n)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 0 {
			httpx.Error(w, http.StatusBadRequest, "bad_request", "offset must be >= 0")
			return 0, 0, false
		}
		offset = int32(n)
	}
	return limit, offset, true
}

func idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid id")
		return 0, false
	}
	return id, true
}

// targetsError maps domain errors to HTTP statuses.
func targetsError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, targets.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, targets.ErrForbidden):
		httpx.Error(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, targets.ErrConflict):
		httpx.Error(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, targets.ErrInvalid):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", op+" failed")
	}
}

func (a *api) listTargets(w http.ResponseWriter, r *http.Request) {
	order, ok := listOrder(w, r, "value", "kind", "source", "tags", "note", "created_at")
	if !ok {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	items, total, err := a.targetStore().ListTargets(r.Context(), limit, offset, order)
	if err != nil {
		targetsError(w, "list targets", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[gen.Target]{Items: items, Total: total})
}

// createTargets: manual entry. All values must be valid, otherwise nothing is
// written and the response is 400 with the per-item errors (line = 1-based index).
// An existing target returns 409 and rolls back the whole request.
func (a *api) createTargets(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Targets []struct {
			Value string       `json:"value"`
			Kind  targets.Kind `json:"kind"`
			Tags  []string     `json:"tags"`
			Note  string       `json:"note"`
		} `json:"targets"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	if len(in.Targets) == 0 {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "targets must not be empty")
		return
	}
	var entries []targets.Entry
	var errs []targets.LineError
	for i, t := range in.Targets {
		e, err := targets.NewEntry(t.Value, t.Kind, t.Tags, t.Note)
		if err != nil {
			errs = append(errs, targets.LineError{Line: i + 1, Message: err.Error()})
			continue
		}
		entries = append(entries, e)
	}
	if len(errs) > 0 {
		httpx.JSON(w, http.StatusBadRequest, map[string]any{
			"error":  httpx.ErrorDetail{Code: "invalid_targets", Message: errs[0].Message},
			"errors": errs,
		})
		return
	}
	created, err := a.targetStore().AddTargets(r.Context(), auth.UserFrom(r.Context()), "manual", entries)
	if err != nil {
		targetsError(w, "add targets", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, list[gen.Target]{Items: created, Total: int64(len(created))})
}

type uploadResult struct {
	*targets.Parsed
	Source  string `json:"source"`
	DryRun  bool   `json:"dry_run"`
	Created int    `json:"created"`
}

// uploadTargets: multipart field "file" (CSV or JSON). dry_run=true only
// parses. Otherwise the valid entries are stored and the bad lines reported.
func (a *api) uploadTargets(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true" || r.URL.Query().Get("dry_run") == "1"
	r.Body = http.MaxBytesReader(w, r.Body, targets.MaxUploadBytes+64<<10)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "multipart field \"file\" is required: "+err.Error())
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, targets.MaxUploadBytes+1))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "read upload: "+err.Error())
		return
	}
	if len(data) > targets.MaxUploadBytes {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "too_large", "upload is larger than 10 MiB")
		return
	}
	parsed, source := targets.ParseUpload(hdr.Filename, data)
	res := uploadResult{Parsed: parsed, Source: source, DryRun: dryRun}
	if !dryRun && len(parsed.Entries) > 0 {
		created, err := a.targetStore().AddTargets(r.Context(), auth.UserFrom(r.Context()), source, parsed.Entries)
		if err != nil {
			targetsError(w, "import targets", err)
			return
		}
		res.Created = len(created)
	}
	httpx.JSON(w, http.StatusOK, res)
}

func (a *api) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := a.targetStore().DeleteTarget(r.Context(), auth.UserFrom(r.Context()), id); err != nil {
		targetsError(w, "delete target", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
