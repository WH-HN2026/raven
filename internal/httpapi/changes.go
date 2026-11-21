package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/changes"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
)

// Run diff and host timeline (task C1; UI is W6).
func (a *api) mountChanges(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/changes", a.getChanges)
	r.With(auth.Require(auth.PermRead)).Get("/changes/hosts/{ip}", a.getHostTimeline)
}

func (a *api) getChanges(w http.ResponseWriter, r *http.Request) {
	from, ok1 := changesRunParam(w, r, "from")
	if !ok1 {
		return
	}
	to, ok2 := changesRunParam(w, r, "to")
	if !ok2 {
		return
	}
	limit, ok := changesIntParam(w, r, "limit", 1000, 1, 5000)
	if !ok {
		return
	}
	c, err := changes.Compare(r.Context(), a.Queries, from, to, limit)
	switch {
	case errors.Is(err, changes.ErrRunNotFound), errors.Is(err, changes.ErrNoRuns):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, changes.ErrSameRun):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	case err != nil:
		slog.Error("compare runs", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "compare runs failed")
	default:
		httpx.JSON(w, http.StatusOK, c)
	}
}

func (a *api) getHostTimeline(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(chi.URLParam(r, "ip"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "ip must be an IP address")
		return
	}
	n, ok := changesIntParam(w, r, "runs", 20, 1, 200)
	if !ok {
		return
	}
	tl, err := changes.HostTimeline(r.Context(), a.Queries, ip.Unmap(), int32(n))
	if err != nil {
		slog.Error("host timeline", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "host timeline failed")
		return
	}
	httpx.JSON(w, http.StatusOK, tl)
}

// changesRunParam reads an optional positive int64 query parameter.
func changesRunParam(w http.ResponseWriter, r *http.Request, name string) (*int64, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		httpx.Error(w, http.StatusBadRequest, "bad_request", name+" must be a run id")
		return nil, false
	}
	return &n, true
}

// changesIntParam reads an optional integer query parameter in [lo, hi].
func changesIntParam(w http.ResponseWriter, r *http.Request, name string, def, lo, hi int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		httpx.Error(w, http.StatusBadRequest, "bad_request", name+" must be "+strconv.Itoa(lo)+".."+strconv.Itoa(hi))
		return 0, false
	}
	return n, true
}
