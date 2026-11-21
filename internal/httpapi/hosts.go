package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/hosts"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
)

// Hosts, services and HTTP observations (task W3; edits are W10).
func (a *api) mountHosts(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/hosts", a.listHosts)
	r.With(auth.Require(auth.PermRead)).Get("/hosts/{ip}", a.getHost)
	r.With(auth.Require(auth.PermHostsEdit)).Patch("/hosts/{ip}", a.updateHost)
	stub(r, "GET", "/services", auth.PermRead)
	r.With(auth.Require(auth.PermHostsEdit)).Patch("/services/{id}", a.updateService)
}

func hostsError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, hosts.ErrNotFound), errors.Is(err, hosts.ErrServiceNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, hosts.ErrInvalid):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", op+" failed")
	}
}

// updateHost edits user-owned fields, then writes them through to the
// IP's Dojo asset (D6).
func (a *api) updateHost(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(chi.URLParam(r, "ip"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "ip must be an IP address")
		return
	}
	var p hosts.Patch
	if !httpx.DecodeJSON(w, r, &p) {
		return
	}
	res, err := hosts.Edit(r.Context(), a.Pool, a.Dojo.Get(), actorID(r), ip, p)
	if err != nil {
		hostsError(w, "update host", err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// updateService writes services.overrides only.
func (a *api) updateService(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Overrides map[string]json.RawMessage `json:"overrides"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	s, err := hosts.EditServiceOverrides(r.Context(), a.Pool, actorID(r), id, in.Overrides)
	if err != nil {
		hostsError(w, "update service", err)
		return
	}
	httpx.JSON(w, http.StatusOK, s)
}

func (a *api) listHosts(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	f, msg := parseHostFilter(r)
	if msg != "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	f.Limit, f.Offset = limit, offset
	items, total, err := hosts.List(r.Context(), a.Pool, f)
	if err != nil {
		slog.Error("list hosts", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "list hosts failed")
		return
	}
	httpx.JSON(w, http.StatusOK, list[hosts.Host]{Items: items, Total: total})
}

// parseHostFilter reads state, port, tech, tag and q.
func parseHostFilter(r *http.Request) (hosts.Filter, string) {
	var f hosts.Filter
	qs := r.URL.Query()
	if v := strings.TrimSpace(qs.Get("state")); v != "" {
		if !slices.Contains(hosts.States, v) {
			return f, "state must be one of " + strings.Join(hosts.States, ", ")
		}
		f.State = v
	}
	if v := strings.TrimSpace(qs.Get("port")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return f, "port must be 0..65535"
		}
		f.Port = &n
	}
	f.Tech = strings.TrimSpace(qs.Get("tech"))
	f.Tag = strings.TrimSpace(qs.Get("tag"))
	f.Q = strings.TrimSpace(qs.Get("q"))
	return f, ""
}

func (a *api) getHost(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(chi.URLParam(r, "ip"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad_request", "ip must be an IP address")
		return
	}
	d, err := hosts.Get(r.Context(), a.Pool, ip)
	switch {
	case errors.Is(err, hosts.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", "host not found")
	case err != nil:
		slog.Error("get host", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "get host failed")
	default:
		httpx.JSON(w, http.StatusOK, d)
	}
}
