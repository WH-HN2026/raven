package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/httpx"
)

// Findings from the Dojo mirror (task D3/D6/W5).
func (a *api) mountFindings(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/findings", a.listFindings)
	r.With(auth.Require(auth.PermFindingsEdit)).Patch("/findings/{id}", a.updateFinding)
	r.With(auth.Require(auth.PermFindingsEdit)).Post("/findings/{id}/notes", a.addFindingNote)
}

// findingsError maps write-through errors to HTTP statuses.
func findingsError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, dojo.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, dojo.ErrInvalid):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, dojo.ErrNotReady):
		httpx.Error(w, http.StatusServiceUnavailable, "dojo_not_ready", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusBadGateway, "dojo_error", op+" failed")
	}
}

// actorID is the audit_log user of the request.
func actorID(r *http.Request) *int64 {
	if u := auth.UserFrom(r.Context()); u != nil {
		return &u.ID
	}
	return nil
}

// updateFinding: PATCH Dojo, then the mirror row (D6).
func (a *api) updateFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var p dojo.FindingPatch
	if !httpx.DecodeJSON(w, r, &p) {
		return
	}
	f, err := dojo.EditFinding(r.Context(), a.Pool, a.Dojo.Get(), actorID(r), id, p, a.DojoPublicURL)
	if err != nil {
		findingsError(w, "update finding", err)
		return
	}
	httpx.JSON(w, http.StatusOK, f)
}

func (a *api) addFindingNote(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Text string `json:"text"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	if err := dojo.AddNote(r.Context(), a.Pool, a.Dojo.Get(), actorID(r), id, in.Text); err != nil {
		findingsError(w, "add finding note", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listFindings reads only the mirror (dojo_findings), never Dojo.
func (a *api) listFindings(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	f, msg := parseFindingFilter(r)
	if msg != "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	f.Limit, f.Offset = limit, offset
	items, total, err := dojo.ListMirrorFindings(r.Context(), a.Pool, f, a.DojoPublicURL)
	if err != nil {
		slog.Error("list findings", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "list findings failed")
		return
	}
	httpx.JSON(w, http.StatusOK, list[dojo.MirrorFinding]{Items: items, Total: total})
}

// parseFindingFilter reads severity (repeatable and/or comma-separated,
// case-insensitive), active, ip (address or CIDR), q and scanner.
func parseFindingFilter(r *http.Request) (dojo.FindingFilter, string) {
	var f dojo.FindingFilter
	qs := r.URL.Query()
	for _, v := range qs["severity"] {
		for s := range strings.SplitSeq(v, ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			i := slices.IndexFunc(dojo.Severities, func(x string) bool { return strings.EqualFold(x, s) })
			if i < 0 {
				return f, "severity must be one of " + strings.Join(dojo.Severities, ", ")
			}
			f.Severities = append(f.Severities, dojo.Severities[i])
		}
	}
	if v := qs.Get("active"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return f, "active must be true or false"
		}
		f.Active = &b
	}
	if v := strings.TrimSpace(qs.Get("ip")); v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			addr, aerr := netip.ParseAddr(v)
			if aerr != nil {
				return f, "ip must be an IP address or CIDR"
			}
			addr = addr.Unmap()
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		f.IP = &p
	}
	f.Q = strings.TrimSpace(qs.Get("q"))
	f.Scanner = strings.TrimSpace(qs.Get("scanner"))
	return f, ""
}
