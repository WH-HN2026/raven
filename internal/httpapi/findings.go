package httpapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dojo"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
)

// Findings from the Dojo mirror (task D3/D6/W5).
func (a *api) mountFindings(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/findings", a.listFindings)
	stub(r, "PATCH", "/findings/{id}", auth.PermFindingsEdit)
	stub(r, "POST", "/findings/{id}/notes", auth.PermFindingsEdit)
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
