package httpapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/cve"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/httpx"
)

// Offline CVE matches (task C3), read-only; the hosts tag in openapi.
func (a *api) mountCVE(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/cve-matches", a.listCVEMatches)
}

func (a *api) listCVEMatches(w http.ResponseWriter, r *http.Request) {
	var ip netip.Addr
	if v := strings.TrimSpace(r.URL.Query().Get("ip")); v != "" {
		var err error
		if ip, err = netip.ParseAddr(v); err != nil {
			httpx.Error(w, http.StatusBadRequest, "bad_request", "ip must be an IP address")
			return
		}
	}
	items, err := cve.List(r.Context(), a.Pool, ip)
	if err != nil {
		slog.Error("list cve matches", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "list cve matches failed")
		return
	}
	httpx.JSON(w, http.StatusOK, list[cve.Match]{Items: items, Total: int64(len(items))})
}
