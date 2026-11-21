package httpapi

import (
	"cmp"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/hosts"
	"github.com/WH-HN2026/raven/internal/httpx"
)

// Services and aggregated technologies (task Q4). Logic lives in internal/hosts.
func (a *api) mountServices(r chi.Router) {
	r.With(auth.Require(auth.PermRead)).Get("/services", a.listServices)
	r.With(auth.Require(auth.PermRead)).Get("/technologies", a.listTechnologies)
}

func (a *api) listServices(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	f, msg := parseServiceListFilter(r)
	if msg != "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	f.Limit, f.Offset = limit, offset
	items, total, err := hosts.ListServices(r.Context(), a.Pool, f)
	if err != nil {
		slog.Error("list services", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "list services failed")
		return
	}
	httpx.JSON(w, http.StatusOK, list[hosts.ServiceItem]{Items: items, Total: total})
}

func parseServiceListFilter(r *http.Request) (hosts.ServiceFilter, string) {
	var f hosts.ServiceFilter
	qs := r.URL.Query()
	if v := strings.TrimSpace(qs.Get("port")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return f, "port must be 0..65535"
		}
		f.Port = &n
	}
	if v := strings.ToLower(strings.TrimSpace(cmp.Or(qs.Get("proto"), qs.Get("protocol")))); v != "" {
		if !slices.Contains(hosts.ServiceProtos, v) {
			return f, "proto must be one of " + strings.Join(hosts.ServiceProtos, ", ")
		}
		f.Proto = v
	}
	if v := strings.ToLower(strings.TrimSpace(qs.Get("state"))); v != "" {
		if !slices.Contains(hosts.ServiceStates, v) {
			return f, "state must be one of " + strings.Join(hosts.ServiceStates, ", ")
		}
		f.State = v
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
	f.Product = strings.TrimSpace(qs.Get("product"))
	f.Technology = strings.TrimSpace(cmp.Or(qs.Get("technology"), qs.Get("tech")))
	f.Version = strings.TrimSpace(qs.Get("version"))
	f.Q = strings.TrimSpace(qs.Get("q"))
	if v := strings.ToLower(strings.TrimSpace(qs.Get("sort"))); v != "" {
		if !slices.Contains(hosts.ServiceSorts, v) {
			return f, "sort must be one of " + strings.Join(hosts.ServiceSorts, ", ")
		}
		f.Sort = v
	}
	if v := strings.ToLower(strings.TrimSpace(qs.Get("order"))); v != "" {
		if !slices.Contains(hosts.SortOrders, v) {
			return f, "order must be one of " + strings.Join(hosts.SortOrders, ", ")
		}
		f.Order = v
	}
	return f, ""
}

func (a *api) listTechnologies(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	f, msg := parseTechnologyFilter(r)
	if msg != "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
		return
	}
	f.Limit, f.Offset = limit, offset
	items, total, err := hosts.ListTechnologies(r.Context(), a.Pool, f)
	if err != nil {
		slog.Error("list technologies", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", "list technologies failed")
		return
	}
	httpx.JSON(w, http.StatusOK, list[hosts.TechnologySummary]{Items: items, Total: total})
}

func parseTechnologyFilter(r *http.Request) (hosts.TechnologyFilter, string) {
	var f hosts.TechnologyFilter
	qs := r.URL.Query()
	if v := strings.ToLower(strings.TrimSpace(qs.Get("state"))); v != "" {
		if !slices.Contains(hosts.TechStates, v) {
			return f, "state must be one of " + strings.Join(hosts.TechStates, ", ")
		}
		f.State = v
	}
	f.Q = strings.TrimSpace(qs.Get("q"))
	if v := strings.ToLower(strings.TrimSpace(qs.Get("sort"))); v != "" {
		if !slices.Contains(hosts.TechSorts, v) {
			return f, "sort must be one of " + strings.Join(hosts.TechSorts, ", ")
		}
		f.Sort = v
	}
	if v := strings.ToLower(strings.TrimSpace(qs.Get("order"))); v != "" {
		if !slices.Contains(hosts.SortOrders, v) {
			return f, "order must be one of " + strings.Join(hosts.SortOrders, ", ")
		}
		f.Order = v
	}
	return f, ""
}
