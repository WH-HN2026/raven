package httpapi

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/httpx"
)

func parseListOrder(q url.Values, columns []string, legacyOrder bool) (db.ListOrder, string) {
	order := db.ListOrder{Column: q.Get("sort"), Direction: q.Get("dir")}
	if legacyOrder {
		order.Column = strings.ToLower(strings.TrimSpace(order.Column))
		if order.Direction == "" {
			order.Direction = strings.ToLower(strings.TrimSpace(q.Get("order")))
		}
	}
	if order.Column != "" && !slices.Contains(columns, order.Column) {
		return order, "sort must be one of " + strings.Join(columns, ", ")
	}
	if order.Direction != "" && order.Direction != "asc" && order.Direction != "desc" {
		return order, "dir must be asc or desc"
	}
	return order, ""
}

func listOrder(w http.ResponseWriter, r *http.Request, columns ...string) (db.ListOrder, bool) {
	order, msg := parseListOrder(r.URL.Query(), columns, false)
	if msg != "" {
		httpx.Error(w, http.StatusBadRequest, "bad_request", msg)
	}
	return order, msg == ""
}
