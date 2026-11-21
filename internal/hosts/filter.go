// Package hosts is the read path for hosts, services and HTTP observations
// (task W3): the filtered host list, the host detail with decrypted fields,
// and the user overrides layered on top of scan data (architecture §5).
package hosts

import (
	"net/netip"
	"strconv"
	"strings"
)

// States are the valid host states (hosts.state).
var States = []string{"active", "unstable", "inactive"}

// Filter selects hosts for GET /api/hosts. Zero values mean "no filter".
type Filter struct {
	State string // exact, one of States
	Port  *int   // has an open service on this port (any proto)
	Tech  string // in http_observations.technologies of any of its services (case-insensitive)
	Tag   string // in user_tags (exact)
	// Q is an IP/CIDR (containment), otherwise an IP text prefix ("10.0.")
	// or a case-insensitive hostname substring.
	Q      string
	Limit  int32
	Offset int32
}

// buildWhere returns the WHERE clause (with a leading " WHERE ", or empty)
// over hosts aliased h, and its args. Values are always bound as parameters.
func buildWhere(f Filter) (string, []any) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if f.State != "" {
		conds = append(conds, "h.state = "+arg(f.State))
	}
	if f.Port != nil {
		conds = append(conds, "EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND s.state = 'open' AND s.port = "+
			arg(*f.Port)+")")
	}
	if f.Tech != "" {
		conds = append(conds, "EXISTS (SELECT 1 FROM services s JOIN http_observations o ON o.service_id = s.id"+
			" WHERE s.ip = h.ip AND EXISTS (SELECT 1 FROM unnest(o.technologies) AS t WHERE lower(t) = lower("+
			arg(f.Tech)+")))")
	}
	if f.Tag != "" {
		conds = append(conds, arg(f.Tag)+" = ANY(h.user_tags)")
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		if p, ok := parsePrefix(q); ok {
			conds = append(conds, "h.ip <<= "+arg(p.String())+"::inet")
		} else {
			n := arg(q)
			conds = append(conds, "(starts_with(host(h.ip), "+n+") OR EXISTS (SELECT 1 FROM unnest(h.hostnames) AS hn"+
				" WHERE strpos(lower(hn), lower("+n+")) > 0))")
		}
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// parsePrefix accepts "10.0.0.0/24" or a single address (as a /32 or /128).
func parsePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// listColumns are the columns of one list item (see scanItem).
const listColumns = `h.ip, h.hostnames, h.state, h.first_seen, h.last_seen, h.miss_count, h.dojo_asset_id,
	h.owner, h.criticality, h.user_tags, h.overrides,
	(SELECT count(*) FROM services s WHERE s.ip = h.ip AND s.state = 'open') AS open_services,
	ARRAY(SELECT DISTINCT s.port FROM services s WHERE s.ip = h.ip AND s.state = 'open' ORDER BY s.port) AS open_ports,
	ARRAY(SELECT DISTINCT t FROM services s JOIN http_observations o ON o.service_id = s.id,
		unnest(o.technologies) AS t WHERE s.ip = h.ip ORDER BY t) AS technologies`

// buildList returns the page query and the count query; the count query
// uses args without the trailing limit/offset. Paginating in a subquery before
// computing the correlated service/technology aggregates ensures Postgres only
// evaluates them for the returned page, not for all offset+limit rows.
func buildList(f Filter) (list, count string, args []any) {
	where, args := buildWhere(f)
	count = "SELECT count(*) FROM hosts h" + where
	n := len(args)
	list = "SELECT " + listColumns + " FROM (SELECT h.* FROM hosts h" + where +
		" ORDER BY h.ip LIMIT $" + strconv.Itoa(n+1) + " OFFSET $" + strconv.Itoa(n+2) +
		") h ORDER BY h.ip"
	return list, count, append(args, f.Limit, f.Offset)
}
