package hosts

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
)

// Valid enum values for GET /api/services and GET /api/technologies.
var (
	ServiceStates = []string{"open", "gone"}
	ServiceProtos = []string{"tcp", "udp"}
	ServiceSorts  = []string{"ip", "port", "name", "product", "version", "state", "technologies", "cves", "first_seen", "last_seen"}
	TechStates    = []string{"open", "gone", "all"}
	TechSorts     = []string{"hosts", "services", "technology", "version", "cves"}
)

// ServiceFilter selects services for GET /api/services (and service export).
// Zero values mean "no filter".
type ServiceFilter struct {
	Port       *int
	Proto      string // tcp | udp
	Product    string // case-insensitive substring of effective product
	Technology string // case-insensitive substring of detected technology or effective product
	Version    string // case-insensitive substring of effective version or tech:version
	State      string // open | gone
	IP         *netip.Prefix
	Q          string // IP/CIDR, IP prefix, hostname, service name/product/version, CPE, or technology
	Sort       string // one of ServiceSorts (default "ip")
	Order      string // asc | desc (default "asc")
	Limit      int32
	Offset     int32
}

// ServiceItem is one row returned by GET /api/services.
type ServiceItem struct {
	Service
	Hostnames    []string `json:"hostnames"`
	Technologies []string `json:"technologies"`
	CVECount     int      `json:"cve_count"`
	CVESeverity  string   `json:"cve_severity"`
	// ResponseMS is the slowest latest HTTP response time of the service (V7).
	ResponseMS *int32 `json:"response_ms"`
	Slow       bool   `json:"slow"`
}

// TechnologyFilter selects technology aggregates for GET /api/technologies.
type TechnologyFilter struct {
	State  string // open (default) | gone | all
	Q      string // case-insensitive substring of technology or version
	Sort   string // hosts (default) | services | technology | cves
	Order  string // asc | desc (default: desc for numeric sorts, asc for technology)
	Limit  int32
	Offset int32
}

// TechnologySummary is one aggregated (technology, version) row for GET /api/technologies.
type TechnologySummary struct {
	Technology    string `json:"technology"`
	Version       string `json:"version"`
	HostCount     int    `json:"host_count"`
	ServiceCount  int    `json:"service_count"`
	CVEMatchCount int    `json:"cve_match_count"`
	CVECount      int    `json:"cve_count"`
	MaxSeverity   string `json:"max_severity"`
}

// Effective service field SQL expressions (overrides layered on scan values).
const (
	effNameExpr    = `COALESCE(NULLIF(s.overrides->>'name', ''), s.name)`
	effProductExpr = `COALESCE(NULLIF(s.overrides->>'product', ''), s.product)`
	effVersionExpr = `COALESCE(NULLIF(s.overrides->>'version', ''), s.version)`
)

// servicesCTE joins services with latest HTTP observation technologies per service.
const servicesCTE = `WITH latest_http AS (
	SELECT DISTINCT ON (o.service_id, o.url) o.id, o.service_id, o.url, o.observed_at, o.run_id, o.technologies, o.response_ms
	FROM http_observations o
	ORDER BY o.service_id, o.url, o.observed_at DESC, o.id DESC
), svc_tech AS (
	SELECT lh.service_id, array_agg(DISTINCT t ORDER BY t) AS technologies
	FROM latest_http lh
	CROSS JOIN LATERAL unnest(lh.technologies) AS t
	GROUP BY lh.service_id
), svc_resp AS (
	-- V7: the slowest URL of each service in its latest HTTP run (URLs not probed
	-- in that run are stale) and that URL's previous response time.
	SELECT DISTINCT ON (lh.service_id) lh.service_id, lh.response_ms,
		(SELECT p.response_ms FROM http_observations p
		 WHERE p.service_id = lh.service_id AND p.url = lh.url AND (p.observed_at, p.id) < (lh.observed_at, lh.id)
		 ORDER BY p.observed_at DESC, p.id DESC LIMIT 1) AS prev_response_ms
	FROM (
		SELECT l.*, first_value(l.run_id) OVER (PARTITION BY l.service_id ORDER BY l.observed_at DESC, l.id DESC) AS last_run
		FROM latest_http l
	) lh
	WHERE lh.response_ms IS NOT NULL AND lh.run_id IS NOT DISTINCT FROM lh.last_run
	ORDER BY lh.service_id, lh.response_ms DESC
)`

const servicesBaseFrom = ` FROM services s
JOIN hosts h ON h.ip = s.ip
LEFT JOIN svc_tech st ON st.service_id = s.id`

// servicesFrom aggregates the per-product cve_matches rows of a port into one
// row per service (a port can carry several products, e.g. nmap + httpx).
const servicesFrom = servicesBaseFrom + `
LEFT JOIN LATERAL (
	SELECT ARRAY(
		SELECT DISTINCT id FROM cve_matches m, unnest(m.cve_ids) AS id
		WHERE m.ip = s.ip AND m.port = s.port AND m.proto = s.proto ORDER BY id
	) AS cve_ids,
	(
		SELECT m.severity FROM cve_matches m
		WHERE m.ip = s.ip AND m.port = s.port AND m.proto = s.proto
		ORDER BY CASE m.severity WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3
			WHEN 'Low' THEN 2 WHEN 'Info' THEN 1 ELSE 0 END DESC
		LIMIT 1
	) AS severity
) cm ON true`

// techFrom keeps one row per (service, CVE-matched product) so ListTechnologies
// can attribute each match to the technology it belongs to.
const techFrom = servicesBaseFrom + `
LEFT JOIN cve_matches cm ON cm.ip = s.ip AND cm.port = s.port AND cm.proto = s.proto`

func buildServiceWhere(f ServiceFilter) (string, []any) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if f.Port != nil {
		conds = append(conds, "s.port = "+arg(*f.Port))
	}
	if f.Proto != "" {
		conds = append(conds, "s.proto = "+arg(f.Proto))
	}
	if f.State != "" {
		conds = append(conds, "s.state = "+arg(f.State))
	}
	if f.IP != nil {
		conds = append(conds, "s.ip <<= "+arg(f.IP.Masked().String())+"::inet")
	}
	if f.Product != "" {
		conds = append(conds, "strpos(lower("+effProductExpr+"), lower("+arg(f.Product)+")) > 0")
	}
	if f.Technology != "" {
		n := arg(f.Technology)
		conds = append(conds, "(EXISTS (SELECT 1 FROM unnest(COALESCE(st.technologies, '{}')) AS t WHERE strpos(lower(t), lower("+n+")) > 0) OR strpos(lower("+effProductExpr+"), lower("+n+")) > 0)")
	}
	if f.Version != "" {
		n := arg(f.Version)
		conds = append(conds, "(strpos(lower("+effVersionExpr+"), lower("+n+")) > 0 OR EXISTS (SELECT 1 FROM unnest(COALESCE(st.technologies, '{}')) AS t WHERE strpos(lower(t), ':' || lower("+n+")) > 0))")
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		if p, ok := parsePrefix(q); ok {
			conds = append(conds, "s.ip <<= "+arg(p.String())+"::inet")
		} else {
			n := arg(q)
			conds = append(conds, "(starts_with(host(s.ip), "+n+")"+
				" OR EXISTS (SELECT 1 FROM unnest(h.hostnames) AS hn WHERE strpos(lower(hn), lower("+n+")) > 0)"+
				" OR strpos(lower("+effNameExpr+"), lower("+n+")) > 0"+
				" OR strpos(lower("+effProductExpr+"), lower("+n+")) > 0"+
				" OR strpos(lower("+effVersionExpr+"), lower("+n+")) > 0"+
				" OR strpos(lower(s.cpe), lower("+n+")) > 0"+
				" OR EXISTS (SELECT 1 FROM unnest(COALESCE(st.technologies, '{}')) AS t WHERE strpos(lower(t), lower("+n+")) > 0))")
		}
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// serviceOrderBy returns a safe ORDER BY clause from allowlisted constants.
func serviceOrderBy(sort, order string) string {
	dir := "ASC"
	if order == "desc" {
		dir = "DESC"
	}
	column := "s.ip"
	switch sort {
	case "port":
		return "s.port " + dir + ", s.proto " + dir + ", s.ip, s.id"
	case "name":
		column = "lower(" + effNameExpr + ")"
	case "product":
		return "lower(" + effProductExpr + ") " + dir + ", lower(" + effVersionExpr + ") " + dir + ", s.ip, s.port, s.id"
	case "version":
		return "lower(" + effVersionExpr + ") " + dir + ", lower(" + effProductExpr + ") ASC, s.ip, s.port, s.id"
	case "state":
		column = "s.state"
	case "technologies":
		column = "COALESCE(st.technologies, '{}')"
	case "cves":
		column = "COALESCE(cardinality(cm.cve_ids), 0)"
	case "first_seen":
		column = "s.first_seen"
	case "last_seen":
		column = "s.last_seen"
	}
	return column + " " + dir + ", s.ip, s.port, s.proto, s.id"
}

func buildServiceList(f ServiceFilter) (list, count string, args []any) {
	where, args := buildServiceWhere(f)
	count = servicesCTE + " SELECT count(*)" + servicesFrom + where
	n := len(args)
	list = servicesCTE + ` SELECT s.id, s.ip, s.port, s.proto, s.name, s.product, s.version, s.cpe,
		COALESCE(raven_dec(s.banner_enc), '')::text AS banner,
		s.state, s.first_seen, s.last_seen, s.overrides,
		h.hostnames, COALESCE(st.technologies, '{}')::text[] AS technologies,
		COALESCE(cardinality(cm.cve_ids), 0)::int AS cve_count,
		COALESCE(cm.severity, '')::text AS cve_severity,
		(SELECT sr.response_ms FROM svc_resp sr WHERE sr.service_id = s.id) AS response_ms,
		(SELECT sr.prev_response_ms FROM svc_resp sr WHERE sr.service_id = s.id) AS prev_response_ms` +
		servicesFrom + where +
		" ORDER BY " + serviceOrderBy(f.Sort, f.Order) +
		" LIMIT $" + strconv.Itoa(n+1) + " OFFSET $" + strconv.Itoa(n+2)
	return list, count, append(args, f.Limit, f.Offset)
}

// ListServices returns one filtered, sorted page of services and the total count.
// Decrypted banners must never be logged.
func ListServices(ctx context.Context, pool *pgxpool.Pool, f ServiceFilter) ([]ServiceItem, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list, count, args := buildServiceList(f)
	var total int64
	if err := pool.QueryRow(ctx, count, args[:len(args)-2]...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count services: %w", err)
	}
	rows, err := pool.Query(ctx, list, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list services: %w", err)
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ServiceItem, error) {
		var (
			id          int64
			ip          netip.Addr
			port        int32
			proto       string
			name        string
			product     string
			version     string
			cpeStr      string
			banner      string
			state       string
			firstSeen   time.Time
			lastSeen    time.Time
			overrides   []byte
			hostnames   []string
			techs       []string
			cveCount    int
			cveSeverity string
			respMS      *int32
			prevMS      *int32
		)
		if err := r.Scan(&id, &ip, &port, &proto, &name, &product, &version, &cpeStr, &banner,
			&state, &firstSeen, &lastSeen, &overrides, &hostnames, &techs, &cveCount, &cveSeverity,
			&respMS, &prevMS); err != nil {
			return ServiceItem{}, err
		}
		scan := ServiceFields{Name: name, Product: product, Version: version}
		eff, over := applyServiceOverrides(scan, overrides)
		if hostnames == nil {
			hostnames = []string{}
		}
		if techs == nil {
			techs = []string{}
		}
		return ServiceItem{
			Service: Service{
				ID: id, IP: ip, Port: port, Proto: proto,
				Name: eff.Name, Product: eff.Product, Version: eff.Version, CPE: cpeStr,
				Scan: scan, Overridden: over, Banner: banner, State: state,
				FirstSeen: firstSeen, LastSeen: lastSeen, Overrides: objectOrEmpty(overrides),
			},
			Hostnames: hostnames, Technologies: techs, CVECount: cveCount, CVESeverity: cveSeverity,
			ResponseMS: respMS, Slow: slow(respMS, prevMS),
		}, nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list services: %w", err)
	}
	if items == nil {
		items = []ServiceItem{}
	}
	return items, total, nil
}

// SplitTechVersion splits a technology string such as "WordPress:6.4.2" into
// ("WordPress", "6.4.2"). Strings without a version suffix (or where the suffix
// does not start with a digit) return (raw, "").
func SplitTechVersion(raw string) (tech, version string) {
	raw = strings.TrimSpace(raw)
	if i := strings.LastIndex(raw, ":"); i > 0 && i+1 < len(raw) && raw[i+1] >= '0' && raw[i+1] <= '9' {
		return strings.TrimSpace(raw[:i]), strings.TrimSpace(raw[i+1:])
	}
	return raw, ""
}

func normTechKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sevRank(s string) int {
	switch s {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Info":
		return 1
	default:
		return 0
	}
}

type techRow struct {
	serviceID   int64
	ip          netip.Addr
	product     string
	version     string
	techs       []string
	cveCPE      string
	cveProduct  string
	serviceCPE  string
	cveIDs      []string
	cveSeverity string
}

// ListTechnologies aggregates detected technologies + versions across services,
// computing distinct host counts, service counts, and CVE match counts.
func ListTechnologies(ctx context.Context, pool *pgxpool.Pool, f TechnologyFilter) ([]TechnologySummary, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	state := f.State
	if state == "" {
		state = "open"
	}
	var args []any
	where := ""
	if state != "all" {
		args = append(args, state)
		where = " WHERE s.state = $1"
	}
	q := servicesCTE + ` SELECT s.id, s.ip, ` + effProductExpr + `, ` + effVersionExpr + `,
		COALESCE(st.technologies, '{}')::text[],
		COALESCE(cm.cpe, '')::text, COALESCE(cm.product, '')::text, s.cpe,
		COALESCE(cm.cve_ids, '{}')::text[], COALESCE(cm.severity, '')::text` +
		techFrom + where
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list technologies: %w", err)
	}
	raw, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (techRow, error) {
		var tr techRow
		err := r.Scan(&tr.serviceID, &tr.ip, &tr.product, &tr.version, &tr.techs, &tr.cveCPE, &tr.cveProduct, &tr.serviceCPE, &tr.cveIDs, &tr.cveSeverity)
		return tr, err
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list technologies: %w", err)
	}

	type bucket struct {
		tech        string
		version     string
		hosts       map[netip.Addr]struct{}
		services    map[int64]struct{}
		cveServices map[int64]struct{}
		cves        map[string]struct{}
		maxSeverity string
	}
	buckets := map[string]*bucket{}
	add := func(tech, version string, r techRow, matchCVE bool) {
		tech = strings.TrimSpace(tech)
		version = strings.TrimSpace(version)
		if tech == "" {
			return
		}
		key := strings.ToLower(tech) + "\x00" + strings.ToLower(version)
		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				tech:        tech,
				version:     version,
				hosts:       map[netip.Addr]struct{}{},
				services:    map[int64]struct{}{},
				cveServices: map[int64]struct{}{},
				cves:        map[string]struct{}{},
			}
			buckets[key] = b
		} else if tech != strings.ToLower(tech) && b.tech == strings.ToLower(b.tech) {
			// Prefer mixed-case display name (e.g. "WordPress" over "wordpress").
			b.tech = tech
		}
		b.hosts[r.ip] = struct{}{}
		b.services[r.serviceID] = struct{}{}
		if matchCVE && len(r.cveIDs) > 0 {
			b.cveServices[r.serviceID] = struct{}{}
			for _, id := range r.cveIDs {
				b.cves[id] = struct{}{}
			}
			if sevRank(r.cveSeverity) > sevRank(b.maxSeverity) {
				b.maxSeverity = r.cveSeverity
			}
		}
	}

	for _, r := range raw {
		seenNorm := map[string]bool{}
		prodCPE, _, prodHasCPE := cve.CPEForTech(r.product)
		// A port can carry several CVE-matched products (one row each); a row's
		// CVEs belong only to the technology or product it was matched for.
		prodMatches := r.cveCPE != "" && ((prodHasCPE && prodCPE == r.cveCPE) ||
			vendorProduct(r.serviceCPE) == r.cveCPE || normTechKey(r.cveProduct) == normTechKey(r.product))
		for _, rawTech := range r.techs {
			name, ver := SplitTechVersion(rawTech)
			if name == "" {
				continue
			}
			techCPE, _, techHasCPE := cve.CPEForTech(name)
			// If httpx detected the tech without a version, but nmap/override has a version
			// for the same product/CPE on this service, keep them aligned.
			sameAsProd := normTechKey(name) == normTechKey(r.product) || (techHasCPE && prodHasCPE && techCPE == prodCPE)
			if ver == "" && sameAsProd && r.version != "" {
				ver = r.version
			}
			seenNorm[normTechKey(name)] = true
			if techHasCPE {
				seenNorm["cpe:"+techCPE] = true
			}
			matchCVE := r.cveCPE != "" && ((techHasCPE && techCPE == r.cveCPE) ||
				normTechKey(name) == normTechKey(r.cveProduct) || (sameAsProd && prodMatches))
			add(name, ver, r, matchCVE)
		}
		if r.product != "" {
			if !seenNorm[normTechKey(r.product)] && !(prodHasCPE && seenNorm["cpe:"+prodCPE]) {
				add(r.product, r.version, r, prodMatches)
			}
		}
	}

	needle := strings.ToLower(strings.TrimSpace(f.Q))
	all := make([]TechnologySummary, 0, len(buckets))
	for _, b := range buckets {
		if needle != "" && !strings.Contains(strings.ToLower(b.tech), needle) && !strings.Contains(strings.ToLower(b.version), needle) {
			continue
		}
		all = append(all, TechnologySummary{
			Technology:    b.tech,
			Version:       b.version,
			HostCount:     len(b.hosts),
			ServiceCount:  len(b.services),
			CVEMatchCount: len(b.cveServices),
			CVECount:      len(b.cves),
			MaxSeverity:   b.maxSeverity,
		})
	}

	sortField := f.Sort
	if sortField == "" {
		sortField = "hosts"
	}
	order := f.Order
	if order == "" {
		if sortField == "technology" || sortField == "version" {
			order = "asc"
		} else {
			order = "desc"
		}
	}
	desc := order == "desc"
	slices.SortFunc(all, func(a, b TechnologySummary) int {
		var d int
		switch sortField {
		case "services":
			d = cmp.Compare(a.ServiceCount, b.ServiceCount)
		case "cves":
			d = cmp.Compare(a.CVECount, b.CVECount)
			if d == 0 {
				d = cmp.Compare(a.CVEMatchCount, b.CVEMatchCount)
			}
		case "version":
			d = cmp.Compare(strings.ToLower(a.Version), strings.ToLower(b.Version))
		case "technology":
			d = cmp.Compare(strings.ToLower(a.Technology), strings.ToLower(b.Technology))
			if d == 0 {
				d = cmp.Compare(strings.ToLower(a.Version), strings.ToLower(b.Version))
			}
		default: // "hosts"
			d = cmp.Compare(a.HostCount, b.HostCount)
		}
		if desc {
			d = -d
		}
		if d != 0 {
			return d
		}
		if d = cmp.Compare(b.ServiceCount, a.ServiceCount); d != 0 {
			return d
		}
		if d = cmp.Compare(strings.ToLower(a.Technology), strings.ToLower(b.Technology)); d != 0 {
			return d
		}
		return cmp.Compare(strings.ToLower(a.Version), strings.ToLower(b.Version))
	})

	total := int64(len(all))
	start := int(f.Offset)
	if start >= len(all) {
		return []TechnologySummary{}, total, nil
	}
	end := len(all)
	if f.Limit > 0 && start+int(f.Limit) < end {
		end = start + int(f.Limit)
	}
	return all[start:end], total, nil
}

// vendorProduct returns the "vendor:product" part of a "vendor:product[:version]" CPE.
func vendorProduct(cpe string) string {
	parts := strings.SplitN(cpe, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + ":" + parts[1]
}

// slow applies httpx.Slow to nullable response times.
func slow(ms, prev *int32) bool {
	if ms == nil {
		return false
	}
	p := -1
	if prev != nil {
		p = int(*prev)
	}
	return httpx.Slow(int(*ms), p)
}
