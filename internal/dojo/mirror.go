package dojo

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/db"
)

var FindingSorts = []string{"severity", "title", "ip", "scanner", "status", "date"}

// FindingFilter selects findings from the mirror (GET /api/findings).
// Zero values mean "no filter".
type FindingFilter struct {
	Severities   []string      // any of (Dojo values, see Severities)
	Active       *bool         //
	Verified     *bool         //
	FalseP       *bool         //
	OutOfScope   *bool         //
	RiskAccepted *bool         //
	Duplicate    *bool         //
	IsMitigated  *bool         //
	AssetID      *int64        // exact dojo_findings.asset_id
	Asset        string        // asset id, IP/CIDR, or dojo_assets.name substring
	IP           *netip.Prefix // a single IP is a /32 (/128) prefix
	Q            string        // case-insensitive title substring
	Scanner      string        // exact: nmap, nuclei, raven, …
	Order        db.ListOrder
	Limit        int32
	Offset       int32
}

// MirrorFinding is one row of the mirror as the API returns it.
type MirrorFinding struct {
	ID           int64       `json:"id"`
	AssetID      *int64      `json:"asset_id"`
	IP           *netip.Addr `json:"ip"`
	Title        string      `json:"title"`
	Severity     string      `json:"severity"`
	Active       bool        `json:"active"`
	Verified     bool        `json:"verified"`
	FalseP       bool        `json:"false_p"`
	OutOfScope   bool        `json:"out_of_scope"`
	RiskAccepted bool        `json:"risk_accepted"`
	Duplicate    bool        `json:"duplicate"`
	IsMitigated  bool        `json:"is_mitigated"`
	Tags         []string    `json:"tags"`
	Scanner      string      `json:"scanner"`
	Date         *string     `json:"date"`
	DojoURL      string      `json:"dojo_url"`
}

const severityRank = `CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END`

// Match the first applicable status displayed in the findings table.
const findingStatus = `CASE WHEN duplicate THEN 'duplicate' WHEN false_p THEN 'false positive'
	WHEN out_of_scope THEN 'out of scope' WHEN risk_accepted THEN 'risk accepted'
	WHEN is_mitigated THEN 'mitigated' WHEN active AND verified THEN 'verified'
	WHEN active THEN 'active' ELSE 'inactive' END`

func findingOrderBy(order db.ListOrder) string {
	column := severityRank
	switch order.Column {
	case "title":
		column = "lower(title)"
	case "ip":
		column = "ip"
	case "scanner":
		column = "lower(scanner)"
	case "status":
		column = findingStatus
	case "date":
		column = "date"
	}
	direction := order.SQLDirection()
	if order.Column == "" && order.Direction == "" {
		direction = "DESC"
	}
	return column + " " + direction + " NULLS LAST, date DESC NULLS LAST, id DESC"
}

// buildFindingWhere returns the WHERE clause (with leading " WHERE " or
// empty) and its args. Values are always bound as parameters.
func buildFindingWhere(f FindingFilter) (string, []any) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if len(f.Severities) > 0 {
		conds = append(conds, "severity = ANY("+arg(f.Severities)+"::text[])")
	}
	if f.Active != nil {
		conds = append(conds, "active = "+arg(*f.Active))
	}
	if f.Verified != nil {
		conds = append(conds, "verified = "+arg(*f.Verified))
	}
	if f.FalseP != nil {
		conds = append(conds, "false_p = "+arg(*f.FalseP))
	}
	if f.OutOfScope != nil {
		conds = append(conds, "out_of_scope = "+arg(*f.OutOfScope))
	}
	if f.RiskAccepted != nil {
		conds = append(conds, "risk_accepted = "+arg(*f.RiskAccepted))
	}
	if f.Duplicate != nil {
		conds = append(conds, "duplicate = "+arg(*f.Duplicate))
	}
	if f.IsMitigated != nil {
		conds = append(conds, "is_mitigated = "+arg(*f.IsMitigated))
	}
	if f.AssetID != nil {
		conds = append(conds, "asset_id = "+arg(*f.AssetID))
	}
	if a := strings.TrimSpace(f.Asset); a != "" {
		if id, err := strconv.ParseInt(a, 10, 64); err == nil && id > 0 {
			conds = append(conds, "asset_id = "+arg(id))
		} else if p, err := netip.ParsePrefix(a); err == nil {
			conds = append(conds, "ip <<= "+arg(p.Masked().String())+"::inet")
		} else if addr, err := netip.ParseAddr(a); err == nil {
			addr = addr.Unmap()
			p := netip.PrefixFrom(addr, addr.BitLen())
			conds = append(conds, "ip <<= "+arg(p.String())+"::inet")
		} else {
			n := arg(a)
			conds = append(conds, "(EXISTS (SELECT 1 FROM dojo_assets da WHERE da.id = dojo_findings.asset_id AND strpos(lower(da.name), lower("+n+")) > 0) OR starts_with(host(ip), "+n+"))")
		}
	}
	if f.IP != nil {
		conds = append(conds, "ip <<= "+arg(f.IP.Masked().String())+"::inet")
	}
	if f.Q != "" {
		conds = append(conds, "strpos(lower(title), lower("+arg(f.Q)+")) > 0")
	}
	if f.Scanner != "" {
		conds = append(conds, "scanner = "+arg(f.Scanner))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// buildFindingList returns the page query and the count query (sharing args
// up to the page's limit/offset, which come last).
func buildFindingList(f FindingFilter) (list string, count string, args []any) {
	where, args := buildFindingWhere(f)
	count = "SELECT count(*) FROM dojo_findings" + where
	n := len(args)
	list = "SELECT id, asset_id, ip, title, severity, active, verified, false_p, out_of_scope, risk_accepted, duplicate, is_mitigated, tags, scanner, " +
		"to_char(date, 'YYYY-MM-DD') FROM dojo_findings" + where +
		" ORDER BY " + findingOrderBy(f.Order) +
		" LIMIT $" + strconv.Itoa(n+1) + " OFFSET $" + strconv.Itoa(n+2)
	return list, count, append(args, f.Limit, f.Offset)
}

// FindingURL is the browser link to a finding in the Dojo UI.
func FindingURL(publicBase string, id int64) string {
	if publicBase == "" {
		return ""
	}
	return strings.TrimRight(publicBase, "/") + "/finding/" + strconv.FormatInt(id, 10)
}

// EngagementURL is the browser link to an engagement in the Dojo UI.
func EngagementURL(publicBase string, id int64) string {
	if publicBase == "" || id <= 0 {
		return ""
	}
	return strings.TrimRight(publicBase, "/") + "/engagement/" + strconv.FormatInt(id, 10)
}

// ListMirrorFindings reads one page of the mirror (never Dojo) and the total.
// dojoPublicURL builds each item's dojo_url.
func ListMirrorFindings(ctx context.Context, pool *pgxpool.Pool, f FindingFilter, dojoPublicURL string) ([]MirrorFinding, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list, count, args := buildFindingList(f)
	var total int64
	if err := pool.QueryRow(ctx, count, args[:len(args)-2]...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count mirror findings: %w", err)
	}
	rows, err := pool.Query(ctx, list, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list mirror findings: %w", err)
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (MirrorFinding, error) {
		var m MirrorFinding
		err := r.Scan(&m.ID, &m.AssetID, &m.IP, &m.Title, &m.Severity, &m.Active, &m.Verified, &m.FalseP,
			&m.OutOfScope, &m.RiskAccepted, &m.Duplicate, &m.IsMitigated, &m.Tags, &m.Scanner, &m.Date)
		m.DojoURL = FindingURL(dojoPublicURL, m.ID)
		return m, err
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list mirror findings: %w", err)
	}
	if items == nil {
		items = []MirrorFinding{}
	}
	return items, total, nil
}
