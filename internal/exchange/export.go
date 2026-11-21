package exchange

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/changes"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dojo"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/hosts"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/targets"
)

// ServiceFilter selects services for GET /api/export/services. Zero values mean
// no filter.
type ServiceFilter struct {
	Port    *int
	Proto   string
	State   string // open | gone
	IP      *netip.Prefix
	Product string
	Q       string
	Limit   int32
	Offset  int32
}

// ExportServiceRow is one exported service row with user overrides applied on
// Name, Product, and Version.
type ExportServiceRow struct {
	ID        int64      `json:"id"`
	IP        netip.Addr `json:"ip"`
	Port      int32      `json:"port"`
	Proto     string     `json:"proto"`
	Name      string     `json:"name"`
	Product   string     `json:"product"`
	Version   string     `json:"version"`
	CPE       string     `json:"cpe,omitempty"`
	State     string     `json:"state"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

// ExportHosts exports hosts matching f (reusing hosts.Filter) as JSON or CSV.
func ExportHosts(ctx context.Context, pool *pgxpool.Pool, f hosts.Filter, format ExportFormat, w io.Writer) error {
	if !ValidExportFormat(format) {
		return fmt.Errorf("%w: format must be json or csv", ErrInvalid)
	}
	if f.Limit <= 0 || f.Limit > MaxExportRows {
		f.Limit = MaxExportRows
	}
	items, _, err := hosts.List(ctx, pool, f)
	if err != nil {
		return fmt.Errorf("export hosts: %w", err)
	}
	if format == FormatJSON {
		return writeJSON(w, items)
	}
	return WriteHostsCSV(w, items)
}

// WriteHostsCSV formats hosts as CSV.
func WriteHostsCSV(w io.Writer, items []hosts.Host) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"ip", "hostnames", "state", "first_seen", "last_seen", "miss_count",
		"dojo_asset_id", "open_service_count", "open_ports", "technologies",
		"owner", "criticality", "user_tags",
	}); err != nil {
		return err
	}
	for _, h := range items {
		assetID := ""
		if h.DojoAssetID != nil {
			assetID = strconv.FormatInt(*h.DojoAssetID, 10)
		}
		if err := cw.Write([]string{
			h.IP.String(),
			strings.Join(h.Hostnames, ";"),
			h.State,
			h.FirstSeen.UTC().Format(time.RFC3339),
			h.LastSeen.UTC().Format(time.RFC3339),
			strconv.Itoa(int(h.MissCount)),
			assetID,
			strconv.FormatInt(h.OpenServices, 10),
			joinInt32s(h.OpenPorts, ";"),
			strings.Join(h.Technologies, ";"),
			h.Owner,
			h.Criticality,
			strings.Join(h.UserTags, ";"),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ListServicesForExport queries filtered services and applies user overrides.
func ListServicesForExport(ctx context.Context, pool *pgxpool.Pool, f ServiceFilter) ([]ExportServiceRow, error) {
	if f.Limit <= 0 || f.Limit > MaxExportRows {
		f.Limit = MaxExportRows
	}
	p := gen.ListServicesForExportParams{Lim: f.Limit, Off: f.Offset}
	if f.Port != nil {
		p.Port = pgtype.Int4{Int32: int32(*f.Port), Valid: true}
	}
	if f.Proto != "" {
		p.Proto = pgtype.Text{String: f.Proto, Valid: true}
	}
	if f.State != "" {
		p.State = pgtype.Text{String: f.State, Valid: true}
	}
	if f.IP != nil {
		p.Ip = pgtype.Text{String: f.IP.Masked().String(), Valid: true}
	}
	if f.Product != "" {
		p.Product = pgtype.Text{String: f.Product, Valid: true}
	}
	if f.Q != "" {
		p.Q = pgtype.Text{String: f.Q, Valid: true}
	}
	rows, err := gen.New(pool).ListServicesForExport(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("list services for export: %w", err)
	}
	out := make([]ExportServiceRow, 0, len(rows))
	for _, r := range rows {
		name, product, version := applyOverrides(r.Name, r.Product, r.Version, r.Overrides)
		out = append(out, ExportServiceRow{
			ID: r.ID, IP: r.Ip, Port: r.Port, Proto: r.Proto,
			Name: name, Product: product, Version: version, CPE: r.Cpe,
			State: r.State, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
		})
	}
	return out, nil
}

// ExportServices exports filtered services as JSON or CSV.
func ExportServices(ctx context.Context, pool *pgxpool.Pool, f ServiceFilter, format ExportFormat, w io.Writer) error {
	if !ValidExportFormat(format) {
		return fmt.Errorf("%w: format must be json or csv", ErrInvalid)
	}
	items, err := ListServicesForExport(ctx, pool, f)
	if err != nil {
		return err
	}
	if format == FormatJSON {
		return writeJSON(w, items)
	}
	return WriteServicesCSV(w, items)
}

// WriteServicesCSV formats services as CSV (compatible with results-csv import).
func WriteServicesCSV(w io.Writer, items []ExportServiceRow) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"id", "ip", "port", "proto", "name", "product", "version", "cpe", "state", "first_seen", "last_seen",
	}); err != nil {
		return err
	}
	for _, s := range items {
		if err := cw.Write([]string{
			strconv.FormatInt(s.ID, 10),
			s.IP.String(),
			strconv.Itoa(int(s.Port)),
			s.Proto,
			s.Name,
			s.Product,
			s.Version,
			s.CPE,
			s.State,
			s.FirstSeen.UTC().Format(time.RFC3339),
			s.LastSeen.UTC().Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ExportFindings exports mirrored DefectDojo findings matching f (reusing
// dojo.FindingFilter) as JSON or CSV. Never calls Dojo directly.
func ExportFindings(ctx context.Context, pool *pgxpool.Pool, f dojo.FindingFilter, dojoPublicURL string, format ExportFormat, w io.Writer) error {
	if !ValidExportFormat(format) {
		return fmt.Errorf("%w: format must be json or csv", ErrInvalid)
	}
	if f.Limit <= 0 || f.Limit > MaxExportRows {
		f.Limit = MaxExportRows
	}
	items, _, err := dojo.ListMirrorFindings(ctx, pool, f, dojoPublicURL)
	if err != nil {
		return fmt.Errorf("export findings: %w", err)
	}
	if format == FormatJSON {
		return writeJSON(w, items)
	}
	return WriteFindingsCSV(w, items)
}

// WriteFindingsCSV formats mirrored findings as CSV.
func WriteFindingsCSV(w io.Writer, items []dojo.MirrorFinding) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"id", "asset_id", "ip", "title", "severity", "active", "verified",
		"false_p", "risk_accepted", "is_mitigated", "tags", "scanner", "date", "dojo_url",
	}); err != nil {
		return err
	}
	for _, f := range items {
		assetID, ip, date := "", "", ""
		if f.AssetID != nil {
			assetID = strconv.FormatInt(*f.AssetID, 10)
		}
		if f.IP != nil {
			ip = f.IP.String()
		}
		if f.Date != nil {
			date = *f.Date
		}
		if err := cw.Write([]string{
			strconv.FormatInt(f.ID, 10),
			assetID,
			ip,
			f.Title,
			f.Severity,
			strconv.FormatBool(f.Active),
			strconv.FormatBool(f.Verified),
			strconv.FormatBool(f.FalseP),
			strconv.FormatBool(f.RiskAccepted),
			strconv.FormatBool(f.IsMitigated),
			strings.Join(f.Tags, ";"),
			f.Scanner,
			date,
			f.DojoURL,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ExportChanges exports a run-vs-run diff (reusing changes.Compare) as JSON or CSV.
func ExportChanges(ctx context.Context, q *gen.Queries, from, to *int64, limit int, format ExportFormat, w io.Writer) error {
	if !ValidExportFormat(format) {
		return fmt.Errorf("%w: format must be json or csv", ErrInvalid)
	}
	if limit <= 0 {
		limit = 5000
	}
	c, err := changes.Compare(ctx, q, from, to, limit)
	if err != nil {
		return err
	}
	if format == FormatJSON {
		return writeJSON(w, c)
	}
	return WriteChangesCSV(w, c)
}

// WriteChangesCSV flattens a run diff into a tabular CSV.
func WriteChangesCSV(w io.Writer, c *changes.Changes) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"from_run_id", "to_run_id", "category", "ip", "port", "proto",
		"other_run", "ports", "changed_fields",
		"before_name", "before_product", "before_version", "before_title", "before_technologies",
		"after_name", "after_product", "after_version", "after_title", "after_technologies",
	}); err != nil {
		return err
	}
	fromID := strconv.FormatInt(c.From.ID, 10)
	toID := strconv.FormatInt(c.To.ID, 10)

	writeHost := func(cat string, h changes.HostChange) error {
		return cw.Write([]string{
			fromID, toID, cat, h.IP.String(), "", "",
			h.OtherRun, joinUint16s(h.Ports, ";"), "",
			"", "", "", "", "",
			"", "", "", "", "",
		})
	}
	writeSvc := func(cat string, s changes.ServiceChange) error {
		var bn, bp, bv, bt, btech, an, ap, av, at, atech string
		if s.Before != nil {
			bn, bp, bv, bt = s.Before.Name, s.Before.Product, s.Before.Version, s.Before.Title
			btech = strings.Join(s.Before.Technologies, ";")
		}
		if s.After != nil {
			an, ap, av, at = s.After.Name, s.After.Product, s.After.Version, s.After.Title
			atech = strings.Join(s.After.Technologies, ";")
		}
		return cw.Write([]string{
			fromID, toID, cat, s.IP.String(), strconv.Itoa(int(s.Port)), s.Proto,
			"", "", strings.Join(s.Fields, ";"),
			bn, bp, bv, bt, btech,
			an, ap, av, at, atech,
		})
	}

	for _, h := range c.HostsNew {
		if err := writeHost("host_new", h); err != nil {
			return err
		}
	}
	for _, h := range c.HostsGone {
		if err := writeHost("host_gone", h); err != nil {
			return err
		}
	}
	for _, s := range c.ServicesNew {
		if err := writeSvc("service_new", s); err != nil {
			return err
		}
	}
	for _, s := range c.ServicesGone {
		if err := writeSvc("service_gone", s); err != nil {
			return err
		}
	}
	for _, s := range c.ServicesChanged {
		if err := writeSvc("service_changed", s); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ExportTargets exports all targets in the JSON/CSV format accepted by
// internal/targets (POST /api/targets/upload).
func ExportTargets(ctx context.Context, pool *pgxpool.Pool, format ExportFormat, w io.Writer) error {
	if !ValidExportFormat(format) {
		return fmt.Errorf("%w: format must be json or csv", ErrInvalid)
	}
	rows, err := gen.New(pool).ListAllTargets(ctx)
	if err != nil {
		return fmt.Errorf("export targets: %w", err)
	}
	entries := make([]targets.Entry, 0, len(rows))
	for _, r := range rows {
		tags := r.Tags
		if tags == nil {
			tags = []string{}
		}
		entries = append(entries, targets.Entry{
			Kind: targets.Kind(r.Kind), Value: r.Value, Tags: tags, Note: r.Note,
		})
	}
	if format == FormatJSON {
		return writeJSON(w, entries)
	}
	return WriteTargetsCSV(w, entries)
}

// WriteTargetsCSV writes targets in internal/targets' value,tags,note CSV format.
func WriteTargetsCSV(w io.Writer, items []targets.Entry) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"value", "tags", "note"}); err != nil {
		return err
	}
	for _, e := range items {
		if err := cw.Write([]string{e.Value, strings.Join(e.Tags, ";"), e.Note}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func applyOverrides(name, product, version string, raw []byte) (string, string, string) {
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return name, product, version
	}
	if v, ok := m["name"].(string); ok {
		name = v
	}
	if v, ok := m["product"].(string); ok {
		product = v
	}
	if v, ok := m["version"].(string); ok {
		version = v
	}
	return name, product, version
}

func joinInt32s(xs []int32, sep string) string {
	if len(xs) == 0 {
		return ""
	}
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(int(x))
	}
	return strings.Join(out, sep)
}

func joinUint16s(xs []uint16, sep string) string {
	if len(xs) == 0 {
		return ""
	}
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(int(x))
	}
	return strings.Join(out, sep)
}
