package hosts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

// ErrNotFound: no host with that IP.
var ErrNotFound = errors.New("host not found")

// TimelineRows is how many host-level up/down observations the detail returns.
const TimelineRows = 20

// Host is one list item (and the base of the detail).
type Host struct {
	IP           netip.Addr      `json:"ip"`
	Hostnames    []string        `json:"hostnames"`
	State        string          `json:"state"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	MissCount    int32           `json:"miss_count"`
	DojoAssetID  *int64          `json:"dojo_asset_id"`
	OpenServices int64           `json:"open_service_count"`
	OpenPorts    []int32         `json:"open_ports"`
	Technologies []string        `json:"technologies"`
	Owner        string          `json:"owner"`
	Criticality  string          `json:"criticality"`
	UserTags     []string        `json:"user_tags"`
	Overrides    json.RawMessage `json:"overrides"`
	EditedBy     *string         `json:"edited_by"`
	EditedAt     *time.Time      `json:"edited_at"`
}

// Service is a service with the user overrides applied: Name/Product/Version
// are the effective values, Scan holds what the scanner saw, Overridden names
// the fields taken from overrides.
type Service struct {
	ID         int64           `json:"id"`
	IP         netip.Addr      `json:"ip"`
	Port       int32           `json:"port"`
	Proto      string          `json:"proto"`
	Name       string          `json:"name"`
	Product    string          `json:"product"`
	Version    string          `json:"version"`
	CPE        string          `json:"cpe,omitempty"`
	Scan       ServiceFields   `json:"scan"`
	Overridden []string        `json:"overridden"`
	Banner     string          `json:"banner"`
	State      string          `json:"state"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Overrides  json.RawMessage `json:"overrides"`
}

// HTTPObservation is the latest observation of one URL, decrypted.
type HTTPObservation struct {
	ID           int64             `json:"id"`
	ServiceID    int64             `json:"service_id"`
	URL          string            `json:"url"`
	Status       *int32            `json:"status"`
	Title        string            `json:"title"`
	Headers      map[string]string `json:"headers"`
	Cookies      []string          `json:"cookies"`
	TLSCert      string            `json:"tls_cert"`
	Redirects    []string          `json:"redirects"`
	Technologies []string          `json:"technologies"`
	FaviconHash  string            `json:"favicon_hash"`
	RunID        *int64            `json:"run_id"`
	ObservedAt   time.Time         `json:"observed_at"`
}

// Observation is one host-level up/down result of a run.
type Observation struct {
	RunID      int64     `json:"run_id"`
	Up         bool      `json:"up"`
	ObservedAt time.Time `json:"observed_at"`
}

// Detail is GET /api/hosts/{ip}.
type Detail struct {
	Host
	Notes    string            `json:"notes"`
	Services []Service         `json:"services"`
	HTTP     []HTTPObservation `json:"http"`
	Timeline []Observation     `json:"timeline"`
}

// serviceFromRow applies the overrides to one services row.
func serviceFromRow(s gen.ListHostServicesRow) Service {
	scan := ServiceFields{Name: s.Name, Product: s.Product, Version: s.Version}
	eff, over := applyServiceOverrides(scan, s.Overrides)
	return Service{
		ID: s.ID, IP: s.Ip, Port: s.Port, Proto: s.Proto,
		Name: eff.Name, Product: eff.Product, Version: eff.Version, CPE: s.Cpe, Scan: scan, Overridden: over,
		Banner: s.Banner, State: s.State, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen,
		Overrides: objectOrEmpty(s.Overrides),
	}
}

// List reads one page of hosts matching f, and the total.
func List(ctx context.Context, pool *pgxpool.Pool, f Filter) ([]Host, int64, error) {
	list, count, args := buildList(f)
	var total int64
	if err := pool.QueryRow(ctx, count, args[:len(args)-2]...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count hosts: %w", err)
	}
	rows, err := pool.Query(ctx, list, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list hosts: %w", err)
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Host, error) {
		var h Host
		err := r.Scan(&h.IP, &h.Hostnames, &h.State, &h.FirstSeen, &h.LastSeen, &h.MissCount, &h.DojoAssetID,
			&h.Owner, &h.Criticality, &h.UserTags, &h.Overrides, &h.EditedBy, &h.EditedAt, &h.OpenServices, &h.OpenPorts, &h.Technologies)
		h.Overrides = objectOrEmpty(h.Overrides)
		return h, err
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list hosts: %w", err)
	}
	if items == nil {
		items = []Host{}
	}
	return items, total, nil
}

// Get reads one host with its services (overrides applied, banner
// decrypted), the latest HTTP observation per URL (decrypted) and the last
// TimelineRows host-level up/down observations. Decrypted values must not be
// logged.
func Get(ctx context.Context, pool *pgxpool.Pool, ip netip.Addr) (*Detail, error) {
	q := gen.New(pool)
	ip = ip.Unmap()
	h, err := q.GetHost(ctx, ip)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host %s: %w", ip, err)
	}
	var editedBy *string
	if h.EditedBy.Valid {
		s := h.EditedBy.String
		editedBy = &s
	}
	d := &Detail{
		Host: Host{
			IP: h.Ip, Hostnames: h.Hostnames, State: h.State, FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
			MissCount: h.MissCount, DojoAssetID: h.DojoAssetID, Owner: h.Owner, Criticality: h.Criticality,
			UserTags: h.UserTags, Overrides: objectOrEmpty(h.Overrides), EditedBy: editedBy, EditedAt: h.EditedAt,
			OpenPorts: []int32{}, Technologies: []string{},
		},
		Notes: h.Notes,
	}

	svcs, err := q.ListHostServices(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("services of %s: %w", ip, err)
	}
	d.Services = make([]Service, 0, len(svcs))
	for _, s := range svcs {
		d.Services = append(d.Services, serviceFromRow(s))
		if s.State == "open" {
			d.OpenServices++
			if n := len(d.OpenPorts); n == 0 || d.OpenPorts[n-1] != s.Port {
				d.OpenPorts = append(d.OpenPorts, s.Port)
			}
		}
	}

	obs, err := q.ListLatestHTTPObservations(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("http observations of %s: %w", ip, err)
	}
	d.HTTP = make([]HTTPObservation, 0, len(obs))
	techs := map[string]bool{}
	for _, o := range obs {
		var status *int32
		if o.Status.Valid {
			status = &o.Status.Int32
		}
		d.HTTP = append(d.HTTP, HTTPObservation{
			ID: o.ID, ServiceID: o.ServiceID, URL: o.Url, Status: status, Title: o.Title,
			Headers: decodeHeaders(o.Headers), Cookies: decodeStrings(o.Cookies), TLSCert: o.TlsCert,
			Redirects: decodeStrings(string(o.Redirects)), Technologies: o.Technologies,
			FaviconHash: o.FaviconHash, RunID: o.RunID, ObservedAt: o.ObservedAt,
		})
		for _, t := range o.Technologies {
			if !techs[t] {
				techs[t] = true
				d.Technologies = append(d.Technologies, t)
			}
		}
	}

	slices.Sort(d.Technologies)

	tl, err := q.ListHostRunObservations(ctx, gen.ListHostRunObservationsParams{Ip: ip, MaxRows: TimelineRows})
	if err != nil {
		return nil, fmt.Errorf("run observations of %s: %w", ip, err)
	}
	d.Timeline = make([]Observation, 0, len(tl))
	for _, o := range tl {
		d.Timeline = append(d.Timeline, Observation{RunID: o.RunID, Up: o.Up, ObservedAt: o.ObservedAt})
	}
	return d, nil
}
