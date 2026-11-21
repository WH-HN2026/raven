package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

// IngestInput is one batch's result, ready to write.
type IngestInput struct {
	RunID, BatchID int64
	Scanner        string // artifacts.scanner
	Raw            []byte // tool output, stored encrypted
	Plan           Plan
	Ports          PortSet // the profile's ports: 'gone' is decided only inside them
	Seen           time.Time
}

type obsServiceFP struct {
	Proto   string `json:"proto,omitempty"`
	Name    string `json:"name,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
}

// Ingest writes a batch into hosts / services / run_observations /
// artifacts using q (the caller's transaction). Only scan-owned columns
// are written (architecture §5): see internal/db/queries/ingest.sql.
func Ingest(ctx context.Context, q *gen.Queries, in IngestInput) error {
	p := in.Plan
	if len(p.Hosts) > 0 {
		ips := make([]netip.Addr, len(p.Hosts))
		hostnamesJSON := make([]string, len(p.Hosts))
		for i, h := range p.Hosts {
			ips[i] = h.IP
			b, err := json.Marshal(nonNil(h.Hostnames))
			if err != nil {
				return fmt.Errorf("ingest host %s hostnames: %w", h.IP, err)
			}
			hostnamesJSON[i] = string(b)
		}
		if err := q.UpsertScannedHosts(ctx, gen.UpsertScannedHostsParams{
			Seen: in.Seen, Ips: ips, HostnamesJson: hostnamesJSON,
		}); err != nil {
			return fmt.Errorf("ingest hosts: %w", err)
		}
	}

	if len(p.Up) > 0 {
		rows, err := q.ListOpenServicesOf(ctx, p.Up)
		if err != nil {
			return fmt.Errorf("ingest: list open services: %w", err)
		}
		before := make([]OpenService, 0, len(rows))
		for _, r := range rows {
			before = append(before, OpenService{ID: r.ID, IP: r.Ip, Port: uint16(r.Port), Proto: r.Proto})
		}
		if gone := GoneServices(p, before, in.Ports); len(gone) > 0 {
			if err := q.MarkServicesGone(ctx, gone); err != nil {
				return fmt.Errorf("ingest: mark services gone: %w", err)
			}
		}
	}

	type ipPort struct {
		ip   netip.Addr
		port uint16
	}
	fpBySvc := make(map[ipPort]string, len(p.Services))
	if len(p.Services) > 0 {
		n := len(p.Services)
		params := gen.UpsertScannedServicesParams{
			Seen:     in.Seen,
			Ips:      make([]netip.Addr, n),
			Ports:    make([]int32, n),
			Protos:   make([]string, n),
			Names:    make([]string, n),
			Products: make([]string, n),
			Versions: make([]string, n),
			Cpes:     make([]string, n),
			Banners:  make([]string, n),
		}
		for i, s := range p.Services {
			params.Ips[i] = s.IP
			params.Ports[i] = int32(s.Port)
			params.Protos[i] = s.Proto
			params.Names[i] = s.Name
			params.Products[i] = s.Product
			params.Versions[i] = s.Version
			params.Cpes[i] = s.CPE
			params.Banners[i] = s.Banner
			b, err := json.Marshal(obsServiceFP{
				Proto: s.Proto, Name: s.Name, Product: s.Product, Version: s.Version, Title: s.Title,
			})
			if err != nil {
				return fmt.Errorf("ingest service %s/%d fp: %w", s.IP, s.Port, err)
			}
			fpBySvc[ipPort{s.IP, s.Port}] = string(b)
		}
		if err := q.UpsertScannedServices(ctx, params); err != nil {
			return fmt.Errorf("ingest services: %w", err)
		}
	}

	if len(p.Observations) > 0 {
		ips := make([]netip.Addr, len(p.Observations))
		ports := make([]int32, len(p.Observations))
		ups := make([]bool, len(p.Observations))
		fps := make([]string, len(p.Observations))
		for i, o := range p.Observations {
			ips[i], ups[i], ports[i] = o.IP, o.Up, int32(o.Port)
			if o.HostLevel {
				ports[i] = -1
			} else if o.Up {
				fps[i] = fpBySvc[ipPort{o.IP, o.Port}]
			}
		}
		if err := q.InsertRunObservations(ctx, gen.InsertRunObservationsParams{
			RunID: in.RunID, ObservedAt: in.Seen, Ips: ips, Ports: ports, Ups: ups, ServiceFps: fps,
		}); err != nil {
			return fmt.Errorf("ingest: run observations: %w", err)
		}
	}

	if len(in.Raw) > 0 {
		if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
			RunID: in.RunID, BatchID: &in.BatchID, Scanner: in.Scanner, Content: string(in.Raw),
		}); err != nil {
			return fmt.Errorf("ingest: artifact: %w", err)
		}
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
