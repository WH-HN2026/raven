package pipeline

import (
	"context"
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

// Ingest writes a batch into hosts / services / run_observations /
// artifacts using q (the caller's transaction). Only scan-owned columns
// are written (architecture §5): see internal/db/queries/ingest.sql.
func Ingest(ctx context.Context, q *gen.Queries, in IngestInput) error {
	p := in.Plan
	for _, h := range p.Hosts {
		if err := q.UpsertScannedHost(ctx, gen.UpsertScannedHostParams{
			Ip: h.IP, Hostnames: nonNil(h.Hostnames), Seen: in.Seen,
		}); err != nil {
			return fmt.Errorf("ingest host %s: %w", h.IP, err)
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

	for _, s := range p.Services {
		if err := q.UpsertScannedService(ctx, gen.UpsertScannedServiceParams{
			Ip: s.IP, Port: int32(s.Port), Proto: s.Proto, Name: s.Name, Product: s.Product,
			Version: s.Version, Cpe: s.CPE, Banner: s.Banner, Seen: in.Seen,
		}); err != nil {
			return fmt.Errorf("ingest service %s/%d: %w", s.IP, s.Port, err)
		}
	}

	if len(p.Observations) > 0 {
		ips := make([]netip.Addr, len(p.Observations))
		ports := make([]int32, len(p.Observations))
		ups := make([]bool, len(p.Observations))
		for i, o := range p.Observations {
			ips[i], ups[i], ports[i] = o.IP, o.Up, int32(o.Port)
			if o.HostLevel {
				ports[i] = -1
			}
		}
		if err := q.InsertRunObservations(ctx, gen.InsertRunObservationsParams{
			RunID: in.RunID, ObservedAt: in.Seen, Ips: ips, Ports: ports, Ups: ups,
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
