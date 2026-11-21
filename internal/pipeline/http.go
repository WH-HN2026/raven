package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
)

// ingestHTTP adds URL-level facts to the services already written by Ingest.
// The corresponding port-level run_observations row is shared by the IP URL
// and all its virtual hosts, so these facts don't add another presence row.
func (s *Service) ingestHTTP(ctx context.Context, q *gen.Queries, b gen.Batch, res *scanner.Result, seen time.Time) error {
	type key struct {
		ip  netip.Addr
		url string
	}
	inserted := make(map[key]bool)
	for _, o := range res.Observations {
		k := key{o.IP, o.URL}
		if o.Kind != scanner.ObsHTTP || o.HTTP == nil || inserted[k] {
			continue
		}
		inserted[k] = true
		h := o.HTTP
		// These values contain only JSON-serializable strings.
		headers, _ := json.Marshal(h.Headers)
		cookies, _ := json.Marshal(nonNil(h.Cookies))
		redirects, _ := json.Marshal(nonNil(h.Redirects))
		at := o.At
		if at.IsZero() {
			at = seen
		}
		n, err := q.InsertHTTPObservation(ctx, gen.InsertHTTPObservationParams{
			Ip: o.IP, Port: int32(o.Port), Url: o.URL, Status: pgtype.Int4{Int32: int32(h.Status), Valid: true}, Title: h.Title,
			Headers: string(headers), Cookies: string(cookies), TlsCert: h.TLSCert,
			Redirects: redirects, Technologies: nonNil(h.Technologies), FaviconHash: h.FaviconHash,
			RunID: &b.RunID, ObservedAt: at,
		})
		if err != nil {
			return fmt.Errorf("ingest HTTP observation for %s/%d: %w", o.IP, o.Port, err)
		}
		if n == 0 {
			return fmt.Errorf("ingest HTTP observation for %s/%d: service missing", o.IP, o.Port)
		}
	}
	if len(res.Raw) == 0 {
		return nil
	}
	if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
		RunID: b.RunID, BatchID: &b.ID, Scanner: s.cfg.HTTPX.Name(), Content: string(res.Raw),
	}); err != nil {
		return fmt.Errorf("ingest HTTP artifact: %w", err)
	}
	return nil
}
