//go:build integration

package dojo

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/scanner/wpscan"
)

// TestPushServiceWPScanStage verifies architecture §3.11 for the wpscan stage:
//   - Default stages (without wpscan) issue NO "Wpscan" reimport even when a
//     wpscan artifact exists in the DB;
//   - Stages including wpscan push "Wpscan" ONLY for the WordPress IP and skip
//     non-WordPress IPs in the same batch;
//   - Stages including wpscan with no wpscan artifact (e.g., skipped: no WordPress)
//     push nothing for Wpscan and preserve prior findings.
func TestPushServiceWPScanStage(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)

	var profileID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'Default'`).Scan(&profileID); err != nil {
		t.Fatal(err)
	}

	ipWP := netip.MustParseAddr("172.31.250.10")
	ipJoomla := netip.MustParseAddr("172.31.250.11")
	nmapRaw := fixture(t, "nmap/testdata/lab.xml")
	firstHTTP := bytes.SplitN(fixture(t, "httpx/testdata/nginx.jsonl"), []byte("\n"), 2)[0]
	httpRaw := bytes.ReplaceAll(firstHTTP, []byte("172.21.0.2"), []byte(ipWP.String()))
	wpRaw := bytes.ReplaceAll(fixture(t, "wpscan/testdata/lab-wordpress.json"), []byte("172.30.0.17"), []byte(ipWP.String()))

	seedBatch := func(stages []string, wpContent []byte) (runID, batchID int64) {
		t.Helper()
		now := time.Now().UTC()
		run, err := q.InsertRun(ctx, gen.InsertRunParams{
			ProfileID: profileID, Status: "done", StartedAt: &now, FinishedAt: &now,
			HostsTotal: 2, Stats: []byte("{}"), Stages: stages,
		})
		if err != nil {
			t.Fatal(err)
		}
		batchID, err = q.InsertBatch(ctx, gen.InsertBatchParams{
			RunID: run.ID, Seq: 1, Ips: []netip.Addr{ipWP, ipJoomla},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range []struct {
			scanner string
			content []byte
		}{
			{"nmap", nmapRaw},
			{"httpx", httpRaw},
			{"wpscan", wpContent},
		} {
			if a.content == nil {
				continue
			}
			if err := q.InsertArtifact(ctx, gen.InsertArtifactParams{
				RunID: run.ID, BatchID: &batchID, Scanner: a.scanner, Content: string(a.content),
			}); err != nil {
				t.Fatal(err)
			}
		}
		return run.ID, batchID
	}

	svc, err := NewPushService(pool, map[string]ParseFunc{
		"nmap": nmap.Parse, "httpx": httpx.Parse, "nuclei": nuclei.Parse, "wpscan": wpscan.Parse,
	})
	if err != nil {
		t.Fatal(err)
	}

	withWPScan := append(pipeline.DefaultStages(), pipeline.StageWPScan)
	for _, tc := range []struct {
		name           string
		stages         []string
		wpContent      []byte
		wantWPReimport int
		wantJoomlaWP   int
	}{
		{
			name:           "default stages never push wpscan even if artifact exists",
			stages:         pipeline.DefaultStages(),
			wpContent:      wpRaw,
			wantWPReimport: 0,
			wantJoomlaWP:   0,
		},
		{
			name:           "wpscan stage pushes Wpscan only for WordPress IP",
			stages:         withWPScan,
			wpContent:      wpRaw,
			wantWPReimport: 1,
			wantJoomlaWP:   0,
		},
		{
			name:           "wpscan stage with no artifact skips Wpscan reimport",
			stages:         withWPScan,
			wpContent:      nil,
			wantWPReimport: 0,
			wantJoomlaWP:   0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runID, batchID := seedBatch(tc.stages, tc.wpContent)
			fc := newFake()
			p := &Pusher{Client: fc, OrganizationID: 1}
			args := PushArgs{
				RunID: runID, BatchID: batchID, ProfileID: profileID, Stages: tc.stages,
				Scanner: "nmap", ScanType: "Nmap Scan", IPs: []netip.Addr{ipWP, ipJoomla}, ScanDate: time.Now().UTC(),
			}
			if err := svc.run(ctx, p, args, true); err != nil {
				t.Fatal(err)
			}
			if got := len(fc.importsOf(ipWP.String(), "Wpscan")); got != tc.wantWPReimport {
				t.Errorf("ipWP Wpscan reimports = %d, want %d", got, tc.wantWPReimport)
			}
			if got := len(fc.importsOf(ipJoomla.String(), "Wpscan")); got != tc.wantJoomlaWP {
				t.Errorf("ipJoomla Wpscan reimports = %d, want %d", got, tc.wantJoomlaWP)
			}
		})
	}
}
