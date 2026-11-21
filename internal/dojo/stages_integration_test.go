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
)

// TestPushServiceStagesGating verifies architecture §3.11:
//   - nmap-only batch issues NO httpx or nuclei reimports (even if artifacts exist);
//   - [nmap, httpx] batch issues nmap + httpx reimports, NO nuclei reimport;
//   - Default batch issues nmap + httpx + nuclei reimports;
//   - Default batch with empty nuclei output STILL reimports nuclei ("[]") to close old findings.
func TestPushServiceStagesGating(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)

	var profileID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'default'`).Scan(&profileID); err != nil {
		t.Fatal(err)
	}

	ip := ipWeb
	nmapRaw := fixture(t, "nmap/testdata/lab.xml")
	firstHTTP := bytes.SplitN(fixture(t, "httpx/testdata/nginx.jsonl"), []byte("\n"), 2)[0]
	httpRaw := bytes.ReplaceAll(firstHTTP, []byte("172.21.0.2"), []byte(ip.String()))
	firstHit := bytes.SplitN(fixture(t, "nuclei/testdata/lab-http.jsonl"), []byte("\n"), 2)[0]
	nucleiRaw := bytes.ReplaceAll(firstHit, []byte("172.30.0.17"), []byte(ip.String()))

	seedBatch := func(stages []string, nucleiContent []byte) (runID, batchID int64) {
		t.Helper()
		now := time.Now().UTC()
		run, err := q.InsertRun(ctx, gen.InsertRunParams{
			ProfileID: profileID, Status: "done", StartedAt: &now, FinishedAt: &now,
			HostsTotal: 1, Stats: []byte("{}"), Stages: stages,
		})
		if err != nil {
			t.Fatal(err)
		}
		batchID, err = q.InsertBatch(ctx, gen.InsertBatchParams{RunID: run.ID, Seq: 1, Ips: []netip.Addr{ip}})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range []struct {
			scanner string
			content []byte
		}{
			{"nmap", nmapRaw},
			{"httpx", httpRaw},
			{"nuclei", nucleiContent},
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
		"nmap": nmap.Parse, "httpx": httpx.Parse, "nuclei": nuclei.Parse,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		stages        []string
		nucleiContent []byte
		wantNmap      int
		wantHTTPX     int
		wantNuclei    int
	}{
		{
			name:          "nmap-only issues no httpx or nuclei reimport",
			stages:        []string{pipeline.StageNmap},
			nucleiContent: nucleiRaw,
			wantNmap:      1,
			wantHTTPX:     0,
			wantNuclei:    0,
		},
		{
			name:          "nmap+httpx issues no nuclei reimport",
			stages:        []string{pipeline.StageNmap, pipeline.StageHTTPX},
			nucleiContent: nucleiRaw,
			wantNmap:      1,
			wantHTTPX:     1,
			wantNuclei:    0,
		},
		{
			name:          "default issues nmap, httpx and nuclei reimports",
			stages:        pipeline.DefaultStages(),
			nucleiContent: nucleiRaw,
			wantNmap:      1,
			wantHTTPX:     1,
			wantNuclei:    1,
		},
		{
			name:          "default with empty nuclei result still reimports nuclei to close old findings",
			stages:        pipeline.DefaultStages(),
			nucleiContent: []byte{},
			wantNmap:      1,
			wantHTTPX:     1,
			wantNuclei:    1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runID, batchID := seedBatch(tc.stages, tc.nucleiContent)
			fc := newFake()
			p := &Pusher{Client: fc, OrganizationID: 1}
			args := PushArgs{
				RunID: runID, BatchID: batchID, ProfileID: profileID, Stages: tc.stages,
				Scanner: "nmap", ScanType: "Nmap Scan", IPs: []netip.Addr{ip}, ScanDate: time.Now().UTC(),
			}
			if err := svc.run(ctx, p, args, true); err != nil {
				t.Fatal(err)
			}
			if got := len(fc.importsOf(ip.String(), "Nmap Scan")); got != tc.wantNmap {
				t.Errorf("Nmap Scan reimports = %d, want %d", got, tc.wantNmap)
			}
			if got := len(fc.importsOf(ip.String(), "httpx Scan")); got != tc.wantHTTPX {
				t.Errorf("httpx Scan reimports = %d, want %d", got, tc.wantHTTPX)
			}
			if got := len(fc.importsOf(ip.String(), "Nuclei Scan")); got != tc.wantNuclei {
				t.Errorf("Nuclei Scan reimports = %d, want %d", got, tc.wantNuclei)
			}
		})
	}
}
