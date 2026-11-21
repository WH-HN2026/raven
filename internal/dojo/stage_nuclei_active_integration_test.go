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

// TestPushServiceNucleiActiveGating verifies:
//   - default stages do NOT push nuclei_active even if an artifact exists;
//   - stages including nuclei_active push it into its own Dojo Test
//     ("RAVEN: nuclei_active", scan type "Nuclei Scan") separate from "RAVEN: nuclei";
//   - an empty nuclei_active artifact still reimports "[]" to close old findings.
func TestPushServiceNucleiActiveGating(t *testing.T) {
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
	firstActive := bytes.SplitN(fixture(t, "nuclei/testdata/lab-active.jsonl"), []byte("\n"), 2)[0]
	activeRaw := bytes.ReplaceAll(firstActive, []byte("172.30.0.17"), []byte(ip.String()))

	seedBatch := func(stages []string, activeContent []byte) (runID, batchID int64) {
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
			{"nuclei", nucleiRaw},
			{pipeline.StageNucleiActive, activeContent},
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
		"nmap":                     nmap.Parse,
		"httpx":                    httpx.Parse,
		"nuclei":                   nuclei.Parse,
		pipeline.StageNucleiActive: nuclei.Parse,
	})
	if err != nil {
		t.Fatal(err)
	}

	withActive := append(pipeline.DefaultStages(), pipeline.StageNucleiActive)

	for _, tc := range []struct {
		name              string
		stages            []string
		activeContent     []byte
		wantNucleiTests   int
		wantActiveBodySub string
	}{
		{
			name:            "default stages skip nuclei_active even if artifact exists",
			stages:          pipeline.DefaultStages(),
			activeContent:   activeRaw,
			wantNucleiTests: 1,
		},
		{
			name:              "aggressive stages push nuclei and nuclei_active into separate Tests",
			stages:            withActive,
			activeContent:     activeRaw,
			wantNucleiTests:   2,
			wantActiveBodySub: `"template-id":"wp-user-enum"`,
		},
		{
			name:              "empty nuclei_active artifact still reimports [] to close old findings",
			stages:            withActive,
			activeContent:     []byte{},
			wantNucleiTests:   2,
			wantActiveBodySub: "[]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runID, batchID := seedBatch(tc.stages, tc.activeContent)
			fc := newFake()
			p := &Pusher{Client: fc, OrganizationID: 1}
			args := PushArgs{
				RunID: runID, BatchID: batchID, ProfileID: profileID, Stages: tc.stages,
				Scanner: "nmap", ScanType: "Nmap Scan", IPs: []netip.Addr{ip}, ScanDate: time.Now().UTC(),
			}
			if err := svc.run(ctx, p, args, true); err != nil {
				t.Fatal(err)
			}
			nucleiImports := fc.importsOf(ip.String(), "Nuclei Scan")
			if len(nucleiImports) != tc.wantNucleiTests {
				t.Fatalf("Nuclei Scan reimports = %d, want %d", len(nucleiImports), tc.wantNucleiTests)
			}
			testTitleByID := make(map[int64]string, len(fc.tests))
			for _, tst := range fc.tests {
				testTitleByID[tst.ID] = tst.Title
			}
			var foundActive *recordedImport
			for i := range nucleiImports {
				if testTitleByID[nucleiImports[i].TestID] == TestTitle(pipeline.StageNucleiActive) {
					foundActive = &nucleiImports[i]
				}
			}
			if tc.wantActiveBodySub == "" {
				if foundActive != nil {
					t.Fatalf("unexpected nuclei_active reimport on default run: %+v", foundActive)
				}
				return
			}
			if foundActive == nil {
				t.Fatalf("missing reimport into Test %q (tests=%v)", TestTitle(pipeline.StageNucleiActive), testTitleByID)
			}
			if !bytes.Contains([]byte(foundActive.Body), []byte(tc.wantActiveBodySub)) {
				t.Fatalf("nuclei_active body = %q, want substring %q", foundActive.Body, tc.wantActiveBodySub)
			}
			if !foundActive.CloseOldFindings || !foundActive.TagFindings {
				t.Fatalf("nuclei_active import flags = %+v", foundActive.ImportRequest)
			}
		})
	}
}
