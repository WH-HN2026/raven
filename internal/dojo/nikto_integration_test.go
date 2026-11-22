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
	"github.com/WH-HN2026/raven/internal/scanner/nikto"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
)

// TestPushServiceNiktoStagesGating verifies architecture §3.11 for nikto:
//   - Default stages (without nikto) issue NO "Nikto Scan" reimport even if a nikto artifact exists;
//   - Stages including nikto issue a "Nikto Scan" reimport with .json file and "raven" tag;
//   - An empty nikto report ("vulnerabilities": []) for a scanned IP still reimports to close old findings;
//   - Missing nikto artifact (e.g. all URLs failed) issues NO "Nikto Scan" reimport so prior findings stay open.
func TestPushServiceNiktoStagesGating(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)

	var profileID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'Default'`).Scan(&profileID); err != nil {
		t.Fatal(err)
	}

	ip := ipWeb
	nmapRaw := fixture(t, "nmap/testdata/lab.xml")
	firstHTTP := bytes.SplitN(fixture(t, "httpx/testdata/nginx.jsonl"), []byte("\n"), 2)[0]
	httpRaw := bytes.ReplaceAll(firstHTTP, []byte("172.21.0.2"), []byte(ip.String()))
	niktoWithFinding := []byte(`[{"host":"` + ip.String() + `","ip":"` + ip.String() + `","port":"80","vulnerabilities":[{"id":"999103","method":"GET","url":"/","msg":"Missing X-Content-Type-Options"}]}]`)
	niktoEmpty := []byte(`[{"host":"` + ip.String() + `","ip":"` + ip.String() + `","port":"80","vulnerabilities":[]}]`)

	seedBatch := func(stages []string, niktoContent []byte) (runID, batchID int64) {
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
			{"nikto", niktoContent},
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
		"nmap": nmap.Parse, "httpx": httpx.Parse, "nuclei": nuclei.Parse, "nikto": nikto.Parse,
	})
	if err != nil {
		t.Fatal(err)
	}

	aggStages := []string{pipeline.StageNmap, pipeline.StageHTTPX, pipeline.StageNikto}
	for _, tc := range []struct {
		name         string
		stages       []string
		niktoContent []byte
		wantNikto    int
	}{
		{
			name:         "default stages skip nikto even when artifact exists",
			stages:       pipeline.DefaultStages(),
			niktoContent: niktoWithFinding,
			wantNikto:    0,
		},
		{
			name:         "nikto stage pushes Nikto Scan report",
			stages:       aggStages,
			niktoContent: niktoWithFinding,
			wantNikto:    1,
		},
		{
			name:         "nikto stage with empty vulns still pushes to close old findings",
			stages:       aggStages,
			niktoContent: niktoEmpty,
			wantNikto:    1,
		},
		{
			name:         "nikto stage with missing artifact skips push to preserve old findings",
			stages:       aggStages,
			niktoContent: nil,
			wantNikto:    0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runID, batchID := seedBatch(tc.stages, tc.niktoContent)
			fc := newFake()
			p := &Pusher{Client: fc, OrganizationID: 1}
			args := PushArgs{
				RunID: runID, BatchID: batchID, ProfileID: profileID, Stages: tc.stages,
				Scanner: "nmap", ScanType: "Nmap Scan", IPs: []netip.Addr{ip}, ScanDate: time.Now().UTC(),
			}
			if err := svc.run(ctx, p, args, true); err != nil {
				t.Fatal(err)
			}
			imports := fc.importsOf(ip.String(), "Nikto Scan")
			if len(imports) != tc.wantNikto {
				t.Fatalf("Nikto Scan reimports = %d, want %d", len(imports), tc.wantNikto)
			}
			for _, imp := range imports {
				if imp.FileName != ip.String()+".nikto.json" {
					t.Errorf("Nikto filename = %q, want %s.nikto.json", imp.FileName, ip.String())
				}
				if !imp.TagFindings || !imp.CloseOldFindings {
					t.Errorf("Nikto reimport flags: tagFindings=%v closeOld=%v, want true/true", imp.TagFindings, imp.CloseOldFindings)
				}
			}
		})
	}
}
