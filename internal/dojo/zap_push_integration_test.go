//go:build integration

package dojo

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/scanner/zap"
)

// TestPushServiceZAPStageGating verifies that "ZAP Scan" is pushed to Dojo
// ONLY when the zap stage ran in the run, and skipped for IPs not in the ZAP
// XML artifact (preserving prior findings on failed URLs).
func TestPushServiceZAPStageGating(t *testing.T) {
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
	zapXML := []byte(`<?xml version="1.0"?>
<OWASPZAPReport programName="ZAP" version="2.17.0">
  <site name="http://` + ip.String() + `" host="` + ip.String() + `" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>10020</pluginid>
        <alert>Missing Anti-clickjacking Header</alert>
        <riskcode>2</riskcode>
        <instances><instance><uri>http://` + ip.String() + `/</uri><method>GET</method></instance></instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>`)

	seed := func(stages []string, zapContent []byte) (runID, batchID int64) {
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
			{"zap", zapContent},
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
		"nmap": nmap.Parse, "httpx": httpx.Parse, "nuclei": nuclei.Parse, "zap": zap.Parse,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		stages     []string
		zapContent []byte
		wantZAP    int
	}{
		{
			name:       "default stages do not push zap even if artifact exists",
			stages:     pipeline.DefaultStages(),
			zapContent: zapXML,
			wantZAP:    0,
		},
		{
			// LB6: the seeded Aggressive profile without RAVEN_ZAP_URL; the run's
			// stages are what StartRun records (zap dropped).
			name:       "aggressive run with zap skipped does not push zap",
			stages:     []string{pipeline.StageNmap, pipeline.StageHTTPX, pipeline.StageNuclei, pipeline.StageNucleiActive, pipeline.StageNikto, pipeline.StageWPScan},
			zapContent: zapXML,
			wantZAP:    0,
		},
		{
			name:       "zap stage pushes ZAP Scan xml report",
			stages:     []string{pipeline.StageNmap, pipeline.StageHTTPX, pipeline.StageZAP},
			zapContent: zapXML,
			wantZAP:    1,
		},
		{
			name:       "zap stage with missing IP in report skips reimport",
			stages:     []string{pipeline.StageNmap, pipeline.StageHTTPX, pipeline.StageZAP},
			zapContent: []byte(`<?xml version="1.0"?><OWASPZAPReport version="2.17.0"></OWASPZAPReport>`),
			wantZAP:    0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runID, batchID := seed(tc.stages, tc.zapContent)
			fc := newFake()
			p := &Pusher{Client: fc, OrganizationID: 1}
			args := PushArgs{
				RunID: runID, BatchID: batchID, ProfileID: profileID, Stages: tc.stages,
				Scanner: "nmap", ScanType: "Nmap Scan", IPs: []netip.Addr{ip}, ScanDate: time.Now().UTC(),
			}
			if err := svc.run(ctx, p, args, true); err != nil {
				t.Fatal(err)
			}
			imports := fc.importsOf(ip.String(), "ZAP Scan")
			if len(imports) != tc.wantZAP {
				t.Fatalf("ZAP Scan imports = %d, want %d", len(imports), tc.wantZAP)
			}
			if tc.wantZAP == 1 && !strings.Contains(imports[0].Body, "Missing Anti-clickjacking Header") {
				t.Fatalf("unexpected ZAP Scan body: %s", imports[0].Body)
			}
		})
	}
}
