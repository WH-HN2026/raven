//go:build integration

package dojo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/pipeline"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/httpx"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nmap"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nuclei"
)

type artifactScanner struct {
	name, scanType string
	result         func() *scanner.Result
}

func (s artifactScanner) Name() string         { return s.name }
func (s artifactScanner) DojoScanType() string { return s.scanType }
func (s artifactScanner) Run(context.Context, scanner.Input, scanner.Options) (*scanner.Result, error) {
	return s.result(), nil
}

func TestIntegrationWebPushAndOffline(t *testing.T) {
	base := os.Getenv("ASI_DOJO_URL")
	if base == "" {
		t.Skip("ASI_DOJO_URL not set")
	}
	pool := dbtest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	token := os.Getenv("ASI_DOJO_TOKEN")
	if token == "" {
		var err error
		token, err = ObtainToken(ctx, base, os.Getenv("DD_ADMIN_USER"), os.Getenv("DD_ADMIN_PASSWORD"))
		must(t, err)
	}
	client := NewHTTPClient(base, token)
	org, err := client.GetOrCreateOrganization(ctx, "asi-it-d4")
	must(t, err)
	randBytes := make([]byte, 2)
	_, err = rand.Read(randBytes)
	must(t, err)
	ip := fmt.Sprintf("198.19.%d.%d", randBytes[0], randBytes[1])
	slug := fmt.Sprintf("it-d4-%x", randBytes)
	assets, err := client.ListAssets(ctx, AssetQuery{Name: ip})
	must(t, err)
	if len(assets.Results) > 0 {
		t.Fatalf("test address %s is already in use", ip)
	}
	asset, err := client.GetOrCreateAsset(ctx, AssetSpec{
		Name: ip, Description: "D4 integration test", OrganizationID: org.ID, Tags: []string{"user:ops"},
	})
	must(t, err)
	t.Cleanup(func() { deleteAsset(t, client, asset.ID) })

	var profileID int64
	err = pool.QueryRow(ctx, `INSERT INTO profiles (name, ports, miss_threshold)
		VALUES ($1, '80,443', 2) RETURNING id`, slug).Scan(&profileID)
	must(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO targets (kind, value, source) VALUES ('ip', $1, 'manual')`, ip)
	must(t, err)

	nmapResult := parsedFixture(t, nmap.Parse, bytes.ReplaceAll(fixture(t, "nmap/testdata/lab.xml"), []byte(ipWeb.String()), []byte(ip)))
	firstHTTP := bytes.SplitN(fixture(t, "httpx/testdata/nginx.jsonl"), []byte("\n"), 2)[0]
	httpResult := parsedFixture(t, httpx.Parse, bytes.ReplaceAll(firstHTTP, []byte("172.21.0.2"), []byte(ip)))
	firstHit := bytes.SplitN(fixture(t, "nuclei/testdata/lab-http.jsonl"), []byte("\n"), 2)[0]
	nucleiResult := parsedFixture(t, nuclei.Parse, bytes.ReplaceAll(firstHit, []byte("172.30.0.17"), []byte(ip)))
	var responding, httpUp, match atomic.Bool
	responding.Store(true)
	httpUp.Store(true)
	match.Store(true)
	parsers := map[string]ParseFunc{"nmap": nmap.Parse, "httpx": httpx.Parse, "nuclei": nuclei.Parse}
	push, err := NewPushService(pool, parsers)
	must(t, err)
	pusher := &Pusher{Client: client, OrganizationID: org.ID}
	push.SetPusher(pusher)
	must(t, push.Start(ctx))
	scan, err := pipeline.New(pool, pipeline.Config{Hook: push,
		Scanner: artifactScanner{"nmap", "Nmap Scan", func() *scanner.Result {
			if responding.Load() {
				return nmapResult
			}
			return &scanner.Result{}
		}},
		HTTPX: artifactScanner{"httpx", "httpx Scan", func() *scanner.Result {
			if httpUp.Load() {
				return httpResult
			}
			return &scanner.Result{}
		}},
		Nuclei: artifactScanner{"nuclei", "Nuclei Scan", func() *scanner.Result {
			if match.Load() {
				return nucleiResult
			}
			return &scanner.Result{Raw: []byte{}}
		}},
	})
	must(t, err)
	must(t, scan.Start(ctx))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		must(t, scan.Shutdown(ctx))
		must(t, push.Shutdown(ctx))
	})

	run := func(up bool, wantInactive bool) int64 {
		t.Helper()
		r, err := scan.StartRun(ctx, nil, profileID)
		must(t, err)
		for ctx.Err() == nil {
			r, err = scan.GetRun(ctx, r.ID)
			must(t, err)
			var stats struct {
				Inactive []string                 `json:"inactive_ips"`
				Push     struct{ OK, Failed int } `json:"dojo_push"`
			}
			must(t, json.Unmarshal(r.Stats, &stats))
			if r.Status == "failed" || stats.Push.Failed != 0 {
				t.Fatalf("run %d failed: %s", r.ID, r.Stats)
			}
			if r.Status == "done" && (!up || stats.Push.OK == 1) {
				if slices.Contains(stats.Inactive, ip) != wantInactive {
					t.Fatalf("run %d inactive IPs = %v, want %s present = %v", r.ID, stats.Inactive, ip, wantInactive)
				}
				return r.ID
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("run %d did not finish with a successful push: %s", r.ID, r.Stats)
		return 0
	}
	findings := func() []Finding {
		t.Helper()
		page, err := client.ListFindings(ctx, FindingQuery{AssetID: asset.ID, Limit: 100})
		must(t, err)
		return page.Results
	}
	assertFindings := func(fs []Finding, scanType string, wantActive bool) {
		t.Helper()
		var count int
		for _, f := range fs {
			if f.TestTypeName == scanType {
				count++
				if f.Active != wantActive || !slices.Contains(f.Tags, TagASI) {
					t.Errorf("%s %q: active=%v, tags=%v", scanType, f.Title, f.Active, f.Tags)
				}
			}
		}
		if count == 0 {
			t.Fatalf("missing %s findings among %v", scanType, titles(fs))
		}
	}

	run(true, false)
	fs := findings()
	for _, scanType := range []string{"Nmap Scan", "httpx Scan", "Nuclei Scan"} {
		assertFindings(fs, scanType, true)
	}
	updated, err := client.GetAsset(ctx, asset.ID)
	must(t, err)
	for _, tag := range []string{"asi", "user:ops", "tech:nginx", "tech:wordpress"} {
		if !slices.Contains(updated.Tags, tag) {
			t.Fatalf("asset tags %v lack %s", updated.Tags, tag)
		}
	}
	t.Logf("asset %d (%s) tags=%v findings=%v", asset.ID, ip, updated.Tags, titles(fs))

	httpUp.Store(false)
	run(true, false)
	fs = findings()
	assertFindings(fs, "httpx Scan", true)
	assertFindings(fs, "Nuclei Scan", true)

	httpUp.Store(true)
	match.Store(false)
	run(true, false)
	assertFindings(findings(), "Nuclei Scan", false)

	responding.Store(false)
	run(false, false)
	offlineRun := run(false, true)
	run(false, false)
	for ctx.Err() == nil {
		var jobs, completed int
		err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE state = 'completed')
			FROM river_job WHERE kind = 'dojo_host_offline' AND args->>'run_id' = $1`, fmt.Sprint(offlineRun)).Scan(&jobs, &completed)
		must(t, err)
		if jobs == 1 && completed == 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	must(t, ctx.Err())
	var offlineJobs int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'dojo_host_offline'`).Scan(&offlineJobs))
	if offlineJobs != 1 {
		t.Fatalf("queued %d offline jobs for one transition", offlineJobs)
	}
	must(t, push.pushOfflineRun(ctx, pusher, offlineRun))
	must(t, pusher.pushOffline(ctx, "other-profile", time.Now(), PushHost{IP: netip.MustParseAddr(ip)}))
	fs = findings()
	assertFindings(fs, "Nmap Scan", true)
	assertFindings(fs, "httpx Scan", true)
	assertFindings(fs, GenericScanType, true)
	byUID := make(map[string]int)
	for _, f := range fs {
		byUID[f.UniqueIDFromTool]++
	}
	if byUID["asi-host-offline:"+ip] != 1 || byUID["asi-new-device:"+ip] != 1 {
		t.Fatalf("want exactly one offline and new-device finding: %v", titles(fs))
	}
	t.Logf("run %d had one offline job, lifecycle after retry and another profile: %v", offlineRun, titles(fs))
}
