//go:build integration

package dojo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/dbtest"
)

// TestIntegrationCVE runs the C3 path end to end: services in a real DB →
// match pass → cve_matches → push to the shared Dojo into "RAVEN CVE match",
// then checks the change from aggregated to per-CVE findings, UID dedup, and
// closure on version change. IPs are benchmark addresses in a test-specific organization.
func TestIntegrationCVE(t *testing.T) {
	base := os.Getenv("RAVEN_DOJO_URL")
	if base == "" {
		t.Skip("RAVEN_DOJO_URL not set")
	}
	pool := dbtest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	token := os.Getenv("RAVEN_DOJO_TOKEN")
	if token == "" {
		var err error
		if token, err = ObtainToken(ctx, base, os.Getenv("DD_ADMIN_USER"), os.Getenv("DD_ADMIN_PASSWORD")); err != nil {
			t.Fatal(err)
		}
	}
	c := NewHTTPClient(base, token)
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	slug := "raven-it-u4-" + hex.EncodeToString(rnd)
	net := fmt.Sprintf("198.18.%d.", rnd[0])
	web, ssh, down := netip.MustParseAddr(net+"10"), netip.MustParseAddr(net+"11"), netip.MustParseAddr(net+"12")
	t.Logf("slug %s ips %s %s %s", slug, web, ssh, down)

	org, err := c.GetOrCreateOrganization(ctx, slug)
	must(t, err)
	t.Cleanup(func() { deleteObj(t, c, "organizations", org.ID) })

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO hosts (ip, state) VALUES ($1, 'active'), ($2, 'active'), ($3, 'inactive')`, web, ssh, down)
	exec(`INSERT INTO services (ip, port, proto, name, product, version, cpe, banner_enc) VALUES
		($1, 80, 'tcp', 'http', 'Apache httpd', '2.4.49', 'apache:http_server:2.4.49', NULL),
		($2, 22, 'tcp', 'ssh', 'OpenSSH', '7.4p1 Debian 10+deb9u7', 'openbsd:openssh:7.4p1', raven_enc('SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7')),
		($3, 80, 'tcp', 'http', 'Apache httpd', '2.4.49', 'apache:http_server:2.4.49', NULL),
		($1, 443, 'tcp', 'https', 'nginx', '', 'igor_sysoev:nginx', NULL)`, web, ssh, down)
	// Also add an HTTP observation on web:80 reporting BOTH Apache HTTP Server:2.4.49
	// (same product as nmap → must dedup to 1) AND WordPress:6.4.1 (web tech only → must produce its own CVE match).
	exec(`INSERT INTO http_observations (service_id, url, status, title, technologies, cpes)
		SELECT id, 'http://' || host(ip) || ':80', 200, 'WP',
		       ARRAY['Apache HTTP Server:2.4.49', 'WordPress:6.4.1'],
		       ARRAY['apache:http_server:2.4.49', 'wordpress:wordpress:6.4.1']
		FROM services WHERE ip = $1 AND port = 80`, web)

	m, err := cve.Default()
	must(t, err)
	assets := map[int64]bool{}
	sync := &CVESync{Pool: pool, Matcher: m, Pusher: &CVEPusher{Client: c, OrganizationID: org.ID}}
	once := func() {
		t.Helper()
		must(t, sync.Once(ctx))
		pg, err := c.ListAssets(ctx, AssetQuery{OrganizationID: org.ID, Limit: 100})
		must(t, err)
		for _, a := range pg.Results {
			if !assets[a.ID] {
				assets[a.ID] = true
				id := a.ID
				t.Cleanup(func() { deleteObj(t, c, "assets", id) })
			}
		}
	}
	_, err = cve.RunPass(ctx, pool, m, time.Now())
	must(t, err)

	// cve_matches: 4 rows (Apache + WordPress on web:80, OpenSSH on ssh:22, Apache on down:80;
	// nmap+httpx Apache on web:80 deduplicated to 1; nginx without a version doesn't match).
	all, err := cve.List(ctx, pool, netip.Addr{})
	must(t, err)
	if len(all) != 4 {
		t.Fatalf("cve_matches = %d rows, want 4: %+v", len(all), all)
	}
	byKey := map[string]cve.Match{}
	for _, x := range all {
		byKey[x.IP.String()+"|"+x.CPE] = x
	}
	ap, wp, sh := byKey[web.String()+"|apache:http_server"], byKey[web.String()+"|wordpress:wordpress"], byKey[ssh.String()+"|openbsd:openssh"]
	if ap.Confidence != "high" || ap.KEV == 0 || ap.Severity != "Critical" {
		t.Errorf("apache match: %+v", ap)
	}
	if wp.Version != "6.4.1" || len(wp.Hits) == 0 {
		t.Errorf("wordpress web-tech match: %+v", wp)
	}
	if sh.Confidence != "low" || !sh.Distro || sh.Severity != "Low" {
		t.Errorf("openssh debian match: %+v", sh)
	}
	asset, err := c.GetOrCreateAsset(ctx, AssetSpec{Name: web.String(), Description: "U4 integration test", OrganizationID: org.ID, Tags: []string{slug}})
	must(t, err)
	assets[asset.ID] = true
	t.Cleanup(func() { deleteObj(t, c, "assets", asset.ID) })
	eng, err := c.GetOrCreateEngagement(ctx, EngagementSpec{AssetID: asset.ID, Name: EngagementName(DefaultCVEProfile)})
	must(t, err)
	test, err := c.GetOrCreateTest(ctx, TestSpec{EngagementID: eng.ID, ScanType: GenericScanType, Title: cve.TestTitle})
	must(t, err)
	ids := make([]string, 0, len(ap.Hits))
	for _, h := range ap.Hits {
		ids = append(ids, h.ID)
	}
	legacy, err := json.Marshal(map[string]any{"findings": []map[string]any{{
		"title": fmt.Sprintf("%s %s: %d known CVEs (%d KEV)", ap.Name, ap.Version, len(ap.Hits), ap.KEV), "description": "Aggregate report", "severity": ap.Severity,
		"unique_id_from_tool": ap.UID(), "vulnerability_ids": ids,
		"component_name": ap.Name, "component_version": ap.Version,
		"tags": ap.FindingTags(), "active": true, "static_finding": true,
	}}})
	must(t, err)
	_, err = c.ReimportScan(ctx, ImportRequest{
		ScanType: GenericScanType, TestID: test.ID, FileName: "raven-cve-legacy.json",
		File: bytes.NewReader(legacy), CloseOldFindings: true, ScanDate: time.Now(),
	})
	must(t, err)
	must(t, cve.MarkPushed(ctx, pool, web, "old-aggregate-hash", time.Now()))

	findings := func() map[string]Finding {
		t.Helper()
		out := map[string]Finding{}
		for offset := 0; ; {
			pg, err := c.ListFindings(ctx, FindingQuery{OrganizationID: org.ID, Limit: 100, Offset: offset})
			must(t, err)
			for _, f := range pg.Results {
				if _, ok := out[f.UniqueIDFromTool]; ok {
					t.Fatalf("duplicate UID %q in Dojo", f.UniqueIDFromTool)
				}
				out[f.UniqueIDFromTool] = f
			}
			if pg.Next == "" {
				return out
			}
			offset += len(pg.Results)
		}
	}
	legacyFinding := findings()[ap.UID()]
	if !legacyFinding.Active {
		t.Fatalf("legacy finding was not active before reimport: %+v", legacyFinding)
	}

	once()
	var pushed int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM cve_push`).Scan(&pushed))
	if pushed != 2 || len(assets) != 2 {
		t.Errorf("pushed IPs = %d, assets = %d, want 2 each (inactive host is skipped)", pushed, len(assets))
	}
	fs := findings()
	closed := fs[ap.UID()]
	if closed.ID != legacyFinding.ID || closed.Active || !closed.IsMitigated {
		t.Errorf("legacy finding after per-CVE reimport: %+v", closed)
	}

	checkActive := func(fs map[string]Finding, m cve.Match) {
		t.Helper()
		for _, h := range m.Hits {
			f := fs[m.FindingUID(h.ID)]
			if !f.Active || f.Duplicate || f.Severity != cve.Severity(h.CVSS, h.KEV, m.Distro) || !contains(f.Tags, "raven") ||
				(m.Distro && !contains(f.Tags, cve.TagDistroBuild)) {
				t.Errorf("%s: invalid active finding: %+v", m.FindingUID(h.ID), f)
			}
		}
	}
	checkActive(fs, ap)
	checkActive(fs, wp)
	checkActive(fs, sh)
	wantActive := len(ap.Hits) + len(wp.Hits) + len(sh.Hits)
	if len(fs) != 1+wantActive {
		t.Fatalf("got %d findings, want %d per-CVE findings and one legacy finding", len(fs), wantActive)
	}
	var detail struct {
		VulnerabilityIDs []struct {
			ID string `json:"vulnerability_id"`
		} `json:"vulnerability_ids"`
	}
	hit := ap.Hits[0]
	must(t, c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v2/findings/%d/", fs[ap.FindingUID(hit.ID)].ID), nil, nil, &detail))
	if len(detail.VulnerabilityIDs) != 1 || detail.VulnerabilityIDs[0].ID != hit.ID {
		t.Errorf("Dojo vulnerability IDs for %s: %+v", hit.ID, detail.VulnerabilityIDs)
	}
	t.Logf("legacy finding %d mitigated, %d per-CVE findings active (%d Apache)", closed.ID, wantActive, len(ap.Hits))

	mirror := Syncer{Client: c, Pool: pool, OrganizationID: org.ID}
	stats, err := mirror.SyncOnce(ctx)
	must(t, err)
	var activeInMirror int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM dojo_findings WHERE active`).Scan(&activeInMirror))
	if stats.Findings != len(fs) || activeInMirror != wantActive {
		t.Errorf("mirror synced %d findings and contains %d active, want %d and %d", stats.Findings, activeInMirror, len(fs), wantActive)
	}

	// Force a Dojo reimport of the same UIDs and verify it retains the finding IDs.
	_, err = sync.Pusher.Push(ctx, cve.PushHost{IP: web, Matches: []cve.Match{ap, wp}}, time.Now())
	must(t, err)
	if reimported := findings(); len(reimported) != len(fs) {
		t.Errorf("unchanged Dojo reimport produced %d findings, want %d", len(reimported), len(fs))
	} else {
		for uid, f := range fs {
			if g := reimported[uid]; g.ID != f.ID || g.Active != f.Active {
				t.Errorf("unchanged Dojo reimport changed %s: before %+v, after %+v", uid, f, g)
			}
		}
	}

	// Second pass: nothing changed → no push, no duplicates.
	var at1, at2 time.Time
	must(t, pool.QueryRow(ctx, `SELECT pushed_at FROM cve_push WHERE ip = $1`, web).Scan(&at1))
	once()
	must(t, pool.QueryRow(ctx, `SELECT pushed_at FROM cve_push WHERE ip = $1`, web).Scan(&at2))
	if !at1.Equal(at2) {
		t.Errorf("unchanged match set was pushed again")
	}
	if n := len(findings()); n != len(fs) {
		t.Errorf("findings after second pass = %d, want %d", n, len(fs))
	}

	// Version change: old findings close and findings for the new version open.
	exec(`UPDATE services SET version = '2.4.50', cpe = 'apache:http_server:2.4.50' WHERE ip = $1 AND port = 80`, web)
	exec(`UPDATE http_observations SET technologies = ARRAY['Apache HTTP Server:2.4.50', 'WordPress:6.4.1'], cpes = ARRAY['apache:http_server:2.4.50', 'wordpress:wordpress:6.4.1']`)
	once()
	got, err := cve.List(ctx, pool, web)
	must(t, err)
	var apNew *cve.Match
	for i := range got {
		if got[i].CPE == "apache:http_server" {
			apNew = &got[i]
		}
	}
	if len(got) != 2 || apNew == nil || apNew.Version != "2.4.50" {
		t.Fatalf("matches of %s after upgrade: %+v", web, got)
	}
	afterUpgrade := findings()
	for _, h := range ap.Hits {
		uid := ap.FindingUID(h.ID)
		f := afterUpgrade[uid]
		if f.ID != fs[uid].ID || f.Active || !f.IsMitigated {
			t.Errorf("old version finding %s after upgrade: %+v", uid, f)
		}
	}
	checkActive(afterUpgrade, *apNew)
	checkActive(afterUpgrade, wp)
	t.Logf("upgrade mitigated %d Apache %s findings and activated %d Apache %s findings",
		len(ap.Hits), ap.Version, len(apNew.Hits), apNew.Version)
}
