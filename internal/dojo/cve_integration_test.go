//go:build integration

package dojo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/dbtest"
)

// TestIntegrationCVE runs the C3 path end to end: services in a real DB →
// match pass → cve_matches → push to the shared Dojo into "RAVEN CVE match",
// then checks dedup on a second pass and that a version change closes the
// old finding. IPs are random 198.18.R.x (benchmark range, never scanned),
// under the organization "raven-it-c3-<rand>", deleted afterwards.
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
	slug := "raven-it-c3-" + hex.EncodeToString(rnd)
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
	once()

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
	var pushed int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM cve_push`).Scan(&pushed))
	if pushed != 2 {
		t.Errorf("pushed IPs = %d, want 2 (the inactive host must not be pushed)", pushed)
	}
	if len(assets) != 2 {
		t.Errorf("dojo assets = %d, want 2", len(assets))
	}

	findings := func() []Finding {
		t.Helper()
		pg, err := c.ListFindings(ctx, FindingQuery{OrganizationID: org.ID, Limit: 100})
		must(t, err)
		return pg.Results
	}
	find := func(fs []Finding, title string) (active, inactive []Finding) {
		for _, f := range fs {
			if strings.EqualFold(f.Title, title) { // Dojo title-cases titles
				if f.Active {
					active = append(active, f)
				} else {
					inactive = append(inactive, f)
				}
			}
		}
		return active, inactive
	}
	fs := findings()
	t.Logf("findings: %v", titles(fs))
	act, _ := find(fs, ap.Title())
	if len(act) != 1 {
		t.Fatalf("active %q = %d, want 1 (all: %v)", ap.Title(), len(act), titles(fs))
	}
	apacheID := act[0].ID
	if act[0].Severity != "Critical" || !contains(act[0].Tags, "raven") {
		t.Errorf("apache finding: severity %s tags %v", act[0].Severity, act[0].Tags)
	}
	var detail struct {
		VulnerabilityIDs []struct {
			ID string `json:"vulnerability_id"`
		} `json:"vulnerability_ids"`
		UniqueID string `json:"unique_id_from_tool"`
	}
	must(t, c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v2/findings/%d/", apacheID), nil, nil, &detail))
	if len(detail.VulnerabilityIDs) != len(ap.Hits) || detail.UniqueID != ap.UID() {
		t.Errorf("apache finding: %d vulnerability_ids (want %d), uid %q (want %q)",
			len(detail.VulnerabilityIDs), len(ap.Hits), detail.UniqueID, ap.UID())
	}
	sact, _ := find(fs, sh.Title())
	if len(sact) != 1 || sact[0].Severity != "Low" || !contains(sact[0].Tags, cve.TagDistroBuild) {
		t.Errorf("openssh finding: %+v", sact)
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

	// Version change: the old finding closes, a new one opens (update both nmap service and httpx obs).
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
	fs = findings()
	_, closed := find(fs, ap.Title())
	nact, _ := find(fs, apNew.Title())
	if len(closed) != 1 || closed[0].ID != apacheID || len(nact) != 1 {
		t.Errorf("after version change: closed %v, new active %v (all: %v)", closed, nact, titles(fs))
	}
	t.Logf("old %q closed, new %q; wp %q active", ap.Title(), apNew.Title(), wp.Title())
}
