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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
)

// TestIntegrationSync: against the shared Dojo and a throwaway DB. It makes
// its own organization "asi-it-d3-<random>" with an IP-named asset (an
// imported nmap scan tagged "asi") and a slug-named asset, syncs, changes
// Dojo (reimport closes a finding, a finding and an asset are deleted),
// syncs again and checks the mirror. It deletes only what it created.
func TestIntegrationSync(t *testing.T) {
	base := os.Getenv("ASI_DOJO_URL")
	if base == "" {
		t.Skip("ASI_DOJO_URL not set")
	}
	pool := dbtest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	token := os.Getenv("ASI_DOJO_TOKEN")
	if token == "" {
		var err error
		if token, err = ObtainToken(ctx, base, os.Getenv("DD_ADMIN_USER"), os.Getenv("DD_ADMIN_PASSWORD")); err != nil {
			t.Fatal(err)
		}
	}
	c := NewHTTPClient(base, token)
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	slug := "asi-it-d3-" + hex.EncodeToString(rnd)
	ip := fmt.Sprintf("198.18.%d.%d", rnd[0], rnd[1]) // RFC 2544 benchmark range, never scanned
	t.Logf("slug %s ip %s", slug, ip)

	org, err := c.GetOrCreateOrganization(ctx, slug)
	must(t, err)
	t.Cleanup(func() { deleteObj(t, c, "organizations", org.ID) })
	hostAsset, err := c.GetOrCreateAsset(ctx, AssetSpec{Name: ip, Description: "D3 integration test", OrganizationID: org.ID, Tags: []string{"asi", slug}})
	must(t, err)
	t.Cleanup(func() { deleteObj(t, c, "assets", hostAsset.ID) })
	otherAsset, err := c.GetOrCreateAsset(ctx, AssetSpec{Name: slug, Description: "D3 integration test", OrganizationID: org.ID})
	must(t, err)
	otherDeleted := false
	t.Cleanup(func() {
		if !otherDeleted {
			deleteObj(t, c, "assets", otherAsset.ID)
		}
	})

	eng, err := c.GetOrCreateEngagement(ctx, EngagementSpec{AssetID: hostAsset.ID, Name: "ASI: it"})
	must(t, err)
	test, err := c.GetOrCreateTest(ctx, TestSpec{EngagementID: eng.ID, ScanType: "Nmap Scan", Title: "nmap"})
	must(t, err)
	reimport := func(file string) {
		t.Helper()
		_, err := c.ReimportScan(ctx, ImportRequest{
			ScanType: "Nmap Scan", TestID: test.ID, FileName: "nmap.xml", File: open(t, file),
			CloseOldFindings: true, Tags: []string{"asi", slug}, TagFindings: true, ScanDate: time.Now(),
		})
		must(t, err)
	}
	reimport("testdata/nmap_3ports.xml")

	s := &Syncer{Client: c, Pool: pool, OrganizationID: org.ID}
	st, err := s.SyncOnce(ctx)
	must(t, err)
	t.Logf("pass 1: %+v", st)
	if st.Assets != 2 || st.Findings != 3 || st.AssetsDeleted != 0 || st.FindingsDeleted != 0 {
		t.Fatalf("pass 1 stats = %+v", st)
	}

	assets := mirrorAssets(t, pool)
	if assets[hostAsset.ID] != ip || assets[otherAsset.ID] != "<nil>" {
		t.Fatalf("mirror assets = %v", assets)
	}
	rows := mirrorFindings(t, pool)
	if len(rows) != 3 {
		t.Fatalf("mirror findings = %+v", rows)
	}
	var port22 int64
	for id, r := range rows {
		if r.assetID != hostAsset.ID || r.ip != ip || r.severity != "Info" || !r.active || r.scanner != "nmap" {
			t.Fatalf("finding %d = %+v", id, r)
		}
		if strings.EqualFold(r.title, "Open port: 22/tcp") {
			port22 = id
		}
	}
	if port22 == 0 {
		t.Fatalf("no 22/tcp finding in %+v", rows)
	}

	// The read path with filters, on the rows just synced.
	pfx := netip.PrefixFrom(netip.MustParseAddr(ip), 32)
	yes := true
	items, total, err := ListMirrorFindings(ctx, pool, FindingFilter{
		Severities: []string{"Info"}, Active: &yes, IP: &pfx, Q: "22/TCP", Scanner: "nmap", Limit: 10,
	}, "http://dojo.example")
	must(t, err)
	if total != 1 || len(items) != 1 || items[0].ID != port22 || items[0].DojoURL != fmt.Sprintf("http://dojo.example/finding/%d", port22) {
		t.Fatalf("filtered list = %d %+v", total, items)
	}
	if _, total, err = ListMirrorFindings(ctx, pool, FindingFilter{Severities: []string{"High"}, Limit: 10}, ""); err != nil || total != 0 {
		t.Fatalf("severity=High total %d err %v", total, err)
	}

	// Dojo changes: 443 closes (reimport without it), 22 is deleted, the
	// non-IP asset is deleted.
	reimport("testdata/nmap_2ports.xml")
	deleteObj(t, c, "findings", port22)
	deleteObj(t, c, "assets", otherAsset.ID)
	otherDeleted = true

	st, err = s.SyncOnce(ctx)
	must(t, err)
	t.Logf("pass 2: %+v", st)
	if st.Assets != 1 || st.Findings != 2 || st.AssetsDeleted != 1 || st.FindingsDeleted != 1 {
		t.Fatalf("pass 2 stats = %+v", st)
	}
	if assets = mirrorAssets(t, pool); len(assets) != 1 || assets[hostAsset.ID] != ip {
		t.Fatalf("mirror assets after = %v", assets)
	}
	rows = mirrorFindings(t, pool)
	if _, ok := rows[port22]; ok || len(rows) != 2 {
		t.Fatalf("mirror findings after = %+v", rows)
	}
	for id, r := range rows {
		closed := strings.EqualFold(r.title, "Open port: 443/tcp")
		if r.active == closed || r.mitigated != closed {
			t.Fatalf("finding %d after = %+v", id, r)
		}
	}
}

type mirrorRow struct {
	assetID                      int64
	ip, title, severity, scanner string
	active, mitigated            bool
}

func mirrorAssets(t *testing.T, pool *pgxpool.Pool) map[int64]string {
	t.Helper()
	rows, err := pool.Query(context.Background(), "SELECT id, coalesce(host(ip), '<nil>') FROM dojo_assets")
	must(t, err)
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var ip string
		must(t, rows.Scan(&id, &ip))
		out[id] = ip
	}
	must(t, rows.Err())
	return out
}

func mirrorFindings(t *testing.T, pool *pgxpool.Pool) map[int64]mirrorRow {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		"SELECT id, coalesce(asset_id, 0), coalesce(host(ip), ''), title, severity, scanner, active, is_mitigated FROM dojo_findings")
	must(t, err)
	defer rows.Close()
	out := map[int64]mirrorRow{}
	for rows.Next() {
		var id int64
		var r mirrorRow
		must(t, rows.Scan(&id, &r.assetID, &r.ip, &r.title, &r.severity, &r.scanner, &r.active, &r.mitigated))
		out[id] = r
	}
	must(t, rows.Err())
	return out
}

// deleteObj deletes one Dojo object this test created; a 404 (already gone,
// e.g. cascaded) is fine.
func deleteObj(t *testing.T, c *HTTPClient, kind string, id int64) {
	t.Helper()
	err := c.do(context.Background(), http.MethodDelete, fmt.Sprintf("/api/v2/%s/%d/", kind, id), nil, nil, nil)
	if err != nil && !IsStatus(err, http.StatusNotFound) {
		t.Errorf("delete %s %d: %v", kind, id, err)
	}
}
