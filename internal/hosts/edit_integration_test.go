//go:build integration

package hosts

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dojo"
)

// scanCols are the scan-owned host columns; an edit must leave them as they were.
const scanCols = `SELECT hostnames::text, state, first_seen::text, last_seen::text, miss_count, COALESCE(dojo_asset_id, 0) FROM hosts WHERE ip = $1`

// TestIntegrationHostEdit: user fields on a host with a Dojo asset (in its
// own organization "asi-it-d6h-<random>" on the shared Dojo), on a host
// without one, and service overrides. Deletes what it created in Dojo.
func TestIntegrationHostEdit(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	Seed(t, pool)
	var actor int64
	if err := pool.QueryRow(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('d6', 'x', 'operator') RETURNING id`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	scanned := func(ip string) string {
		t.Helper()
		var h, st, fs, ls string
		var miss int
		var asset int64
		must(pool.QueryRow(ctx, scanCols, ip).Scan(&h, &st, &fs, &ls, &miss, &asset))
		return fmt.Sprint(h, st, fs, ls, miss, asset)
	}

	// Host without a Dojo asset: saved, write-through pending.
	before := scanned("10.10.0.3")
	res, err := Edit(ctx, pool, nil, &actor, netip.MustParseAddr("10.10.0.3"), Patch{
		Owner: sp(" ops "), Criticality: sp("Critical"), Notes: sp("rack 4, top secret"), UserTags: &[]string{"Prod", "dmz"},
	})
	must(err)
	if res.DojoSync != DojoPending || res.Owner != "ops" || res.Criticality != "critical" ||
		res.Notes != "rack 4, top secret" || !slices.Equal(res.UserTags, []string{"dmz", "prod"}) {
		t.Fatalf("edit result = %+v %+v", res.Host, res.DojoSync)
	}
	if after := scanned("10.10.0.3"); after != before {
		t.Fatalf("scan-owned columns changed: %s → %s", before, after)
	}
	var raw []byte
	must(pool.QueryRow(ctx, `SELECT notes_enc FROM hosts WHERE ip = '10.10.0.3'`).Scan(&raw))
	if len(raw) == 0 || bytes.Contains(raw, []byte("top secret")) {
		t.Fatalf("notes_enc is not encrypted: %q", raw)
	}
	var diff string
	must(pool.QueryRow(ctx, `SELECT diff::text FROM audit_log WHERE action = 'host.update' AND object_id = '10.10.0.3' AND user_id = $1`, actor).Scan(&diff))
	if strings.Contains(diff, "top secret") || !strings.Contains(diff, `"notes": "changed"`) || !strings.Contains(diff, `"owner"`) {
		t.Fatalf("audit diff = %s", diff)
	}
	// Clearing notes nulls notes_enc.
	_, err = Edit(ctx, pool, nil, &actor, netip.MustParseAddr("10.10.0.3"), Patch{Notes: sp("")})
	must(err)
	must(pool.QueryRow(ctx, `SELECT notes_enc FROM hosts WHERE ip = '10.10.0.3'`).Scan(&raw))
	if raw != nil {
		t.Fatalf("notes_enc after clear = %q", raw)
	}
	if _, err := Edit(ctx, pool, nil, &actor, netip.MustParseAddr("10.99.0.1"), Patch{Owner: sp("x")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
	if _, err := Edit(ctx, pool, nil, &actor, netip.MustParseAddr("10.10.0.3"), Patch{Criticality: sp("urgent")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad criticality: %v", err)
	}

	// Service overrides: only services.overrides changes.
	var svcID int64
	must(pool.QueryRow(ctx, `SELECT id FROM services WHERE ip = '10.10.0.2' AND port = 80`).Scan(&svcID))
	svcScan := func() string {
		var s string
		must(pool.QueryRow(ctx, `SELECT concat_ws('|', name, product, version, state, first_seen, last_seen, asi_dec(banner_enc)) FROM services WHERE id = $1`, svcID).Scan(&s))
		return s
	}
	sb := svcScan()
	svc, err := EditServiceOverrides(ctx, pool, &actor, svcID, map[string]json.RawMessage{
		"version": json.RawMessage(`"1.25.4-custom"`), "product": json.RawMessage(`null`),
	})
	must(err)
	if svc.Product != "nginx" || svc.Version != "1.25.4-custom" || !slices.Equal(svc.Overridden, []string{"version"}) ||
		svc.Scan.Version != "1.25.3" || svc.Banner != "nginx banner" {
		t.Fatalf("service after override = %+v", svc)
	}
	if sa := svcScan(); sa != sb {
		t.Fatalf("scan-owned service columns changed: %s → %s", sb, sa)
	}
	if _, err := EditServiceOverrides(ctx, pool, &actor, svcID, map[string]json.RawMessage{"port": json.RawMessage(`"1"`)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad key: %v", err)
	}
	if _, err := EditServiceOverrides(ctx, pool, &actor, 1<<40, map[string]json.RawMessage{"name": json.RawMessage(`"x"`)}); !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("unknown service: %v", err)
	}

	// Host with a Dojo asset: description and tags are written through.
	base := os.Getenv("ASI_DOJO_URL")
	if base == "" {
		t.Skip("ASI_DOJO_URL not set: Dojo part skipped")
	}
	token := os.Getenv("ASI_DOJO_TOKEN")
	if token == "" {
		token, err = dojo.ObtainToken(ctx, base, os.Getenv("DD_ADMIN_USER"), os.Getenv("DD_ADMIN_PASSWORD"))
		must(err)
	}
	c := dojo.NewHTTPClient(base, token)
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	slug := "asi-it-d6h-" + hex.EncodeToString(rnd)
	ip := fmt.Sprintf("198.18.%d.%d", rnd[0], rnd[1]) // RFC 2544 benchmark range, never scanned
	t.Logf("slug %s ip %s", slug, ip)
	org, err := c.GetOrCreateOrganization(ctx, slug)
	must(err)
	asiTags := dojo.AssetTags([]string{"web.lab"}) // what the push sets: asi, host:web.lab
	asset, err := c.GetOrCreateAsset(ctx, dojo.AssetSpec{Name: ip, Description: "Host " + ip + " (managed by ASI)",
		OrganizationID: org.ID, Tags: append(slices.Clone(asiTags), slug, "user:stale")})
	must(err)
	t.Cleanup(func() {
		deleteDojo(t, base, token, "assets", asset.ID)
		deleteDojo(t, base, token, "organizations", org.ID)
	})
	_, err = pool.Exec(ctx, `INSERT INTO hosts (ip, hostnames, dojo_asset_id) VALUES ($1, '{web.lab}', $2)`, ip, asset.ID)
	must(err)

	before = scanned(ip)
	res, err = Edit(ctx, pool, c, &actor, netip.MustParseAddr(ip), Patch{
		Owner: sp("web team"), Criticality: sp("high"), Notes: sp("behind the WAF"), UserTags: &[]string{"dmz", "prod"},
	})
	must(err)
	if res.DojoSync != DojoSynced {
		t.Fatalf("dojo_sync = %s", res.DojoSync)
	}
	if after := scanned(ip); after != before {
		t.Fatalf("scan-owned columns changed: %s → %s", before, after)
	}
	a, err := c.GetAsset(ctx, asset.ID)
	must(err)
	wantTags := append(slices.Clone(asiTags), slug, "user:dmz", "user:prod")
	if !sameSet(a.Tags, wantTags) {
		t.Fatalf("asset tags = %v, want %v", a.Tags, wantTags)
	}
	for _, s := range []string{"**Owner:** web team", "**Criticality:** high", "behind the WAF"} {
		if !strings.Contains(a.Description, s) {
			t.Fatalf("asset description %q lacks %q", a.Description, s)
		}
	}
	var mirrorTags []string
	must(pool.QueryRow(ctx, `SELECT tags FROM dojo_assets WHERE id = $1`, asset.ID).Scan(&mirrorTags))
	if !sameSet(mirrorTags, wantTags) {
		t.Fatalf("mirror asset tags = %v", mirrorTags)
	}

	// Removing a user tag removes only its user: tag; ASI's tags stay.
	_, err = Edit(ctx, pool, c, &actor, netip.MustParseAddr(ip), Patch{UserTags: &[]string{"prod"}})
	must(err)
	a, err = c.GetAsset(ctx, asset.ID)
	must(err)
	if want := append(slices.Clone(asiTags), slug, "user:prod"); !sameSet(a.Tags, want) {
		t.Fatalf("asset tags after removal = %v, want %v", a.Tags, want)
	}
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// deleteDojo removes a test object (the client has no delete; ASI never deletes in Dojo).
func deleteDojo(t *testing.T, base, token, kind string, id int64) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v2/%s/%d/", strings.TrimRight(base, "/"), kind, id), nil)
	if err != nil {
		t.Error(err)
		return
	}
	req.Header.Set("Authorization", "Token "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("cleanup %s %d: %v", kind, id, err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		t.Errorf("cleanup %s %d: HTTP %d", kind, id, resp.StatusCode)
	}
}
