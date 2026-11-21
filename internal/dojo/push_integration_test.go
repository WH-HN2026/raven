//go:build integration

package dojo

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

// TestIntegrationPush runs the push path against the shared compose Dojo with
// the S2 fixture. Its IPs are rewritten to a random 198.18.R.0/24 (benchmark
// range, never scanned) so the IP-named assets are unique per test run; they
// live under the organization "raven-it-d2" and are deleted afterwards.
func TestIntegrationPush(t *testing.T) {
	base := os.Getenv("RAVEN_DOJO_URL")
	if base == "" {
		t.Skip("RAVEN_DOJO_URL not set")
	}
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

	rnd := make([]byte, 1)
	_, _ = rand.Read(rnd)
	net := fmt.Sprintf("198.18.%d.", rnd[0])
	raw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	must(t, err)
	res, err := nmap.Parse([]byte(strings.ReplaceAll(string(raw), "172.31.250.", net)))
	must(t, err)
	web, ssh := netip.MustParseAddr(net+"10"), netip.MustParseAddr(net+"11")
	t.Logf("ips %s %s", web, ssh)

	org, err := c.GetOrCreateOrganization(ctx, "raven-it-d2")
	must(t, err)
	p := &Pusher{Client: c, OrganizationID: org.ID, Parallel: c.Concurrency()}
	seen := time.Now().Add(-time.Hour)
	batch := func(webAsset, sshAsset int64) PushBatch {
		return PushBatch{RunID: 1, BatchID: 1, Profile: "it-d2", Scanner: "nmap", ScanType: "Nmap Scan",
			ScanDate: time.Now(), Hosts: []PushHost{
				{IP: web, Hostnames: []string{"web.it-d2"}, FirstSeen: seen, OpenPorts: []string{"80/tcp", "443/tcp"},
					AssetID: webAsset, Report: res.PerIP(web)},
				{IP: ssh, FirstSeen: seen, OpenPorts: []string{"22/tcp"}, AssetID: sshAsset, Report: res.PerIP(ssh)},
			}}
	}
	push := func(b PushBatch) []HostResult {
		t.Helper()
		out := p.Push(ctx, b)
		for _, r := range out {
			if r.AssetID != 0 {
				id := r.AssetID
				t.Cleanup(func() { deleteObj(t, c, "assets", id) })
			}
			must(t, r.Err)
		}
		return out
	}

	// First push: chain created, new device for both.
	out := push(batch(0, 0))
	if !out[0].NewDevice || !out[1].NewDevice {
		t.Fatalf("first push new-device flags: %+v", out)
	}
	webID, sshID := out[0].AssetID, out[1].AssetID

	// Second push, and a duplicated "first" push (retry before dojo_asset_id was stored).
	push(batch(webID, sshID))
	push(batch(0, sshID))

	findings := func(assetID int64) []Finding {
		t.Helper()
		var all []Finding
		for off := 0; ; off += 100 {
			pg, err := c.ListFindings(ctx, FindingQuery{OrganizationID: org.ID, Related: true, Limit: 100, Offset: off})
			must(t, err)
			for _, f := range pg.Results {
				if id, _ := f.Asset(); id == assetID {
					all = append(all, f)
				}
			}
			if pg.Next == "" {
				return all
			}
		}
	}
	count := func(fs []Finding, title string, activeOnly bool) (n int, last Finding) {
		for _, f := range fs {
			// Dojo title-cases titles ("New Device Found: …", "Open Port: 80/TCP").
			if strings.EqualFold(f.Title, title) && (!activeOnly || f.Active) {
				n++
				last = f
			}
		}
		return n, last
	}

	fs := findings(webID)
	for _, f := range fs {
		if !contains(f.Tags, "raven") {
			t.Errorf("finding %d %q not tagged raven: %v", f.ID, f.Title, f.Tags)
		}
	}
	if n, _ := count(fs, "New device found: "+web.String(), false); n != 1 {
		t.Fatalf("web new-device findings = %d, want exactly 1 (all: %v)", n, titles(fs))
	}
	if n, _ := count(findings(sshID), "New device found: "+ssh.String(), false); n != 1 {
		t.Fatalf("ssh new-device findings = %d, want 1", n)
	}
	n, port80 := count(fs, "Open port: 80/tcp", true)
	if n != 1 {
		t.Fatalf("active 'Open port: 80/tcp' = %d, want 1 (all: %v)", n, titles(fs))
	}

	// A severity edit (our UI → PATCH) survives the next reimport: same finding, still active.
	high := "High"
	_, err = c.PatchFinding(ctx, port80.ID, FindingPatch{Severity: &high})
	must(t, err)
	push(batch(webID, sshID))
	fs = findings(webID)
	n, after := count(fs, "Open port: 80/tcp", true)
	if n != 1 || after.ID != port80.ID || after.Severity != "High" {
		t.Fatalf("after severity edit + reimport: %d active, id %d (want %d), severity %q; all: %v",
			n, after.ID, port80.ID, after.Severity, titles(fs))
	}
	if total, _ := count(fs, "Open port: 80/tcp", false); total != 1 {
		t.Fatalf("'Open port: 80/tcp' findings in total = %d, want 1 (no close + recreate)", total)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func titles(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%d:%s(active=%v,%s)", f.ID, f.Title, f.Active, f.Severity))
	}
	return out
}
