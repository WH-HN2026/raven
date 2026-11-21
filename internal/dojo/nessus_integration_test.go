//go:build integration

package dojo

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIntegrationPushNessus pushes per-IP .nessus slices against the shared
// compose DefectDojo and verifies a "Tenable Scan" Test and its findings are
// created on the matching IP's Asset. Uses a random 198.18.R.0/24 range under
// org "raven-it-p3-exchange" and cleans up created assets afterwards.
func TestIntegrationPushNessus(t *testing.T) {
	base := os.Getenv("RAVEN_DOJO_URL")
	if base == "" {
		t.Skip("RAVEN_DOJO_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	prefix := fmt.Sprintf("198.18.%d.", rnd[0])
	ip1 := netip.MustParseAddr(prefix + "10")

	raw, err := os.ReadFile("../exchange/testdata/sample.nessus")
	must(t, err)
	// Keep only the first ReportHost rewritten to ip1.
	text := strings.ReplaceAll(string(raw), "172.30.0.10", ip1.String())
	if idx := strings.Index(text, `  <ReportHost name="ssh.lab">`); idx > 0 {
		end := strings.Index(text[idx:], "</Report>")
		text = text[:idx] + text[idx+end:]
	}

	org, err := c.GetOrCreateOrganization(ctx, "raven-it-p3-exchange")
	must(t, err)
	p := &Pusher{Client: c, OrganizationID: org.ID, Parallel: 2}

	res := p.PushNessus(ctx, NessusBatch{
		Profile:  "it-p3-exchange",
		ScanDate: time.Now().UTC(),
		Hosts: []NessusHost{
			{IP: ip1, Hostnames: []string{"web.p3-exchange"}, Report: []byte(text)},
		},
	})
	if len(res) != 1 {
		t.Fatalf("len(res) = %d, want 1", len(res))
	}
	if res[0].AssetID != 0 {
		id := res[0].AssetID
		t.Cleanup(func() { deleteObj(t, c, "assets", id) })
	}
	must(t, res[0].Err)
	if res[0].TestID == 0 || res[0].Total < 2 {
		t.Fatalf("unexpected nessus push result: %+v", res[0])
	}

	// Verify via Dojo API that the Test is "Tenable Scan" on the matching IP Asset.
	var testObj map[string]any
	must(t, c.do(ctx, "GET", "/api/v2/tests/"+itoa(res[0].TestID)+"/", nil, nil, &testObj))
	testJSON, _ := json.MarshalIndent(testObj, "", "  ")
	t.Logf("Dojo Test API output for asset %s (id=%d):\n%s", ip1, res[0].AssetID, testJSON)

	if gotType, _ := testObj["scan_type"].(string); gotType != TenableScanType {
		t.Fatalf("test scan_type = %q, want %q", gotType, TenableScanType)
	}
	if gotTitle, _ := testObj["title"].(string); gotTitle != "RAVEN: nessus" {
		t.Fatalf("test title = %q, want %q", gotTitle, "RAVEN: nessus")
	}

	pg, err := c.ListFindings(ctx, FindingQuery{TestID: res[0].TestID, Related: true, Limit: 50})
	must(t, err)
	if len(pg.Results) < 2 {
		t.Fatalf("got %d findings on Tenable Scan test, want >= 2", len(pg.Results))
	}
	findingsJSON, _ := json.MarshalIndent(pg.Results, "", "  ")
	t.Logf("Dojo Findings API output (%d findings):\n%s", len(pg.Results), findingsJSON)

	for _, f := range pg.Results {
		aid, aname := f.Asset()
		if aid != res[0].AssetID || aname != ip1.String() {
			t.Fatalf("finding %d asset = (%d, %q), want (%d, %q)", f.ID, aid, aname, res[0].AssetID, ip1)
		}
		if f.TestTypeName != TenableScanType {
			t.Fatalf("finding %d test_type_name = %q, want %q", f.ID, f.TestTypeName, TenableScanType)
		}
	}
}
