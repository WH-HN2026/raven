//go:build integration

package dojo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/targets"
)

// TestIntegrationDojo runs the whole client against the shared compose Dojo
// (RAVEN_DOJO_URL + RAVEN_DOJO_TOKEN or DD_ADMIN_USER/DD_ADMIN_PASSWORD, from
// .env.local). Every run makes a fresh asset "raven-it-d1-<random>" under the
// shared organization "raven-it-d1", and deletes only the assets it created.
func TestIntegrationDojo(t *testing.T) {
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
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	slug := "raven-it-d1-" + hex.EncodeToString(rnd)
	t.Logf("slug %s", slug)

	// Get-or-create is idempotent: twice → same id. The organization name is
	// fixed, so a second test run reuses it.
	org, err := c.GetOrCreateOrganization(ctx, "raven-it-d1")
	must(t, err)
	org2, err := c.GetOrCreateOrganization(ctx, "raven-it-d1")
	must(t, err)
	if org.ID != org2.ID {
		t.Fatalf("organization ids %d != %d", org.ID, org2.ID)
	}

	// Racing goroutines all get the one asset.
	spec := AssetSpec{Name: slug, Description: "D1 integration test", OrganizationID: org.ID, Tags: []string{"raven-it"}}
	ids := make([]int64, 4)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := c.GetOrCreateAsset(ctx, spec)
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = a.ID
		}()
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	asset := &Asset{ID: ids[0]}
	t.Cleanup(func() { deleteAsset(t, c, asset.ID) })
	for _, id := range ids {
		if id != asset.ID {
			t.Fatalf("racing get-or-create returned ids %v", ids)
		}
	}

	eng, err := c.GetOrCreateEngagement(ctx, EngagementSpec{AssetID: asset.ID, Name: "RAVEN: it", Tags: []string{"raven"}})
	must(t, err)
	eng2, err := c.GetOrCreateEngagement(ctx, EngagementSpec{AssetID: asset.ID, Name: "RAVEN: it"})
	must(t, err)
	if eng.ID != eng2.ID || eng.AssetID != asset.ID {
		t.Fatalf("engagements %+v %+v", eng, eng2)
	}

	test, err := c.GetOrCreateTest(ctx, TestSpec{EngagementID: eng.ID, ScanType: "Nmap Scan", Title: "nmap"})
	must(t, err)
	test2, err := c.GetOrCreateTest(ctx, TestSpec{EngagementID: eng.ID, ScanType: "Nmap Scan", Title: "nmap"})
	must(t, err)
	if test.ID != test2.ID || test.EngagementID != eng.ID {
		t.Fatalf("tests %+v %+v", test, test2)
	}

	// First reimport into the empty test: 3 open ports → 3 new findings.
	tags := []string{"raven", slug}
	r1, err := c.ReimportScan(ctx, ImportRequest{
		ScanType: "Nmap Scan", TestID: test.ID, FileName: "nmap.xml", File: open(t, "testdata/nmap_3ports.xml"),
		CloseOldFindings: true, Tags: tags, TagFindings: true, ScanDate: time.Now(),
	})
	must(t, err)
	t.Logf("reimport 1: %+v", *r1)
	if r1.TestID != test.ID || r1.AssetID != asset.ID || r1.Created != 3 || r1.Active != 3 {
		t.Fatalf("reimport 1 = %+v", *r1)
	}

	// Second reimport with 443 gone and close_old_findings → 1 closed.
	r2, err := c.ReimportScan(ctx, ImportRequest{
		ScanType: "Nmap Scan", TestID: test.ID, FileName: "nmap.xml", File: open(t, "testdata/nmap_2ports.xml"),
		CloseOldFindings: true, Tags: tags, TagFindings: true, ScanDate: time.Now(),
	})
	must(t, err)
	t.Logf("reimport 2: %+v", *r2)
	if r2.Closed != 1 || r2.Untouched != 2 || r2.Created != 0 || r2.Active != 2 {
		t.Fatalf("reimport 2 = %+v", *r2)
	}

	// List by tag: 3 findings, the 443 one closed.
	page, err := c.ListFindings(ctx, FindingQuery{Tags: []string{slug}})
	must(t, err)
	if page.Count != 3 {
		t.Fatalf("findings by tag %s: count %d", slug, page.Count)
	}
	var open22 *Finding
	for i, f := range page.Results {
		t.Logf("finding %d %q active=%v mitigated=%v tags=%v", f.ID, f.Title, f.Active, f.IsMitigated, f.Tags)
		if strings.EqualFold(f.Title, "Open port: 443/tcp") && (f.Active || !f.IsMitigated) {
			t.Errorf("443 finding should be closed: %+v", f)
		}
		if strings.EqualFold(f.Title, "Open port: 22/tcp") {
			open22 = &page.Results[i]
		}
	}
	if open22 == nil {
		t.Fatal("no 'Open port: 22/tcp' finding")
	}
	active := true
	act, err := c.ListFindings(ctx, FindingQuery{Tags: []string{slug}, Active: &active})
	must(t, err)
	if act.Count != 2 {
		t.Fatalf("active findings = %d, want 2", act.Count)
	}

	// Triage: patch, note. (Not severity here: "Nmap Scan" uses Dojo's legacy
	// dedup, which matches reimported findings on title+severity, so a
	// severity edit makes the next reimport close it and create a new one.)
	verified := true
	pf, err := c.PatchFinding(ctx, open22.ID, FindingPatch{Verified: &verified})
	must(t, err)
	if !pf.Verified || pf.ID != open22.ID {
		t.Fatalf("patched finding = %+v", pf)
	}
	must(t, c.AddFindingNote(ctx, open22.ID, "D1 integration test note"))

	// A third reimport of the same file keeps the triage (Dojo matches findings).
	r3, err := c.ReimportScan(ctx, ImportRequest{
		ScanType: "Nmap Scan", TestID: test.ID, FileName: "nmap.xml", File: open(t, "testdata/nmap_2ports.xml"),
		CloseOldFindings: true, Tags: tags, TagFindings: true,
	})
	must(t, err)
	if r3.Created != 0 || r3.Closed != 0 || r3.Untouched != 2 {
		t.Fatalf("reimport 3 = %+v", *r3)
	}
	after, err := c.ListFindings(ctx, FindingQuery{TestID: test.ID, Active: &active})
	must(t, err)
	for _, f := range after.Results {
		if f.ID == open22.ID && !f.Verified {
			t.Fatalf("reimport lost triage: %+v", f)
		}
	}

	// Asset tags replace.
	newTags := []string{"raven", slug, "host:it.example"}
	must(t, c.SetAssetTags(ctx, asset.ID, newTags))
	assets, err := c.ListAssets(ctx, AssetQuery{Tags: []string{slug}})
	must(t, err)
	if assets.Count != 1 || assets.Results[0].ID != asset.ID {
		t.Fatalf("assets by tag = %+v", assets)
	}
	got := slices.Sorted(slices.Values(assets.Results[0].Tags))
	if !slices.Equal(got, slices.Sorted(slices.Values(newTags))) {
		t.Fatalf("asset tags = %v", got)
	}

	// Engagement status.
	must(t, c.SetEngagementStatus(ctx, eng.ID, EngagementCompleted))
	engs, err := c.ListEngagements(ctx, EngagementQuery{AssetID: asset.ID, Status: EngagementCompleted})
	must(t, err)
	if engs.Count != 1 || engs.Results[0].ID != eng.ID {
		t.Fatalf("engagements = %+v", engs)
	}

	// import-scan with auto_create_context makes asset + engagement + test.
	autoName := slug + "-auto"
	ri, err := c.ImportScan(ctx, ImportRequest{
		ScanType: "Nmap Scan", AutoCreate: true, OrganizationName: org.Name, AssetName: autoName,
		EngagementName: "RAVEN: it", FileName: "nmap.xml", File: open(t, "testdata/nmap_3ports.xml"),
	})
	must(t, err)
	t.Cleanup(func() { deleteAsset(t, c, ri.AssetID) })
	t.Logf("import auto-create: %+v", *ri)
	if ri.TestID == 0 || ri.AssetID == 0 || ri.AssetID == asset.ID || ri.OrganizationID != org.ID || ri.Created != 3 {
		t.Fatalf("import = %+v", *ri)
	}

	// 4xx is not retried and carries Dojo's message.
	_, err = c.PatchFinding(ctx, open22.ID, FindingPatch{Severity: ptr("Bogus")})
	if !IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("bad severity err = %v", err)
	}
	t.Logf("expected 400: %v", err)
}

// TestIntegrationFetchTargets checks ListURLs (/api/v2/url/) and FetchTargets
// against the shared compose Dojo, creating and cleaning up only its own org
// and assets.
func TestIntegrationFetchTargets(t *testing.T) {
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
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	hexID := hex.EncodeToString(rnd)
	slug := "raven-it-d7-" + hexID
	ip := fmt.Sprintf("198.18.%d.%d", rnd[0], rnd[1])
	domain := fmt.Sprintf("d7-%s.example", hexID)
	nonTarget := "RAVEN Non Target " + hexID

	org, err := c.GetOrCreateOrganization(ctx, slug)
	must(t, err)
	t.Cleanup(func() {
		if err := c.do(context.Background(), http.MethodDelete, "/api/v2/organizations/"+itoa(org.ID)+"/", nil, nil, nil); err != nil {
			t.Errorf("cleanup org %d: %v", org.ID, err)
		}
	})

	aIP, err := c.GetOrCreateAsset(ctx, AssetSpec{Name: ip, Description: "D7 test IP", OrganizationID: org.ID, Tags: []string{"raven", "d7-custom"}})
	must(t, err)
	t.Cleanup(func() { deleteAsset(t, c, aIP.ID) })

	aDom, err := c.GetOrCreateAsset(ctx, AssetSpec{Name: domain, Description: "D7 test domain", OrganizationID: org.ID, Tags: []string{"d7-dom"}})
	must(t, err)
	t.Cleanup(func() { deleteAsset(t, c, aDom.ID) })

	aBad, err := c.GetOrCreateAsset(ctx, AssetSpec{Name: nonTarget, Description: "D7 test non-target", OrganizationID: org.ID})
	must(t, err)
	t.Cleanup(func() { deleteAsset(t, c, aBad.ID) })

	// Import a tiny scan so /api/v2/url/ is guaranteed non-empty even on a fresh Dojo.
	eng, err := c.GetOrCreateEngagement(ctx, EngagementSpec{AssetID: aIP.ID, Name: "RAVEN: d7"})
	must(t, err)
	test, err := c.GetOrCreateTest(ctx, TestSpec{EngagementID: eng.ID, ScanType: "Nmap Scan", Title: "nmap"})
	must(t, err)
	_, err = c.ReimportScan(ctx, ImportRequest{
		ScanType: "Nmap Scan", TestID: test.ID, FileName: "nmap.xml", File: open(t, "testdata/nmap_3ports.xml"),
		CloseOldFindings: true, Tags: []string{"raven", slug}, TagFindings: true, ScanDate: time.Now(),
	})
	must(t, err)

	urlPage, err := c.ListURLs(ctx, URLQuery{Limit: 10})
	must(t, err)
	if urlPage.Count == 0 || len(urlPage.Results) == 0 {
		t.Fatalf("ListURLs returned empty page: %+v", urlPage)
	}
	t.Logf("ListURLs count=%d first=%+v", urlPage.Count, urlPage.Results[0])

	fetched, err := FetchTargets(ctx, c)
	must(t, err)
	if fetched.Skipped < 1 {
		t.Fatalf("expected at least 1 skipped non-target (%q), got skipped=%d", nonTarget, fetched.Skipped)
	}
	var gotIP, gotDom *targets.Entry
	for i := range fetched.Entries {
		e := &fetched.Entries[i]
		if e.Value == nonTarget {
			t.Fatalf("non-target %q must not be in fetched entries", nonTarget)
		}
		if e.Kind == targets.KindIP && e.Value == ip {
			gotIP = e
		}
		if e.Kind == targets.KindDomain && e.Value == domain {
			gotDom = e
		}
	}
	if gotIP == nil || !slices.Contains(gotIP.Tags, "d7-custom") || slices.Contains(gotIP.Tags, "raven") {
		t.Fatalf("IP entry = %+v, want ip=%s with tag d7-custom (and no internal raven tag)", gotIP, ip)
	}
	if gotDom == nil || !slices.Contains(gotDom.Tags, "d7-dom") {
		t.Fatalf("domain entry = %+v, want domain=%s with tag d7-dom", gotDom, domain)
	}
}

func deleteAsset(t *testing.T, c *HTTPClient, id int64) {
	if id == 0 {
		return
	}
	if err := c.do(context.Background(), http.MethodDelete, "/api/v2/assets/"+itoa(id)+"/", nil, nil, nil); err != nil {
		t.Errorf("cleanup asset %d: %v", id, err)
	}
}

func open(t *testing.T, path string) *os.File {
	f, err := os.Open(path)
	must(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }
