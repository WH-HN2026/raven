//go:build integration

package exchange

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/changes"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/hosts"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/targets"
)

type recordingHook struct {
	mu      sync.Mutex
	batches []pipeline.BatchResult
}

func (h *recordingHook) AfterBatch(_ context.Context, b pipeline.BatchResult) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.batches = append(h.batches, b)
	return nil
}

func TestIntegrationImportResultsAndExport(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)

	hash, _ := auth.HashPassword("editor-secret-pw")
	editor, err := q.CreateUser(ctx, gen.CreateUserParams{Username: "ed", PasswordHash: hash, Role: "editor"})
	if err != nil {
		t.Fatal(err)
	}
	u := &auth.User{ID: editor.ID, Username: editor.Username, Role: auth.RoleEditor}

	// Add a global blacklist entry for 172.30.0.11 to verify scope/blacklist filtering!
	adminHash, _ := auth.HashPassword("admin-secret-pw")
	adminRow, err := q.CreateUser(ctx, gen.CreateUserParams{Username: "adm", PasswordHash: adminHash, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	adminUser := &auth.User{ID: adminRow.ID, Username: adminRow.Username, Role: auth.RoleAdmin}
	if _, err := (&targets.Store{Pool: pool}).AddScopeEntry(ctx, adminUser, targets.ScopeInput{
		Value: "172.30.0.11", List: "exclude", Note: "blacklisted for test",
	}); err != nil {
		t.Fatal(err)
	}

	hook := &recordingHook{}
	pipe, err := pipeline.New(pool, pipeline.Config{Scanner: nmap.New(nmap.Config{}), Hook: hook})
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{Pool: pool, Pipeline: pipe, DojoPublicURL: "http://dojo.local"}

	// 1. Import our results JSON fixture.
	rawJSON, err := os.ReadFile("testdata/sample_results.json")
	if err != nil {
		t.Fatal(err)
	}
	// Empty profile = the seeded Default profile.
	run1, err := svc.ImportResults(ctx, u, ImportRequest{
		Kind: ImportResultsJSON, Profile: "", Filename: "sample_results.json", Data: rawJSON,
	})
	if err != nil {
		t.Fatalf("ImportResults(results-json): %v", err)
	}
	var defaultID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = $1`, pipeline.DefaultProfileName).Scan(&defaultID); err != nil {
		t.Fatal(err)
	}
	if run1.ProfileID != defaultID {
		t.Fatalf("run1.ProfileID = %d, want Default (%d)", run1.ProfileID, defaultID)
	}
	if run1.Status != "done" || run1.HostsTotal != 2 || run1.HostsUp != 1 {
		t.Fatalf("run1 = %+v (expected status=done, hosts_total=2 [172.30.0.11 excluded], hosts_up=1)", run1)
	}
	var st map[string]any
	if err := json.Unmarshal(run1.Stats, &st); err != nil {
		t.Fatal(err)
	}
	if st["source"] != "import" || st["import_kind"] != "results-json" || st["excluded"].(float64) != 1 {
		t.Fatalf("run1.stats = %v", st)
	}

	// Verify hosts/services/HTTP observations in our DB, and that blacklisted 172.30.0.11 was NOT ingested.
	detail, err := hosts.Get(ctx, pool, netip.MustParseAddr("172.30.0.10"))
	if err != nil {
		t.Fatalf("hosts.Get(172.30.0.10): %v", err)
	}
	if len(detail.Services) != 1 || detail.Services[0].Product != "nginx" || detail.Services[0].Version != "1.24.0" {
		t.Fatalf("services = %+v", detail.Services)
	}
	if len(detail.HTTP) != 1 || detail.HTTP[0].Title != "Welcome to Lab" || !slices.Contains(detail.HTTP[0].Technologies, "nginx") {
		t.Fatalf("http observations = %+v", detail.HTTP)
	}
	if _, err := hosts.Get(ctx, pool, netip.MustParseAddr("172.30.0.11")); err != hosts.ErrNotFound {
		t.Fatalf("blacklisted 172.30.0.11 should not exist in hosts, got err=%v", err)
	}

	// Verify BatchHook ran with the responding IP and valid PerIP nmap XML!
	if len(hook.batches) != 1 {
		t.Fatalf("hook batches = %d, want 1", len(hook.batches))
	}
	b0 := hook.batches[0]
	if b0.RunID != run1.ID || !slices.Equal(b0.Responding, []netip.Addr{netip.MustParseAddr("172.30.0.10")}) {
		t.Fatalf("hook batch = %+v", b0)
	}
	if xmlSlice := b0.Result.PerIP(netip.MustParseAddr("172.30.0.10")); !bytes.Contains(xmlSlice, []byte(`addr="172.30.0.10"`)) {
		t.Fatalf("hook PerIP missing IP: %s", xmlSlice)
	}

	// Verify audit_log entry was written.
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'import.results' AND user_id = $1`, editor.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit_log import.results count = %d, want 1", auditCount)
	}

	// 2. Import a second run (version changed to 1.26.0) so we can test changes export!
	rawJSON2 := bytes.ReplaceAll(rawJSON, []byte("1.24.0"), []byte("1.26.0"))
	run2, err := svc.ImportResults(ctx, u, ImportRequest{
		Kind: ImportResultsJSON, Profile: "Default", Filename: "run2.json", Data: rawJSON2,
	})
	if err != nil {
		t.Fatalf("ImportResults(run2): %v", err)
	}

	// 3. Import raw nmap XML fixture (lab.xml) and nuclei JSONL fixture (lab-http.jsonl).
	nmapRaw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	runNmap, err := svc.ImportResults(ctx, u, ImportRequest{
		Kind: ImportNmapXML, Profile: "Default", Filename: "lab.xml", Data: nmapRaw,
	})
	if err != nil {
		t.Fatalf("ImportResults(nmap-xml): %v", err)
	}
	if runNmap.HostsUp != 3 {
		t.Fatalf("runNmap.HostsUp = %d, want 3", runNmap.HostsUp)
	}

	nucleiRaw, err := os.ReadFile("../scanner/nuclei/testdata/lab-http.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	runNuclei, err := svc.ImportResults(ctx, u, ImportRequest{
		Kind: ImportNucleiJSONL, Profile: "Default", Filename: "lab-http.jsonl", Data: nucleiRaw,
	})
	if err != nil {
		t.Fatalf("ImportResults(nuclei-jsonl): %v", err)
	}
	if runNuclei.HostsUp != 2 {
		t.Fatalf("runNuclei.HostsUp = %d, want 2", runNuclei.HostsUp)
	}
	if len(hook.batches) != 4 {
		t.Fatalf("total hook batches = %d, want 4", len(hook.batches))
	}
	if hook.batches[3].Scanner.DojoScanType() != "Nuclei Scan" {
		t.Fatalf("nuclei hook scan type = %q", hook.batches[3].Scanner.DojoScanType())
	}

	// 4. Test Exports (hosts CSV, services JSON with filter, findings CSV, changes JSON & CSV).
	var hostsCSV bytes.Buffer
	port80 := 80
	if err := ExportHosts(ctx, pool, hosts.Filter{Port: &port80}, FormatCSV, &hostsCSV); err != nil {
		t.Fatalf("ExportHosts CSV: %v", err)
	}
	recs, err := csv.NewReader(bytes.NewReader(hostsCSV.Bytes())).ReadAll()
	if err != nil || len(recs) < 2 || !strings.Contains(hostsCSV.String(), "172.30.0.10") {
		t.Fatalf("hosts CSV unexpected:\n%s", hostsCSV.String())
	}

	var svcJSON bytes.Buffer
	if err := ExportServices(ctx, pool, ServiceFilter{Product: "nginx"}, FormatJSON, &svcJSON); err != nil {
		t.Fatalf("ExportServices JSON: %v", err)
	}
	var exportedSvcs []ExportServiceRow
	if err := json.Unmarshal(svcJSON.Bytes(), &exportedSvcs); err != nil || len(exportedSvcs) < 1 {
		t.Fatalf("exported services = %s err=%v", svcJSON.String(), err)
	}

	// Seed one mirrored finding to verify findings export.
	if _, err := pool.Exec(ctx, `INSERT INTO dojo_findings (id, ip, title, severity, active, scanner) VALUES (901, '172.30.0.10', 'Test finding', 'High', true, 'nmap')`); err != nil {
		t.Fatal(err)
	}
	var findCSV bytes.Buffer
	if err := ExportFindings(ctx, pool, dojo.FindingFilter{Severities: []string{"High"}}, "http://dojo.local", FormatCSV, &findCSV); err != nil {
		t.Fatalf("ExportFindings CSV: %v", err)
	}
	if !strings.Contains(findCSV.String(), "Test finding") || !strings.Contains(findCSV.String(), "http://dojo.local/finding/901") {
		t.Fatalf("findings CSV unexpected:\n%s", findCSV.String())
	}

	var chJSON bytes.Buffer
	if err := ExportChanges(ctx, q, &run1.ID, &run2.ID, 100, FormatJSON, &chJSON); err != nil {
		t.Fatalf("ExportChanges JSON: %v", err)
	}
	var diff changes.Changes
	if err := json.Unmarshal(chJSON.Bytes(), &diff); err != nil {
		t.Fatal(err)
	}
	if diff.Summary.ServicesChanged != 1 || diff.ServicesChanged[0].Before.Version != "1.24.0" || diff.ServicesChanged[0].After.Version != "1.26.0" {
		t.Fatalf("exported changes diff = %+v", diff)
	}
}
