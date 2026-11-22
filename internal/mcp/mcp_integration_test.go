//go:build integration

package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/changes"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/hosts"
	"github.com/WH-HN2026/raven/internal/httpapi"
	"github.com/WH-HN2026/raven/internal/mcp"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/targets"
	"github.com/WH-HN2026/raven/internal/users"
)

type bearerRT struct {
	base  http.RoundTripper
	token string
}

func (t *bearerRT) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

type noopScanner struct{}

func (noopScanner) Name() string         { return "nmap" }
func (noopScanner) DojoScanType() string { return "Nmap Scan" }
func (noopScanner) Run(context.Context, scanner.Input, scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{}, nil
}

func connectClient(t *testing.T, endpoint, token string) *sdkmcp.ClientSession {
	t.Helper()
	c := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "mcp-integration-test", Version: "1.0.0"}, nil)
	tr := &sdkmcp.StreamableClientTransport{
		Endpoint: endpoint,
		HTTPClient: &http.Client{
			Transport: &bearerRT{base: http.DefaultTransport, token: token},
		},
	}
	sess, err := c.Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func callJSON[T any](t *testing.T, sess *sdkmcp.ClientSession, name string, args map[string]any) T {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	txt := extractText(res)
	if res.IsError {
		t.Fatalf("CallTool(%s) returned tool error: %s", name, txt)
	}
	var out T
	if err := json.Unmarshal([]byte(txt), &out); err != nil {
		t.Fatalf("unmarshal %s output %q: %v", name, txt, err)
	}
	return out
}

func callExpectError(t *testing.T, sess *sdkmcp.ClientSession, name string, args map[string]any, wantSubstr string) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s) protocol error: %v", name, err)
	}
	txt := extractText(res)
	if !res.IsError {
		t.Fatalf("CallTool(%s) succeeded (%s), want IsError containing %q", name, txt, wantSubstr)
	}
	if !strings.Contains(strings.ToLower(txt), strings.ToLower(wantSubstr)) {
		t.Fatalf("CallTool(%s) error = %q, want containing %q", name, txt, wantSubstr)
	}
}

func extractText(res *sdkmcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestMCPEndToEnd(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)

	authSvc := auth.NewService(q, time.Hour)
	if err := authSvc.EnsureBootstrapAdmin(ctx, "admin", "admin password 1"); err != nil {
		t.Fatal(err)
	}
	adminRow, err := q.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	adminUser := &auth.User{ID: adminRow.ID, Username: adminRow.Username, Role: auth.RoleAdmin}

	userStore := &users.Store{Pool: pool}
	viewerU, err := userStore.Create(ctx, adminUser, "viewer1", "viewer password 1", auth.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	editorU, err := userStore.Create(ctx, adminUser, "editor1", "editor password 1", auth.RoleEditor)
	if err != nil {
		t.Fatal(err)
	}

	viewerTok, err := userStore.CreateAPIToken(ctx, adminUser, "viewer-cli", &viewerU.ID)
	if err != nil {
		t.Fatal(err)
	}
	editorTok, err := userStore.CreateAPIToken(ctx, adminUser, "editor-cli", &editorU.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Build pipeline service (not started, so enqueued jobs don't execute real scanners).
	pipe, err := pipeline.New(pool, pipeline.Config{Scanner: noopScanner{}})
	if err != nil {
		t.Fatal(err)
	}

	// Seed profiles: Default (seeded) + an aggressive profile.
	defProf, err := q.GetProfileByName(ctx, pipeline.DefaultProfileName)
	if err != nil {
		t.Fatal(err)
	}
	aggProf, err := q.CreateProfile(ctx, gen.CreateProfileParams{
		Name:               "aggressive-lab",
		Ports:              "80,443",
		NmapMaxRate:        100,
		NucleiRate:         20,
		NucleiTags:         []string{"tech"},
		MissThreshold:      3,
		TargetBatchSeconds: 600,
		Enabled:            true,
		Stages:             []string{pipeline.StageNmap, pipeline.StageHTTPX, pipeline.StageNuclei, pipeline.StageNucleiActive},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add include scope for both profiles (local lab range only).
	targetStore := &targets.Store{Pool: pool, IsAggressive: pipeline.IsAggressive}
	for _, pid := range []int64{defProf.ID, aggProf.ID} {
		p := pid
		if _, err := targetStore.AddScopeEntry(ctx, adminUser, targets.ScopeInput{
			Value: "172.30.0.0/24", List: "include", ProfileID: &p,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Seed hosts, services, HTTP observations, CVE matches, Dojo mirror findings, and 2 finished runs for diff.
	ip1 := netip.MustParseAddr("172.30.0.10")
	ip2 := netip.MustParseAddr("172.30.0.11")
	now := time.Now().UTC().Truncate(time.Second)

	_, err = pool.Exec(ctx, `
		INSERT INTO hosts (ip, hostnames, state, first_seen, last_seen, owner, criticality, user_tags, notes_enc)
		VALUES
			($1, ARRAY['web.lab.local'], 'active', $3, $3, 'team-a', 'high', ARRAY['prod','web'], raven_enc('host 10 secret note')),
			($2, ARRAY['db.lab.local'], 'inactive', $3, $3, 'team-b', 'low', ARRAY['db'], raven_enc('host 11 note'))`,
		ip1, ip2, now)
	if err != nil {
		t.Fatal(err)
	}

	var svcID int64
	err = pool.QueryRow(ctx, `
		INSERT INTO services (ip, port, proto, name, product, version, cpe, banner_enc, state, first_seen, last_seen)
		VALUES ($1, 80, 'tcp', 'http', 'Apache httpd', '2.4.49', 'apache:http_server', raven_enc('Apache/2.4.49'), 'open', $2, $2)
		RETURNING id`, ip1, now).Scan(&svcID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO http_observations (service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc, redirects, technologies, favicon_hash, observed_at)
		VALUES ($1, 'http://172.30.0.10:80/', 200, 'Lab Portal', raven_enc('{"Server":"Apache/2.4.49"}'), raven_enc('[]'), raven_enc(''), '[]'::jsonb, ARRAY['Apache','PHP'], '12345', $2)`,
		svcID, now)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO cve_matches (ip, port, proto, product, cpe, version, cve_ids, hits, max_cvss, kev, distro, confidence, severity, matched_at, updated_at)
		VALUES ($1, 80, 'tcp', 'Apache httpd', 'apache:http_server', '2.4.49', ARRAY['CVE-2021-41773'],
			'[{"id":"CVE-2021-41773","cvss":7.5,"kev":true,"epss":0.97}]'::jsonb, 7.5, 1, false, 'high', 'Critical', $2, $2)`,
		ip1, now)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO dojo_findings (id, ip, title, severity, active, verified, false_p, risk_accepted, is_mitigated, tags, scanner, date)
		VALUES
			(101, $1, 'CVE-2021-41773 in Apache httpd 2.4.49', 'Critical', true, true, false, false, false, ARRAY['raven'], 'cve', CURRENT_DATE),
			(102, $2, 'Old TLS cipher', 'Low', false, false, false, false, true, ARRAY['raven'], 'nuclei', CURRENT_DATE)`,
		ip1, ip2)
	if err != nil {
		t.Fatal(err)
	}

	// Seed two finished runs for get_changes and list_runs.
	var run1ID, run2ID int64
	err = pool.QueryRow(ctx, `
		INSERT INTO runs (profile_id, status, started_at, finished_at, hosts_total, hosts_up, stages)
		VALUES ($1, 'done', $2, $3, 1, 1, ARRAY['nmap','httpx','nuclei']) RETURNING id`,
		defProf.ID, now.Add(-2*time.Hour), now.Add(-110*time.Minute)).Scan(&run1ID)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.QueryRow(ctx, `
		INSERT INTO runs (profile_id, status, started_at, finished_at, hosts_total, hosts_up, stages)
		VALUES ($1, 'done', $2, $3, 2, 2, ARRAY['nmap','httpx','nuclei']) RETURNING id`,
		defProf.ID, now.Add(-1*time.Hour), now.Add(-50*time.Minute)).Scan(&run2ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO run_observations (run_id, ip, port, up, observed_at, service_fp) VALUES
			($1, $3, NULL, true, $5, NULL),
			($1, $3, 80, true, $5, '{"name":"http","product":"Apache httpd","version":"2.4.48"}'::jsonb),
			($2, $3, NULL, true, $6, NULL),
			($2, $3, 80, true, $6, '{"name":"http","product":"Apache httpd","version":"2.4.49"}'::jsonb),
			($2, $4, NULL, true, $6, NULL)`,
		run1ID, run2ID, ip1, ip2, now.Add(-2*time.Hour), now.Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// Mount full router (verifies /mcp is outside cookie CSRF and before SPA catch-all).
	srv := httptest.NewServer(httpapi.NewRouter(httpapi.Deps{
		Pool:          pool,
		Queries:       q,
		Auth:          authSvc,
		Pipeline:      pipe,
		DojoPublicURL: "http://dojo.local:8080",
	}))
	t.Cleanup(srv.Close)
	mcpURL := srv.URL + "/mcp"

	// 1. Viewer connects via Streamable HTTP and runs all 5 read tools.
	viewerSess := connectClient(t, mcpURL, viewerTok.Token)

	// Verify last_used_at was updated on api_tokens.
	var lastUsed *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_used_at FROM api_tokens WHERE id = $1`, viewerTok.ID).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed == nil {
		t.Fatalf("expected api_tokens.last_used_at to be updated after MCP auth")
	}

	// Tool 1: search_hosts
	hostList := callJSON[struct {
		Items []hosts.Host `json:"items"`
		Total int64        `json:"total"`
	}](t, viewerSess, "search_hosts", map[string]any{
		"state": "active",
		"port":  80,
		"tech":  "apache",
		"tag":   "prod",
		"query": "web.lab",
	})
	if hostList.Total != 1 || len(hostList.Items) != 1 || hostList.Items[0].IP != ip1 {
		t.Fatalf("search_hosts = %+v, want 1 host %s", hostList, ip1)
	}

	// Tool 2: get_host (detail + services + HTTP observations + CVE matches)
	hostDetail := callJSON[mcp.HostDetailOutput](t, viewerSess, "get_host", map[string]any{"ip": ip1.String()})
	if hostDetail.IP != ip1 || len(hostDetail.Services) != 1 || len(hostDetail.HTTP) != 1 || len(hostDetail.CVEMatches) != 1 {
		t.Fatalf("get_host = %+v, want 1 service, 1 http obs, 1 cve match", hostDetail)
	}
	if hostDetail.Notes != "host 10 secret note" {
		t.Fatalf("get_host notes = %q", hostDetail.Notes)
	}

	// Tool 3: list_findings (mirror only, never calls Dojo)
	findingList := callJSON[struct {
		Items []dojo.MirrorFinding `json:"items"`
		Total int64                `json:"total"`
	}](t, viewerSess, "list_findings", map[string]any{
		"severity": "critical",
		"active":   true,
		"ip":       "172.30.0.0/24",
		"search":   "CVE-2021-41773",
	})
	if findingList.Total != 1 || len(findingList.Items) != 1 || findingList.Items[0].ID != 101 {
		t.Fatalf("list_findings = %+v, want finding 101", findingList)
	}

	// Tool 4: get_changes
	diff := callJSON[changes.Changes](t, viewerSess, "get_changes", map[string]any{
		"from_run_id": run1ID,
		"to_run_id":   run2ID,
	})
	if diff.Summary.HostsNew != 1 || diff.Summary.ServicesChanged != 1 {
		t.Fatalf("get_changes summary = %+v, want 1 new host + 1 changed service", diff.Summary)
	}

	// Tool 5: list_runs
	runList := callJSON[struct {
		Items []pipeline.Run `json:"items"`
		Total int64          `json:"total"`
	}](t, viewerSess, "list_runs", map[string]any{"profile_id": defProf.ID, "limit": 10})
	if runList.Total != 2 || len(runList.Items) != 2 {
		t.Fatalf("list_runs = %+v, want 2 runs", runList)
	}

	// Viewer is DENIED on editor tools (add_targets, start_scan).
	callExpectError(t, viewerSess, "add_targets", map[string]any{
		"targets": []map[string]any{{"value": "172.30.0.20"}},
	}, "permission denied")
	callExpectError(t, viewerSess, "start_scan", map[string]any{
		"profile_id": defProf.ID,
	}, "permission denied")

	var targetCount int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM targets`).Scan(&targetCount); err != nil {
		t.Fatal(err)
	}
	if targetCount != 0 {
		t.Fatalf("viewer add_targets mutated DB: count=%d", targetCount)
	}

	// 2. Editor connects via Streamable HTTP and runs add_targets + start_scan (including aggressive gating).
	editorSess := connectClient(t, mcpURL, editorTok.Token)

	// Tool 7: add_targets
	added := callJSON[struct {
		Items []gen.Target `json:"items"`
		Total int64        `json:"total"`
	}](t, editorSess, "add_targets", map[string]any{
		"targets": []map[string]any{
			{"value": "172.30.0.20", "tags": []string{"mcp"}, "note": "added via mcp"},
			{"value": "172.30.0.21"},
		},
	})
	if added.Total != 2 || len(added.Items) != 2 {
		t.Fatalf("add_targets = %+v, want 2 created", added)
	}
	// Invalid target fails cleanly without writing.
	callExpectError(t, editorSess, "add_targets", map[string]any{
		"targets": []map[string]any{{"value": "not a valid target!!!"}},
	}, "target 1")

	// Tool 6: start_scan on default profile succeeds.
	startedDef := callJSON[pipeline.Run](t, editorSess, "start_scan", map[string]any{
		"profile_id": defProf.ID,
	})
	if startedDef.ProfileID != defProf.ID || startedDef.Aggressive {
		t.Fatalf("start_scan default = %+v", startedDef)
	}

	// Tool 6: start_scan on aggressive profile succeeds directly and writes aggressive:true to audit_log.
	startedAgg := callJSON[pipeline.Run](t, editorSess, "start_scan", map[string]any{
		"profile_id": aggProf.ID,
	})
	if startedAgg.ProfileID != aggProf.ID || !startedAgg.Aggressive {
		t.Fatalf("start_scan aggressive = %+v", startedAgg)
	}

	// Verify audit_log captured editor's mutations, including aggressive flag, with zero plaintext token leaks.
	rows, err := pool.Query(ctx, `SELECT action, coalesce(user_id, 0), diff::text FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var sawTargetsAdd, sawDefRun, sawAggRun bool
	for rows.Next() {
		var action, diffText string
		var uid int64
		if err := rows.Scan(&action, &uid, &diffText); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(diffText, viewerTok.Token) || strings.Contains(diffText, editorTok.Token) {
			t.Fatalf("audit_log leaked plaintext API token in %s: %s", action, diffText)
		}
		if action == "targets.add" && uid == editorU.ID {
			sawTargetsAdd = true
		}
		if action == "runs.start" && uid == editorU.ID {
			var m map[string]any
			if err := json.Unmarshal([]byte(diffText), &m); err != nil {
				t.Fatal(err)
			}
			if agg, _ := m["aggressive"].(bool); agg {
				sawAggRun = true
			} else {
				sawDefRun = true
			}
		}
	}
	if !sawTargetsAdd || !sawDefRun || !sawAggRun {
		t.Fatalf("missing expected audit_log rows: targets.add=%v defRun=%v aggRun=%v", sawTargetsAdd, sawDefRun, sawAggRun)
	}

	// 3. Revoking viewer token immediately causes HTTP 401 on /mcp.
	if err := userStore.RevokeAPIToken(ctx, adminUser, viewerTok.ID); err != nil {
		t.Fatal(err)
	}
	checkStatus := func(token string, want int) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, mcpURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("POST /mcp status = %d, want %d", resp.StatusCode, want)
		}
	}
	checkStatus(viewerTok.Token, http.StatusUnauthorized)

	// 4. Disabling editor user immediately causes HTTP 401 on /mcp.
	disabled := true
	if _, err := userStore.Update(ctx, adminUser, editorU.ID, users.Patch{Disabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	checkStatus(editorTok.Token, http.StatusUnauthorized)
}
