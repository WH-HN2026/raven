//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner"
)

type noopScanner struct {
	name string
}

func (n noopScanner) Name() string         { return n.name }
func (n noopScanner) DojoScanType() string { return "Nmap Scan" }
func (n noopScanner) Run(context.Context, scanner.Input, scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{Raw: []byte("<nmaprun/>")}, nil
}

func TestAggressiveGatingIntegration(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	authSvc := auth.NewService(q, time.Hour)
	if err := authSvc.EnsureBootstrapAdmin(ctx, "admin", "integration test admin password"); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username = 'admin'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}

	pipe, err := pipeline.New(pool, pipeline.Config{
		Scanner:  noopScanner{name: "nmap"},
		HTTPX:    noopScanner{name: "httpx"},
		Nuclei:   noopScanner{name: "nuclei"},
		Resolver: net.DefaultResolver,
		Workers:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(Deps{Pool: pool, Queries: q, Auth: authSvc, Pipeline: pipe})

	request := func(wantCode int, role auth.Role, method, path, body string) []byte {
		t.Helper()
		rc := auth.WithUser(ctx, &auth.User{ID: adminID, Username: string(role), Role: role})
		req := httptest.NewRequestWithContext(rc, method, "/api"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(auth.CSRFHeader, "1")
		out := httptest.NewRecorder()
		router.ServeHTTP(out, req)
		if out.Code != wantCode {
			t.Fatalf("%s %s as %s = %d %s, want %d", method, path, role, out.Code, out.Body, wantCode)
		}
		return out.Body.Bytes()
	}
	parse := func(data []byte, out any) {
		t.Helper()
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
	}
	assertAuditAggressive := func(action, objectID string) {
		t.Helper()
		var raw []byte
		err := pool.QueryRow(ctx,
			`SELECT diff FROM audit_log WHERE action = $1 AND object_id = $2 ORDER BY id DESC LIMIT 1`,
			action, objectID,
		).Scan(&raw)
		if err != nil {
			t.Fatalf("audit_log %s/%s: %v", action, objectID, err)
		}
		var m map[string]any
		parse(raw, &m)
		if v, ok := m["aggressive"].(bool); !ok || !v {
			t.Fatalf("audit_log %s/%s diff = %s, want aggressive:true", action, objectID, raw)
		}
	}

	admin, editor, viewer := auth.RoleAdmin, auth.RoleEditor, auth.RoleViewer

	// 1. With production availability, unimplemented aggressive stages still fail with 400 "not available".
	for _, st := range pipeline.Stages() {
		if !st.Aggressive || st.Available {
			continue
		}
		for _, role := range []auth.Role{admin, editor} {
			body := request(400, role, http.MethodPost, "/profiles",
				fmt.Sprintf(`{"name":"unavail-%s","ports":"80","stages":["nmap","httpx","%s"]}`, st.Name, st.Name))
			if !strings.Contains(string(body), "not available") {
				t.Fatalf("expected 'not available' for stage %s as %s, got %s", st.Name, role, body)
			}
		}
	}

	// 2. Enable nikto only for this test to exercise aggressive gating.
	pipeline.WithStageAvailable(t, pipeline.StageNikto)

	// Validation order: unknown / duplicate / missing dependency / unavailable -> 400 BEFORE 403 for editor.
	for _, badBody := range []string{
		`{"name":"bad-1","ports":"80","stages":["nmap","unknown"]}`,
		`{"name":"bad-2","ports":"80","stages":["nmap","nmap"]}`,
		`{"name":"bad-3","ports":"80","stages":["nmap","nikto"]}`,
		`{"name":"bad-4","ports":"80","stages":["nmap","httpx","zap"]}`,
	} {
		request(400, editor, http.MethodPost, "/profiles", badBody)
	}

	// Editor & viewer cannot create an aggressive profile (403).
	aggPayload := `{"name":"agg-profile","ports":"80,443","stages":["nmap","httpx","nikto"]}`
	request(403, editor, http.MethodPost, "/profiles", aggPayload)
	request(403, viewer, http.MethodPost, "/profiles", aggPayload)

	// Admin creates an aggressive profile (201) with aggressive:true and audit_log.
	var aggProf profileView
	parse(request(201, admin, http.MethodPost, "/profiles", aggPayload), &aggProf)
	if !aggProf.Aggressive || !slices.Equal(aggProf.Stages, []string{"nmap", "httpx", "nikto"}) {
		t.Fatalf("created aggressive profile = %+v", aggProf)
	}
	assertAuditAggressive("profiles.create", fmt.Sprint(aggProf.ID))

	// Editor creates a normal profile -> 201, aggressive:false.
	var normalProf profileView
	parse(request(201, editor, http.MethodPost, "/profiles", `{"name":"normal-profile","ports":"80"}`), &normalProf)
	if normalProf.Aggressive {
		t.Fatalf("normal profile should not be aggressive: %+v", normalProf)
	}

	// GET /profiles returns aggressive flag accurately.
	var profList list[profileView]
	parse(request(200, viewer, http.MethodGet, "/profiles", ""), &profList)
	foundAgg, foundNormal := false, false
	for _, p := range profList.Items {
		if p.ID == aggProf.ID {
			if !p.Aggressive {
				t.Fatalf("GET /profiles aggressive profile has aggressive=false")
			}
			foundAgg = true
		}
		if p.ID == normalProf.ID {
			if p.Aggressive {
				t.Fatalf("GET /profiles normal profile has aggressive=true")
			}
			foundNormal = true
		}
	}
	if !foundAgg || !foundNormal {
		t.Fatalf("expected both profiles in list: foundAgg=%v foundNormal=%v", foundAgg, foundNormal)
	}

	aggPath := fmt.Sprintf("/profiles/%d", aggProf.ID)
	normalPath := fmt.Sprintf("/profiles/%d", normalProf.ID)

	// Editor cannot add aggressive stage to normal profile, nor edit/downgrade/delete aggressive profile.
	request(403, editor, http.MethodPut, normalPath, `{"name":"normal-profile","ports":"80","stages":["nmap","httpx","nikto"]}`)
	request(403, editor, http.MethodPut, aggPath, `{"name":"agg-renamed","ports":"80,443"}`)
	request(403, editor, http.MethodPut, aggPath, `{"name":"agg-profile","ports":"80,443","stages":["nmap","httpx"]}`)
	request(403, editor, http.MethodDelete, aggPath, "")
	request(403, viewer, http.MethodPut, aggPath, `{"name":"agg-renamed","ports":"80,443"}`)
	request(403, viewer, http.MethodDelete, aggPath, "")

	// Admin can update aggressive profile -> 200 + audit aggressive:true.
	parse(request(200, admin, http.MethodPut, aggPath, `{"name":"agg-profile","ports":"80,443,8080"}`), &aggProf)
	if !aggProf.Aggressive || aggProf.Ports != "80,443,8080" {
		t.Fatalf("updated agg profile = %+v", aggProf)
	}
	assertAuditAggressive("profiles.update", fmt.Sprint(aggProf.ID))

	// 3. Scope entries on aggressive profile.
	// Editor cannot add include/exclude on aggressive profile, but can on normal profile.
	request(403, editor, http.MethodPost, "/scope", fmt.Sprintf(`{"value":"172.30.0.10","list":"include","profile_id":%d}`, aggProf.ID))
	request(403, editor, http.MethodPost, "/scope", fmt.Sprintf(`{"value":"172.30.0.11","list":"exclude","profile_id":%d}`, aggProf.ID))
	request(403, viewer, http.MethodPost, "/scope", fmt.Sprintf(`{"value":"172.30.0.10","list":"include","profile_id":%d}`, aggProf.ID))

	var normalScope gen.ScopeEntry
	parse(request(201, editor, http.MethodPost, "/scope", fmt.Sprintf(`{"value":"172.30.0.10","list":"include","profile_id":%d}`, normalProf.ID)), &normalScope)
	request(204, editor, http.MethodDelete, fmt.Sprintf("/scope/%d", normalScope.ID), "")

	// Admin adds and deletes scope entry on aggressive profile; editor gets 403 deleting it.
	var aggScope gen.ScopeEntry
	parse(request(201, admin, http.MethodPost, "/scope", fmt.Sprintf(`{"value":"172.30.0.10","list":"include","profile_id":%d}`, aggProf.ID)), &aggScope)
	assertAuditAggressive("scope.add", fmt.Sprint(aggScope.ID))
	request(403, editor, http.MethodDelete, fmt.Sprintf("/scope/%d", aggScope.ID), "")
	request(403, viewer, http.MethodDelete, fmt.Sprintf("/scope/%d", aggScope.ID), "")
	request(204, admin, http.MethodDelete, fmt.Sprintf("/scope/%d", aggScope.ID), "")
	assertAuditAggressive("scope.delete", fmt.Sprint(aggScope.ID))

	// 4. Starting runs: viewer gets 403; editor and admin can start an existing aggressive profile directly.
	request(403, viewer, http.MethodPost, "/runs", fmt.Sprintf(`{"profile_id":%d}`, aggProf.ID))

	// Empty targets => run finishes immediately (status=done), allowing another run right after.
	var editorRun pipeline.Run
	parse(request(201, editor, http.MethodPost, "/runs", fmt.Sprintf(`{"profile_id":%d}`, aggProf.ID)), &editorRun)
	if !editorRun.Aggressive || editorRun.Status != "done" {
		t.Fatalf("editor aggressive run = %+v", editorRun)
	}
	assertAuditAggressive("runs.start", fmt.Sprint(editorRun.ID))

	var fetchedRun pipeline.Run
	parse(request(200, viewer, http.MethodGet, fmt.Sprintf("/runs/%d", editorRun.ID), ""), &fetchedRun)
	if !fetchedRun.Aggressive {
		t.Fatalf("GET /runs/%d aggressive=false, want true", editorRun.ID)
	}

	var adminRun pipeline.Run
	parse(request(201, admin, http.MethodPost, "/runs", fmt.Sprintf(`{"profile_id":%d}`, aggProf.ID)), &adminRun)
	if !adminRun.Aggressive {
		t.Fatalf("admin aggressive run = %+v", adminRun)
	}
	assertAuditAggressive("runs.start", fmt.Sprint(adminRun.ID))

	var normalRun pipeline.Run
	parse(request(201, editor, http.MethodPost, "/runs", fmt.Sprintf(`{"profile_id":%d}`, normalProf.ID)), &normalRun)
	if normalRun.Aggressive {
		t.Fatalf("normal run should not be aggressive: %+v", normalRun)
	}

	var runList list[pipeline.Run]
	parse(request(200, viewer, http.MethodGet, "/runs", ""), &runList)
	var seenAggRun, seenNormalRun bool
	for _, r := range runList.Items {
		if r.ID == editorRun.ID && r.Aggressive {
			seenAggRun = true
		}
		if r.ID == normalRun.ID && !r.Aggressive {
			seenNormalRun = true
		}
	}
	if !seenAggRun || !seenNormalRun {
		t.Fatalf("GET /runs aggressive flags mismatch: seenAgg=%v seenNormal=%v", seenAggRun, seenNormalRun)
	}

	// 5. Schedules for aggressive profile: admin-only (scan:aggressive).
	schedPayload := fmt.Sprintf(`{"name":"Agg nightly","profile_id":%d,"cron":"* * * * *"}`, aggProf.ID)
	request(403, editor, http.MethodPost, "/schedules", schedPayload)
	request(403, viewer, http.MethodPost, "/schedules", schedPayload)

	var aggSched scheduleView
	parse(request(201, admin, http.MethodPost, "/schedules", schedPayload), &aggSched)
	assertAuditAggressive("schedules.create", fmt.Sprint(aggSched.ID))

	aggSchedPath := fmt.Sprintf("/schedules/%d", aggSched.ID)
	request(403, editor, http.MethodPut, aggSchedPath, schedPayload)
	request(403, editor, http.MethodDelete, aggSchedPath, "")
	parse(request(200, admin, http.MethodPut, aggSchedPath, schedPayload), &aggSched)
	assertAuditAggressive("schedules.update", fmt.Sprint(aggSched.ID))

	// Editor cannot retarget a normal schedule onto an aggressive profile.
	var normalSched scheduleView
	parse(request(201, editor, http.MethodPost, "/schedules", fmt.Sprintf(`{"name":"Normal","profile_id":%d,"cron":"0 * * * *"}`, normalProf.ID)), &normalSched)
	request(403, editor, http.MethodPut, fmt.Sprintf("/schedules/%d", normalSched.ID), schedPayload)

	// Backdate created_at so the "* * * * *" cron schedule is immediately due,
	// then verify the scheduler dispatches it without per-run confirmation.
	if _, err := pool.Exec(ctx, `UPDATE schedules SET created_at = now() - interval '2 minutes' WHERE id = $1`, aggSched.ID); err != nil {
		t.Fatal(err)
	}
	if err := pipe.DispatchSchedule(ctx, aggSched.ID); err != nil {
		t.Fatalf("DispatchSchedule(UI aggressive): %v", err)
	}
	var schedRunID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM runs WHERE schedule_id = $1 ORDER BY id DESC LIMIT 1`, aggSched.ID).Scan(&schedRunID); err != nil {
		t.Fatalf("expected scheduled run for aggressive UI schedule: %v", err)
	}
	assertAuditAggressive("runs.start", fmt.Sprint(schedRunID))

	// Defense-in-depth: a Dojo schedule for an aggressive profile is never started by the scheduler.
	engID := int64(9001)
	winStart := time.Now().Add(-time.Hour)
	winEnd := time.Now().Add(time.Hour)
	dojoSched, err := q.UpsertDojoSchedule(ctx, gen.UpsertDojoScheduleParams{
		Name: "Dojo aggressive", ProfileID: aggProf.ID, DojoEngagementID: &engID,
		WindowStart: &winStart, WindowEnd: &winEnd, Timezone: "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipe.DispatchSchedule(ctx, dojoSched.ID); err != nil {
		t.Fatalf("DispatchSchedule(Dojo aggressive): %v", err)
	}
	var dojoRuns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runs WHERE schedule_id = $1`, dojoSched.ID).Scan(&dojoRuns); err != nil {
		t.Fatal(err)
	}
	if dojoRuns != 0 {
		t.Fatalf("Dojo schedule started %d runs for aggressive profile, want 0", dojoRuns)
	}
	assertAuditAggressive("schedules.dojo_skip_aggressive", fmt.Sprint(dojoSched.ID))

	// Admin deletes aggressive schedule -> 204 + audit aggressive:true.
	request(204, admin, http.MethodDelete, aggSchedPath, "")
	assertAuditAggressive("schedules.delete", fmt.Sprint(aggSched.ID))

	// Admin deletes an unused aggressive profile -> 204 + audit aggressive:true.
	var tempAgg profileView
	parse(request(201, admin, http.MethodPost, "/profiles", `{"name":"agg-temp","ports":"80","stages":["nmap","httpx","nikto"]}`), &tempAgg)
	request(204, admin, http.MethodDelete, fmt.Sprintf("/profiles/%d", tempAgg.ID), "")
	assertAuditAggressive("profiles.delete", fmt.Sprint(tempAgg.ID))
}
