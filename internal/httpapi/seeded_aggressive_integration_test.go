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
)

// TestSeededAggressiveProfile (LB6): the seeded Aggressive profile (no zap) is
// gated as any aggressive profile (AG1), and a run of a profile with zap on a
// deployment without ZAP drops the zap stage with a run warning instead of failing.
func TestSeededAggressiveProfile(t *testing.T) {
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
	// Production default without RAVEN_ZAP_URL.
	pipeline.SetStageAvailable(pipeline.StageZAP, false)

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
	admin, editor, viewer := auth.RoleAdmin, auth.RoleEditor, auth.RoleViewer

	var profs list[profileView]
	parse(request(200, viewer, http.MethodGet, "/profiles", ""), &profs)
	var def, agg profileView
	for _, p := range profs.Items {
		switch p.Name {
		case pipeline.DefaultProfileName:
			def = p
		case pipeline.AggressiveProfileName:
			agg = p
		}
	}
	if profs.Total != 2 || def.ID == 0 || agg.ID == 0 {
		t.Fatalf("seeded profiles = %+v, want Default and Aggressive", profs)
	}
	if def.Aggressive || !slices.Equal(def.Stages, pipeline.DefaultStages()) {
		t.Fatalf("Default = %+v", def)
	}
	if !agg.Aggressive || !slices.Equal(agg.Stages, pipeline.SeededAggressiveStages()) || slices.Contains(agg.Stages, pipeline.StageZAP) {
		t.Fatalf("Aggressive = %+v, want %v (no zap)", agg, pipeline.SeededAggressiveStages())
	}

	// Only admins may change it.
	aggPath := fmt.Sprintf("/profiles/%d", agg.ID)
	request(403, editor, http.MethodPut, aggPath, `{"name":"Aggressive","ports":"80"}`)
	request(403, editor, http.MethodPut, aggPath, `{"name":"Aggressive","ports":"80","stages":["nmap","httpx","nuclei"]}`)
	request(403, editor, http.MethodDelete, aggPath, "")
	request(403, editor, http.MethodPost, "/scope", fmt.Sprintf(`{"value":"172.30.0.17","list":"include","profile_id":%d}`, agg.ID))
	request(403, viewer, http.MethodPut, aggPath, `{"name":"Aggressive","ports":"80"}`)
	// Saving keeps the validation: sending zap is rejected while unavailable;
	// an edit that leaves stages out keeps them.
	if body := request(400, admin, http.MethodPut, aggPath, fmt.Sprintf(`{"name":"Aggressive","ports":%q,"stages":["nmap","httpx","nuclei","nuclei_active","nikto","wpscan","zap"]}`, agg.Ports)); !strings.Contains(string(body), "not available") {
		t.Fatalf("admin save with unavailable zap: %s", body)
	}
	var edited profileView
	parse(request(200, admin, http.MethodPut, aggPath, fmt.Sprintf(`{"name":"Aggressive","ports":%q,"nmap_max_rate":200}`, agg.Ports)), &edited)
	if edited.NmapMaxRate != 200 || !slices.Equal(edited.Stages, pipeline.SeededAggressiveStages()) {
		t.Fatalf("admin edit = %+v", edited)
	}

	request(201, admin, http.MethodPost, "/targets", `{"targets":[{"value":"172.30.0.17"}]}`)
	var stats struct {
		Warnings []string `json:"warnings"`
	}

	var aggRun pipeline.Run
	parse(request(201, admin, http.MethodPost, "/runs", fmt.Sprintf(`{"profile_id":%d}`, agg.ID)), &aggRun)
	parse(aggRun.Stats, &stats)
	if aggRun.Status != "running" || !aggRun.Aggressive || !slices.Equal(aggRun.Stages, pipeline.SeededAggressiveStages()) || len(stats.Warnings) != 0 {
		t.Fatalf("seeded Aggressive run = %+v warnings %v", aggRun, stats.Warnings)
	}

	// A profile with zap, saved while ZAP was available, run on a deployment
	// without ZAP: zap is skipped with a warning instead of failing the run.
	pipeline.SetStageAvailable(pipeline.StageZAP, true)
	t.Cleanup(func() { pipeline.SetStageAvailable(pipeline.StageZAP, false) })
	var zapProf profileView
	parse(request(201, admin, http.MethodPost, "/profiles",
		`{"name":"agg-zap","ports":"80","stages":["nmap","httpx","nuclei","nuclei_active","nikto","wpscan","zap"]}`), &zapProf)
	if !slices.Equal(zapProf.Stages, pipeline.AggressiveStages()) {
		t.Fatalf("zap profile = %+v", zapProf)
	}
	pipeline.SetStageAvailable(pipeline.StageZAP, false)

	var run pipeline.Run
	parse(request(201, admin, http.MethodPost, "/runs", fmt.Sprintf(`{"profile_id":%d}`, zapProf.ID)), &run)
	wantStages := []string{pipeline.StageNmap, pipeline.StageHTTPX, pipeline.StageNuclei,
		pipeline.StageNucleiActive, pipeline.StageNikto, pipeline.StageWPScan}
	if run.Status != "running" || run.HostsTotal != 1 || !run.Aggressive || !slices.Equal(run.Stages, wantStages) {
		t.Fatalf("run = %+v, want running aggressive with stages %v", run, wantStages)
	}
	var dbStages []string
	if err := pool.QueryRow(ctx, `SELECT stages FROM runs WHERE id = $1`, run.ID).Scan(&dbStages); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(dbStages, pipeline.StageZAP) {
		t.Fatalf("runs.stages = %v contains zap", dbStages)
	}
	parse(run.Stats, &stats)
	if !slices.Contains(stats.Warnings, "stage zap skipped: not available") {
		t.Fatalf("run warnings = %v", stats.Warnings)
	}
	var diff struct {
		Aggressive bool     `json:"aggressive"`
		Skipped    []string `json:"skipped_stages"`
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT diff FROM audit_log WHERE action = 'runs.start' AND object_id = $1`,
		fmt.Sprint(run.ID)).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	parse(raw, &diff)
	if !diff.Aggressive || !slices.Equal(diff.Skipped, []string{pipeline.StageZAP}) {
		t.Fatalf("runs.start audit diff = %s", raw)
	}

	// A Default run is unchanged: no skipped stages, no warning.
	var defRun pipeline.Run
	parse(request(201, editor, http.MethodPost, "/runs", fmt.Sprintf(`{"profile_id":%d}`, def.ID)), &defRun)
	parse(defRun.Stats, &stats)
	if defRun.Aggressive || !slices.Equal(defRun.Stages, pipeline.DefaultStages()) || len(stats.Warnings) != 0 {
		t.Fatalf("Default run = %+v warnings %v", defRun, stats.Warnings)
	}
}
