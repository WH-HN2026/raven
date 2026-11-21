//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestProfilesAndSchedulesAPI(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	svc := auth.NewService(q, time.Hour)
	if err := svc.EnsureBootstrapAdmin(ctx, "admin", "integration test admin password"); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE username = 'admin'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(Deps{Pool: pool, Queries: q, Auth: svc, DojoPublicURL: "http://dojo.local"})
	request := func(code int, role auth.Role, method, path, body string) []byte {
		t.Helper()
		rc := auth.WithUser(ctx, &auth.User{ID: adminID, Role: role})
		req := httptest.NewRequestWithContext(rc, method, "/api"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(auth.CSRFHeader, "1")
		out := httptest.NewRecorder()
		router.ServeHTTP(out, req)
		if out.Code != code {
			t.Fatalf("%s %s as %s = %d %s, want %d", method, path, role, out.Code, out.Body, code)
		}
		return out.Body.Bytes()
	}
	parse := func(data []byte, out any) {
		t.Helper()
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
	}
	admin, viewer := auth.RoleAdmin, auth.RoleViewer
	var stagesResp struct {
		Stages  []pipeline.StageDef   `json:"stages"`
		Presets pipeline.StagePresets `json:"presets"`
	}
	parse(request(200, viewer, http.MethodGet, "/stages", ""), &stagesResp)
	if len(stagesResp.Stages) != 7 || !slices.Equal(stagesResp.Presets.Default, pipeline.DefaultStages()) ||
		!slices.Equal(stagesResp.Presets.Aggressive, pipeline.AggressiveStages()) {
		t.Fatalf("GET /stages = %+v", stagesResp)
	}
	for _, st := range stagesResp.Stages {
		available := st.Name == pipeline.StageWPScan || st.Name == pipeline.StageNucleiActive
		if st.Aggressive && available && !st.Available {
			t.Fatalf("aggressive stage %s should be available", st.Name)
		}
		if st.Aggressive && !available && st.Available {
			t.Fatalf("aggressive stage %s should not be available yet", st.Name)
		}
	}

	profileBody := `{"name":"p1 integration","ports":"22,80,8000-8100","nuclei_tags":["tech","ssl"]}`
	var profile gen.Profile
	parse(request(201, admin, http.MethodPost, "/profiles", profileBody), &profile)
	if profile.ID == 0 || profile.NmapMaxRate != 300 || profile.NucleiRate != 50 ||
		profile.MissThreshold != 3 || !profile.Enabled || len(profile.NucleiTags) != 2 ||
		!slices.Equal(profile.Stages, pipeline.DefaultStages()) {
		t.Fatalf("created profile = %+v", profile)
	}
	path := fmt.Sprintf("/profiles/%d", profile.ID)
	parse(request(200, admin, http.MethodPut, path,
		`{"name":"p1 integration updated","ports":"443","nmap_max_rate":25,"enabled":false}`), &profile)
	if profile.NmapMaxRate != 25 || profile.Enabled || profile.Ports != "443" || len(profile.NucleiTags) != 2 ||
		!slices.Equal(profile.Stages, pipeline.DefaultStages()) {
		t.Fatalf("updated profile = %+v", profile)
	}
	// Explicit stages on update (normalised to registry order).
	parse(request(200, admin, http.MethodPut, path,
		`{"name":"p1 integration updated","ports":"443","stages":["httpx","nmap"]}`), &profile)
	if !slices.Equal(profile.Stages, []string{"nmap", "httpx"}) {
		t.Fatalf("updated profile stages = %v, want [nmap httpx]", profile.Stages)
	}
	// Explicit nmap-only stages on create.
	var nmapOnly gen.Profile
	parse(request(201, admin, http.MethodPost, "/profiles",
		`{"name":"nmap-only-wf1","ports":"22,80","stages":["nmap"]}`), &nmapOnly)
	if !slices.Equal(nmapOnly.Stages, []string{"nmap"}) {
		t.Fatalf("nmap-only profile stages = %v, want [nmap]", nmapOnly.Stages)
	}
	// Audit log includes stages on create and update.
	var auditDiff []byte
	var auditParsed struct {
		Stages []string `json:"stages"`
	}
	if err := pool.QueryRow(ctx, `SELECT diff FROM audit_log WHERE action = 'profiles.create' AND object_id = $1`,
		fmt.Sprint(nmapOnly.ID)).Scan(&auditDiff); err != nil {
		t.Fatalf("profiles.create audit diff: %v", err)
	}
	parse(auditDiff, &auditParsed)
	if !slices.Equal(auditParsed.Stages, []string{"nmap"}) {
		t.Fatalf("profiles.create audit diff stages = %v, want [nmap]", auditParsed.Stages)
	}
	var profiles list[gen.Profile]
	parse(request(200, viewer, http.MethodGet, "/profiles", ""), &profiles)
	if profiles.Total != 3 {
		t.Fatalf("profile page = %+v", profiles)
	}
	for _, body := range []string{
		`{"name":"bad","ports":"80,--script"}`,
		`{"name":"bad","ports":"80","nmap_max_rate":0}`,
		`{"name":"bad","ports":"80","nmap_max_rate":1000001}`,
		`{"name":"bad","ports":"80","nuclei_rate":-10}`,
		`{"name":"bad","ports":"80","nuclei_tags":["cve"]}`,
		`{"name":"bad","ports":"80","miss_threshold":0}`,
		`{"name":"bad","ports":"80","target_batch_seconds":0}`,
		`{"name":"bad","ports":"80","stages":[]}`,
		`{"name":"bad","ports":"80","stages":["httpx"]}`,
		`{"name":"bad","ports":"80","stages":["nmap","nuclei"]}`,
		`{"name":"bad","ports":"80","stages":["nmap","nmap"]}`,
		`{"name":"bad","ports":"80","stages":["nmap","masscan"]}`,
		`{"name":"bad","ports":"80","stages":["nmap","nuclei_active"]}`,
		`{"name":"bad","ports":"80","stages":["nmap","httpx","nikto"]}`,
		`{"name":"bad","ports":"80","stages":["nmap","wpscan"]}`,
		`{"name":"bad","ports":"80","stages":["nmap","httpx","zap"]}`,
	} {
		request(400, admin, http.MethodPost, "/profiles", body)
	}
	for _, body := range []string{
		`{"name":"p1 integration updated","ports":"443","stages":["nmap","nuclei"]}`,
		`{"name":"p1 integration updated","ports":"443","stages":["nmap","httpx","nikto"]}`,
	} {
		request(400, admin, http.MethodPut, path, body)
	}
	request(409, admin, http.MethodPost, "/profiles", `{"name":"p1 integration updated","ports":"22"}`)
	request(403, viewer, http.MethodPost, "/profiles", `{"name":"viewer-wf1","ports":"80","stages":["nmap"]}`)
	request(403, viewer, http.MethodPut, path, `{"name":"p1","ports":"80","stages":["nmap"]}`)
	request(403, viewer, http.MethodDelete, path, "")

	scheduleBody := fmt.Sprintf(`{"name":"Nightly sweep","profile_id":%d,"cron":"0 23 * * *","window_start":"2026-11-21T23:00:00+01:00","window_end":"2026-11-22T01:00:00+01:00"}`, profile.ID)
	var schedule scheduleView
	parse(request(201, admin, http.MethodPost, "/schedules", scheduleBody), &schedule)
	if schedule.Name != "Nightly sweep" || schedule.DojoURL != "" || schedule.Source != "ui" || schedule.Timezone != "Europe/Warsaw" || schedule.ProfileID != profile.ID ||
		!schedule.Enabled || schedule.WindowStart == nil || schedule.WindowEnd == nil || schedule.Cron.String != "0 23 * * *" {
		t.Fatalf("created schedule = %+v", schedule)
	}
	schedulePath := fmt.Sprintf("/schedules/%d", schedule.ID)
	scheduleUpdate := fmt.Sprintf(`{"name":"Every 15m","profile_id":%d,"cron":"*/15 * * * *","timezone":"UTC","enabled":false}`, profile.ID)
	parse(request(200, admin, http.MethodPut, schedulePath, scheduleUpdate), &schedule)
	if schedule.Name != "Every 15m" || schedule.Enabled || schedule.Timezone != "UTC" || schedule.Cron.String != "*/15 * * * *" || schedule.WindowStart != nil {
		t.Fatalf("updated schedule = %+v", schedule)
	}
	for _, extra := range []string{
		`"cron":"* * * * 1"`,
		`"cron":"* * * * *","timezone":"Mars/Olympus"`,
		`"cron":"* * * * *","window_start":"2026-11-21T12:00:00Z"`,
		`"cron":"* * * * *","window_start":"2026-11-21T12:00:00Z","window_end":"2026-11-21T11:00:00Z"`,
	} {
		request(400, admin, http.MethodPost, "/schedules", fmt.Sprintf(`{"profile_id":%d,%s}`, profile.ID, extra))
	}
	request(400, admin, http.MethodPost, "/schedules", `{"profile_id":999999,"cron":"* * * * *"}`)
	request(403, viewer, http.MethodPost, "/schedules", scheduleBody)
	request(403, viewer, http.MethodPut, schedulePath, scheduleUpdate)
	request(403, viewer, http.MethodDelete, schedulePath, "")

	engagementID := int64(123)
	dojo, err := q.UpsertDojoSchedule(ctx, gen.UpsertDojoScheduleParams{
		Name: "Q4 planned audit", ProfileID: profile.ID, DojoEngagementID: &engagementID, Timezone: "Europe/Warsaw",
	})
	if err != nil {
		t.Fatal(err)
	}
	var schedules list[scheduleView]
	parse(request(200, viewer, http.MethodGet, "/schedules", ""), &schedules)
	if schedules.Total != 2 || len(schedules.Items) != 2 || schedules.Items[1].Source != "dojo" ||
		schedules.Items[1].Name != "Q4 planned audit" || schedules.Items[1].DojoURL != "http://dojo.local/engagement/123" {
		t.Fatalf("schedule page = %+v", schedules)
	}
	dojoPath := fmt.Sprintf("/schedules/%d", dojo.ID)
	request(409, admin, http.MethodPut, dojoPath, scheduleUpdate)
	request(409, admin, http.MethodDelete, dojoPath, "")
	request(204, admin, http.MethodDelete, schedulePath, "")
	request(404, admin, http.MethodDelete, schedulePath, "")
	request(409, admin, http.MethodDelete, path, "") // Would delete the Dojo schedule.
	var temporary gen.Profile
	parse(request(201, admin, http.MethodPost, "/profiles", `{"name":"temporary","ports":"22"}`), &temporary)
	temporaryPath := fmt.Sprintf("/profiles/%d", temporary.ID)
	request(204, admin, http.MethodDelete, temporaryPath, "")
	request(404, admin, http.MethodDelete, temporaryPath, "")

	var events int
	err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE user_id = $1 AND
		(action LIKE 'profiles.%' OR action LIKE 'schedules.%')`, adminID).Scan(&events)
	if err != nil || events != 9 {
		t.Fatalf("configuration audit count = %d, %v, want 9", events, err)
	}
}
