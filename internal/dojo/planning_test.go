package dojo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

func TestParseProfileTag(t *testing.T) {
	tests := []struct {
		name   string
		tags   []string
		want   string
		wantOK bool
	}{
		{"exact", []string{"raven-profile:default"}, "default", true},
		{"among other tags", []string{"lab", "raven-profile:web-fast", "nightly"}, "web-fast", true},
		{"uppercase prefix", []string{"RAVEN-PROFILE:Default"}, "Default", true},
		{"trimmed", []string{"  raven-profile: fast  "}, "fast", true},
		{"empty name skipped", []string{"raven-profile:", "raven-profile:   "}, "", false},
		{"empty then valid", []string{"raven-profile:", "raven-profile:corp"}, "corp", true},
		{"substring not prefix", []string{"my-raven-profile:default"}, "", false},
		{"unrelated tags", []string{"raven", "host:a"}, "", false},
		{"empty slice", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseProfileTag(tc.tags)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("parseProfileTag(%v) = (%q, %v), want (%q, %v)", tc.tags, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestProfileIndex(t *testing.T) {
	idx := newProfileIndex([]gen.ListAllProfileNamesRow{
		{ID: 1, Name: "default"},
		{ID: 2, Name: "WebFast"},
		{ID: 3, Name: "CaseMix"},
		{ID: 4, Name: "casemix"},
	})
	tests := []struct {
		name   string
		wantID int64
		wantOK bool
	}{
		{"default", 1, true},
		{"webfast", 2, true}, // Dojo lowercases all tags
		{"WebFast", 2, true},
		{"CaseMix", 3, true}, // exact beats case-fold
		{"casemix", 4, true},
		{"missing", 0, false},
	}
	for _, tc := range tests {
		got, ok := idx.resolve(tc.name)
		if got.id != tc.wantID || ok != tc.wantOK {
			t.Errorf("resolve(%q) = (%+v, %v), want (id=%d, %v)", tc.name, got, ok, tc.wantID, tc.wantOK)
		}
	}
}

func TestParseEngagementWindow(t *testing.T) {
	warsaw, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		start     string
		end       string
		wantStart string
		wantEnd   string
		wantErr   bool
	}{
		{
			name:      "single day covers full day",
			start:     "2026-12-01",
			end:       "2026-12-01",
			wantStart: "2026-12-01T00:00:00+01:00",
			wantEnd:   "2026-12-02T00:00:00+01:00",
		},
		{
			name:      "multi day range",
			start:     "2026-07-10",
			end:       "2026-07-12",
			wantStart: "2026-07-10T00:00:00+02:00",
			wantEnd:   "2026-07-13T00:00:00+02:00",
		},
		{
			name:      "rfc3339 timestamps kept verbatim",
			start:     "2026-12-01T22:00:00Z",
			end:       "2026-12-02T06:00:00Z",
			wantStart: "2026-12-01T22:00:00Z",
			wantEnd:   "2026-12-02T06:00:00Z",
		},
		{
			name:      "both empty",
			start:     "",
			end:       "",
			wantStart: "",
			wantEnd:   "",
		},
		{
			name:      "start only",
			start:     "2026-12-01",
			end:       "",
			wantStart: "2026-12-01T00:00:00+01:00",
			wantEnd:   "",
		},
		{
			name:      "end only",
			start:     "",
			end:       "2026-12-01",
			wantStart: "",
			wantEnd:   "2026-12-02T00:00:00+01:00",
		},
		{
			name:    "inverted dates rejected",
			start:   "2026-12-05",
			end:     "2026-12-01",
			wantErr: true,
		},
		{
			name:    "equal rfc3339 rejected",
			start:   "2026-12-01T22:00:00Z",
			end:     "2026-12-01T22:00:00Z",
			wantErr: true,
		},
		{
			name:    "bad start date",
			start:   "not-a-date",
			end:     "2026-12-01",
			wantErr: true,
		},
		{
			name:    "bad end date",
			start:   "2026-12-01",
			end:     "12/01/2026",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, e, err := parseEngagementWindow(tc.start, tc.end, warsaw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got start=%v end=%v", s, e)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			gotS, gotE := "", ""
			if s != nil {
				gotS = s.Format(time.RFC3339)
			}
			if e != nil {
				gotE = e.Format(time.RFC3339)
			}
			if gotS != tc.wantStart || gotE != tc.wantEnd {
				t.Fatalf("got (%q, %q), want (%q, %q)", gotS, gotE, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestNextEngagementStatus(t *testing.T) {
	tests := []struct {
		runStatus  string
		sentStatus string
		want       string
		wantSend   bool
	}{
		{"pending", "", "", false},
		{"running", "", EngagementInProgress, true},
		{"suspended", "", EngagementInProgress, true},
		{"running", EngagementInProgress, "", false},
		{"suspended", EngagementInProgress, "", false},
		{"done", "", EngagementCompleted, true},
		{"done", EngagementInProgress, EngagementCompleted, true},
		{"failed", EngagementInProgress, EngagementCompleted, true},
		{"stopped", EngagementInProgress, EngagementCompleted, true},
		{"done", EngagementCompleted, "", false},
		{"failed", EngagementCompleted, "", false},
		{"running", engagementStatusNotFound, "", false},
		{"done", engagementStatusNotFound, "", false},
		{"unknown", "", "", false},
	}
	for _, tc := range tests {
		got, send := nextEngagementStatus(tc.runStatus, tc.sentStatus)
		if got != tc.want || send != tc.wantSend {
			t.Errorf("nextEngagementStatus(%q, %q) = (%q, %v), want (%q, %v)",
				tc.runStatus, tc.sentStatus, got, send, tc.want, tc.wantSend)
		}
	}
}

func TestMapPlannedEngagement(t *testing.T) {
	idx := newProfileIndex([]gen.ListAllProfileNamesRow{
		{ID: 7, Name: "Default", Stages: []string{"nmap", "httpx", "nuclei"}},
		{ID: 8, Name: "FullAggressive", Stages: []string{"nmap", "httpx", "nikto"}},
	})
	e := Engagement{
		ID: 99, Name: "Weekend scan", Status: EngagementNotStarted,
		TargetStart: "2026-12-01", TargetEnd: "2026-12-02",
		Tags: []string{"raven", "raven-profile:default"},
	}
	p, reason, agg := mapPlannedEngagement(e, idx, "UTC", time.UTC)
	if reason != "" || agg != nil {
		t.Fatalf("unexpected skip: reason=%q agg=%+v", reason, agg)
	}
	if p.Name != "Weekend scan" || p.ProfileID != 7 || p.DojoEngagementID == nil || *p.DojoEngagementID != 99 || p.Timezone != "UTC" {
		t.Fatalf("params = %+v", p)
	}
	if p.WindowStart == nil || p.WindowEnd == nil ||
		p.WindowStart.Format(time.RFC3339) != "2026-12-01T00:00:00Z" ||
		p.WindowEnd.Format(time.RFC3339) != "2026-12-03T00:00:00Z" {
		t.Fatalf("window = %v .. %v", p.WindowStart, p.WindowEnd)
	}

	// Aggressive profile → skipped cleanly and flagged for audit.
	_, reason, agg = mapPlannedEngagement(Engagement{
		ID: 103, Name: "Dojo aggressive attempt", TargetStart: "2026-12-01", TargetEnd: "2026-12-02",
		Tags: []string{"raven-profile:fullaggressive"},
	}, idx, "UTC", time.UTC)
	if !strings.Contains(reason, "aggressive") || agg == nil || agg.id != 8 || agg.name != "FullAggressive" {
		t.Fatalf("aggressive skip = (reason=%q, agg=%+v)", reason, agg)
	}

	// Unknown profile → skipped cleanly.
	_, reason, agg = mapPlannedEngagement(Engagement{ID: 100, Tags: []string{"raven-profile:nope"}}, idx, "UTC", time.UTC)
	if !strings.Contains(reason, "unknown profile") || agg != nil {
		t.Fatalf("unknown profile reason = %q agg=%+v", reason, agg)
	}

	// Missing tag → skipped cleanly.
	_, reason, agg = mapPlannedEngagement(Engagement{ID: 101, Tags: []string{"other"}}, idx, "UTC", time.UTC)
	if !strings.Contains(reason, "missing") || agg != nil {
		t.Fatalf("missing tag reason = %q agg=%+v", reason, agg)
	}

	// Invalid window → skipped cleanly.
	_, reason, agg = mapPlannedEngagement(Engagement{
		ID: 102, Tags: []string{"raven-profile:default"}, TargetStart: "2026-12-05", TargetEnd: "2026-12-01",
	}, idx, "UTC", time.UTC)
	if !strings.Contains(reason, "not after") || agg != nil {
		t.Fatalf("invalid window reason = %q agg=%+v", reason, agg)
	}
}

func TestEngagementClientMethodsHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/engagements/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("product") != "12" || q.Get("status") != "Not Started" ||
			q.Get("tag") != "raven-profile:" || q.Get("tags") != "a,b" || q.Get("o") != "created" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"count":1,"results":[{"id":55,"name":"Plan 1","product":12,"status":"Not Started","target_start":"2026-12-01","target_end":"2026-12-02","tags":["raven-profile:default"]}]}`))
	})
	mux.HandleFunc("GET /api/v2/engagements/55/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":55,"name":"Plan 1","product":12,"status":"In Progress","target_start":"2026-12-01","target_end":"2026-12-02","tags":["raven-profile:default"]}`))
	})
	mux.HandleFunc("PATCH /api/v2/engagements/55/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["status"] != EngagementInProgress {
			t.Errorf("patch body = %v", body)
		}
		_, _ = w.Write([]byte(`{"id":55,"status":"In Progress"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := testClient(srv.URL, Options{})
	page, err := c.ListEngagements(context.Background(), EngagementQuery{
		AssetID: 12, Status: EngagementNotStarted, Tags: []string{"a", "b"}, TagContains: ProfileTagPrefix,
	})
	if err != nil || page.Count != 1 || len(page.Results) != 1 || page.Results[0].ID != 55 {
		t.Fatalf("list: page=%+v err=%v", page, err)
	}
	if err := c.SetEngagementStatus(context.Background(), 55, EngagementInProgress); err != nil {
		t.Fatalf("patch: %v", err)
	}
	eng, err := c.GetEngagement(context.Background(), 55)
	if err != nil || eng.ID != 55 || eng.Status != EngagementInProgress {
		t.Fatalf("get: eng=%+v err=%v", eng, err)
	}
}
