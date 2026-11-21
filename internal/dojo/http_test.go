package dojo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(url string, o Options) *HTTPClient {
	if o.Backoff == 0 {
		o.Backoff = time.Millisecond
	}
	return NewHTTPClientOpts(url, "tok", o)
}

func TestRetries(t *testing.T) {
	tests := []struct {
		name      string
		statuses  []int // answered in order; the last one repeats
		attempts  int
		wantCalls int32
		wantErr   string
	}{
		{"5xx then ok", []int{502, 503, 200}, 4, 3, ""},
		{"429 then ok", []int{429, 200}, 4, 2, ""},
		{"400 not retried", []int{400}, 4, 1, "HTTP 400: boom"},
		{"404 not retried", []int{404}, 4, 1, "HTTP 404"},
		{"5xx gives up", []int{500}, 3, 3, "after 3 attempts"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(calls.Add(1)) - 1
				st := tc.statuses[min(n, len(tc.statuses)-1)]
				if r.Header.Get("Authorization") != "Token tok" {
					t.Errorf("auth header = %q", r.Header.Get("Authorization"))
				}
				if st != 200 {
					http.Error(w, "boom", st)
					return
				}
				_, _ = w.Write([]byte(`{"count":1,"results":[{"id":5,"title":"x"}]}`))
			}))
			defer srv.Close()
			c := testClient(srv.URL, Options{MaxAttempts: tc.attempts})
			page, err := c.ListFindings(context.Background(), FindingQuery{Tags: []string{"asi"}})
			if calls.Load() != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls.Load(), tc.wantCalls)
			}
			if tc.wantErr == "" {
				if err != nil || page.Results[0].ID != 5 {
					t.Fatalf("page=%+v err=%v", page, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "dojo list findings") {
				t.Fatalf("err = %v, want it to contain %q and context", err, tc.wantErr)
			}
			var he *HTTPError
			if !errors.As(err, &he) {
				t.Fatalf("err is not an *HTTPError: %v", err)
			}
		})
	}
}

func TestRetryNetworkError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close() // drop the connection without an answer
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL, Options{})
	if err := c.SetEngagementStatus(context.Background(), 3, EngagementCompleted); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

func TestErrorBodyTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"name":["` + strings.Repeat("x", 5000) + `"]}`))
	}))
	defer srv.Close()
	_, err := testClient(srv.URL, Options{}).PatchFinding(context.Background(), 9, FindingPatch{})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 400 || len(he.Body) > 512 || !strings.HasPrefix(he.Body, `{"name":["xxx`) {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(err.Error(), "dojo patch finding 9: PATCH /api/v2/findings/9/: HTTP 400") {
		t.Fatalf("err context = %.80s", err.Error())
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var inflight, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		inflight.Add(-1)
		_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL, Options{Concurrency: 2})
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ListAssets(context.Background(), AssetQuery{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if peak.Load() != 2 {
		t.Fatalf("peak in-flight = %d, want 2", peak.Load())
	}
}

func TestDefaultConcurrency(t *testing.T) {
	if c := NewHTTPClient("http://x", ""); cap(c.sem) != 4 {
		t.Fatalf("default concurrency = %d", cap(c.sem))
	}
}

func TestPerAttemptTimeout(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond) // longer than the client's per-attempt timeout
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL, Options{Timeout: 50 * time.Millisecond})
	if err := c.SetAssetTags(context.Background(), 1, nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (timeout then retry)", calls.Load())
	}
}

func TestImportMultipart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/reimport-scan/" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		f := r.MultipartForm.Value
		want := map[string]string{
			"scan_type": "Nmap Scan", "test": "42", "close_old_findings": "true",
			"auto_create_context": "false", "apply_tags_to_findings": "true",
			"scan_date": "2026-11-20", "deduplication_execution_mode": "async_wait",
		}
		for k, v := range want {
			if got := f[k]; len(got) != 1 || got[0] != v {
				t.Errorf("field %s = %v, want %q", k, got, v)
			}
		}
		if got := f["tags"]; len(got) != 2 || got[0] != "asi" || got[1] != "ip:10.0.0.1" {
			t.Errorf("tags = %v", got)
		}
		if _, ok := f["engagement"]; ok {
			t.Errorf("zero engagement id must be omitted")
		}
		fh := r.MultipartForm.File["file"]
		if len(fh) != 1 || fh[0].Filename != "nmap.xml" {
			t.Fatalf("file = %+v", fh)
		}
		fd, _ := fh[0].Open()
		b, _ := io.ReadAll(fd)
		if string(b) != "<nmaprun/>" {
			t.Errorf("file content = %q", b)
		}
		_, _ = w.Write([]byte(`{"test_id":42,"engagement_id":7,"product_id":3,"product_type_id":1,
			"statistics":{"before":{"total":{"active":3,"total":3}},
			"delta":{"created":{"total":{"total":1}},"closed":{"total":{"total":2}},
			         "reactivated":{"total":{"total":0}},"untouched":{"total":{"total":1}}},
			"after":{"total":{"active":2,"total":4}}}}`))
	}))
	defer srv.Close()
	res, err := testClient(srv.URL, Options{}).ReimportScan(context.Background(), ImportRequest{
		ScanType: "Nmap Scan", TestID: 42, FileName: "nmap.xml", File: strings.NewReader("<nmaprun/>"),
		CloseOldFindings: true, Tags: []string{"asi", "ip:10.0.0.1"}, TagFindings: true,
		ScanDate: time.Date(2026, 11, 20, 23, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := ImportResult{TestID: 42, EngagementID: 7, AssetID: 3, OrganizationID: 1,
		Created: 1, Closed: 2, Untouched: 1, Active: 2, Total: 4}
	if *res != want {
		t.Fatalf("result = %+v, want %+v", *res, want)
	}
}

// The multipart body must be resent intact on retry.
func TestImportRetryResendsBody(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil || len(r.MultipartForm.File["file"]) != 1 {
			t.Errorf("attempt %d: bad multipart: %v", calls.Load()+1, err)
		}
		if calls.Add(1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"test_id":9,"statistics":{"after":{"total":{"active":3,"total":3}}}}`))
	}))
	defer srv.Close()
	res, err := testClient(srv.URL, Options{}).ImportScan(context.Background(), ImportRequest{
		ScanType: "Nmap Scan", EngagementID: 7, File: strings.NewReader("<nmaprun/>"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || res.TestID != 9 || res.Created != 3 {
		t.Fatalf("calls=%d res=%+v", calls.Load(), res)
	}
}

// A racing writer created the asset between our list and create: Dojo answers
// 400 (unique name), and we must return the existing one.
func TestGetOrCreateRace(t *testing.T) {
	var lists atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/assets/", func(w http.ResponseWriter, r *http.Request) {
		if lists.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"count":1,"results":[{"id":11,"name":"10.0.0.1"}]}`))
	})
	mux.HandleFunc("POST /api/v2/assets/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"name":["Asset with this Name already exists."]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	a, err := testClient(srv.URL, Options{}).GetOrCreateAsset(context.Background(), AssetSpec{Name: "10.0.0.1", OrganizationID: 1})
	if err != nil || a.ID != 11 {
		t.Fatalf("asset=%+v err=%v", a, err)
	}
}

// Concurrent get-or-create of the same engagement in one process creates it once.
func TestGetOrCreateEngagementSerialised(t *testing.T) {
	var mu sync.Mutex
	var created []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/engagements/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Query().Get("product") != "3" || r.URL.Query().Get("name") != "ASI: default" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		if len(created) == 0 {
			_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"count":1,"results":[{"id":8,"name":"ASI: default","product":3}]}`))
	})
	mux.HandleFunc("POST /api/v2/engagements/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		created = append(created, string(b))
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":8,"name":"ASI: default","product":3}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := testClient(srv.URL, Options{})
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := c.GetOrCreateEngagement(context.Background(), EngagementSpec{AssetID: 3, Name: "ASI: default"})
			if err != nil || e.ID != 8 {
				t.Errorf("e=%+v err=%v", e, err)
			}
		}()
	}
	wg.Wait()
	if len(created) != 1 {
		t.Fatalf("creates = %d, want 1", len(created))
	}
	if !strings.Contains(created[0], `"engagement_type":"CI/CD"`) || !strings.Contains(created[0], `"product":3`) {
		t.Fatalf("create body = %s", created[0])
	}
}
