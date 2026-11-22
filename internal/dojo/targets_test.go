package dojo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/WH-HN2026/raven/internal/targets"
)

func TestListURLsHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v2/url/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("limit") != "50" || q.Get("offset") != "10" || q.Get("o") != "id" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"count":2,"results":[` +
			`{"id":1,"string":"tcp://10.0.0.1:80","host":"10.0.0.1","port":80,"tags":["web"]},` +
			`{"id":2,"string":"https://app.example.com/","host":"app.example.com","port":443,"tags":[]}` +
			`]}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, Options{})
	page, err := c.ListURLs(context.Background(), URLQuery{Limit: 50, Offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	want := &Page[URL]{
		Count: 2,
		Results: []URL{
			{ID: 1, Host: "10.0.0.1", Tags: []string{"web"}},
			{ID: 2, Host: "app.example.com", Tags: []string{}},
		},
	}
	if !reflect.DeepEqual(page, want) {
		t.Fatalf("page = %+v, want %+v", page, want)
	}
}

func TestListURLsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := testClient(srv.URL, Options{}).ListURLs(context.Background(), URLQuery{})
	if err == nil || !strings.Contains(err.Error(), "dojo list urls") || !IsStatus(err, http.StatusForbidden) {
		t.Fatalf("err = %v", err)
	}
}

type fakeTargetClient struct {
	assets      []Asset
	urls        []URL
	assetErr    error
	urlErr      error
	assetOrgs   []int64
	assetCalls  int
	urlCalls    int
	maxPageSize int // 0 = use caller limit
}

func (f *fakeTargetClient) ListAssets(_ context.Context, q AssetQuery) (*Page[Asset], error) {
	f.assetCalls++
	f.assetOrgs = append(f.assetOrgs, q.OrganizationID)
	if f.assetErr != nil {
		return nil, f.assetErr
	}
	lim := q.Limit
	if f.maxPageSize > 0 && lim > f.maxPageSize {
		lim = f.maxPageSize
	}
	start := min(q.Offset, len(f.assets))
	end := min(start+lim, len(f.assets))
	return &Page[Asset]{Count: len(f.assets), Results: f.assets[start:end]}, nil
}

func (f *fakeTargetClient) ListURLs(_ context.Context, q URLQuery) (*Page[URL], error) {
	f.urlCalls++
	if f.urlErr != nil {
		return nil, f.urlErr
	}
	lim := q.Limit
	if f.maxPageSize > 0 && lim > f.maxPageSize {
		lim = f.maxPageSize
	}
	start := min(q.Offset, len(f.urls))
	end := min(start+lim, len(f.urls))
	return &Page[URL]{Count: len(f.urls), Results: f.urls[start:end]}, nil
}

func TestFetchTargets(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		if _, err := FetchTargets(context.Background(), nil); !errors.Is(err, ErrNotReady) {
			t.Fatalf("err = %v, want ErrNotReady", err)
		}
	})

	t.Run("extracts deduplicates filters tags and skips non-targets across pages", func(t *testing.T) {
		fc := &fakeTargetClient{
			maxPageSize: 2,
			assets: []Asset{
				{ID: 1, Name: "RAVEN Planning", OrganizationID: 1, Tags: []string{"raven"}},
				{ID: 2, Name: "Web Portal", OrganizationID: 2, Tags: []string{"external"}},
				{ID: 3, Name: "10.0.0.1", OrganizationID: 1, Tags: []string{"raven", "host:web.lab", "tech:nginx", "panel:admin", "env:prod", "cve:distro-build", "user:team", "dmz"}},
				{ID: 4, Name: "10.0.2.5/24", OrganizationID: 2, Tags: []string{"asi", "subnet"}},
				{ID: 5, Name: "WEB.Example.COM.", OrganizationID: 3, Tags: []string{"app"}},
				{ID: 6, Name: "2001:db8::1", OrganizationID: 1},
				{ID: 7, Name: "10.0.0.0/7", OrganizationID: 1},
			},
			urls: []URL{
				{ID: 10, Host: "10.0.0.1", Tags: []string{"http", "dmz"}},
				{ID: 11, Host: "10.0.0.1", Tags: []string{"https"}},
				{ID: 12, Host: "web.example.com", Tags: []string{"frontend"}},
				{ID: 13, Host: "api.example.com", Tags: []string{"raven", "api"}},
				{ID: 14, Host: "", Tags: nil},
				{ID: 15, Host: "not a host!", Tags: nil},
				{ID: 16, Host: "172.30.0.10", Tags: nil},
			},
		}

		got, err := FetchTargets(context.Background(), fc)
		if err != nil {
			t.Fatal(err)
		}
		// Must query all organizations (OrganizationID == 0 on every page).
		if fc.assetCalls < 2 || fc.urlCalls < 2 {
			t.Fatalf("expected multi-page fetches, got assetCalls=%d urlCalls=%d", fc.assetCalls, fc.urlCalls)
		}
		for _, org := range fc.assetOrgs {
			if org != 0 {
				t.Fatalf("ListAssets OrganizationID = %d, want 0 (all orgs)", org)
			}
		}

		wantEntries := []targets.Entry{
			{Kind: targets.KindIP, Value: "10.0.0.1", Tags: []string{"dmz", "http", "https", "team"}},
			{Kind: targets.KindCIDR, Value: "10.0.2.0/24", Tags: []string{"subnet"}},
			{Kind: targets.KindDomain, Value: "web.example.com", Tags: []string{"app", "frontend"}},
			{Kind: targets.KindDomain, Value: "api.example.com", Tags: []string{"api"}},
			{Kind: targets.KindIP, Value: "172.30.0.10", Tags: []string{}},
		}
		// Skipped: "RAVEN Planning", "Web Portal", "2001:db8::1", "10.0.0.0/7", "", "not a host!" = 6
		if got.Skipped != 6 {
			t.Fatalf("skipped = %d, want 6", got.Skipped)
		}
		if !reflect.DeepEqual(got.Entries, wantEntries) {
			t.Fatalf("entries =\n%#v\nwant\n%#v", got.Entries, wantEntries)
		}
	})

	t.Run("propagates errors", func(t *testing.T) {
		fc := &fakeTargetClient{assetErr: errors.New("boom assets")}
		if _, err := FetchTargets(context.Background(), fc); err == nil || !strings.Contains(err.Error(), "boom assets") {
			t.Fatalf("asset err = %v", err)
		}
		fc2 := &fakeTargetClient{urlErr: errors.New("boom urls")}
		if _, err := FetchTargets(context.Background(), fc2); err == nil || !strings.Contains(err.Error(), "boom urls") {
			t.Fatalf("url err = %v", err)
		}
	})

	t.Run("paging over HTTP server", func(t *testing.T) {
		var assets [3]Asset
		for i := range assets {
			assets[i] = Asset{ID: int64(i + 1), Name: "192.0.2." + strconv.Itoa(i+1)}
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v2/assets/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("organization") != "" {
				t.Errorf("organization filter must be empty, got %q", r.URL.Query().Get("organization"))
			}
			_, _ = w.Write([]byte(`{"count":2,"results":[{"id":1,"name":"192.0.2.1"},{"id":2,"name":"RAVEN Planning"}]}`))
		})
		mux.HandleFunc("GET /api/v2/url/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"count":2,"results":[{"id":1,"host":"192.0.2.1"},{"id":2,"host":"svc.lab"}]}`))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		got, err := FetchTargets(context.Background(), testClient(srv.URL, Options{}))
		if err != nil {
			t.Fatal(err)
		}
		if got.Skipped != 1 || len(got.Entries) != 2 || got.Entries[0].Value != "192.0.2.1" || got.Entries[1].Value != "svc.lab" {
			t.Fatalf("got = %+v", got)
		}
	})
}
