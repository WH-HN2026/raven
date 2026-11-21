package dojo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDojo: first token request fails (Dojo still booting), then serves an
// empty organization/asset list and records the creates.
func TestBootstrap(t *testing.T) {
	var tokenCalls, orgCreates, assetCreates atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/api-token-auth/", func(w http.ResponseWriter, r *http.Request) {
		if tokenCalls.Add(1) == 1 {
			http.Error(w, "booting", http.StatusBadGateway)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["username"] != "admin" || in["password"] != "pw" {
			http.Error(w, "bad creds", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
	})
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Token tok" {
				http.Error(w, "no auth", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/v2/organizations/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "RAVEN" {
			t.Errorf("organization filter = %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
	}))
	mux.HandleFunc("POST /api/v2/organizations/", auth(func(w http.ResponseWriter, r *http.Request) {
		orgCreates.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7,"name":"RAVEN"}`))
	}))
	mux.HandleFunc("GET /api/v2/assets/", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
	}))
	mux.HandleFunc("POST /api/v2/assets/", auth(func(w http.ResponseWriter, r *http.Request) {
		assetCreates.Add(1)
		var a AssetSpec
		_ = json.NewDecoder(r.Body).Decode(&a)
		if a.Name != PlanningAssetName || a.OrganizationID != 7 || a.Description == "" {
			t.Errorf("asset create body = %+v", a)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":9,"name":"RAVEN Planning","organization":7}`))
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Bootstrap(ctx, BootstrapConfig{
		URL: srv.URL, AdminUser: "admin", AdminPass: "pw", Organization: "RAVEN", RetryEvery: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Organization.ID != 7 || res.Planning.ID != 9 {
		t.Fatalf("result = %+v %+v", res.Organization, res.Planning)
	}
	if tokenCalls.Load() != 2 || orgCreates.Load() != 1 || assetCreates.Load() != 1 {
		t.Fatalf("calls: token=%d org=%d asset=%d", tokenCalls.Load(), orgCreates.Load(), assetCreates.Load())
	}
}
