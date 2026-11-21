//go:build integration

package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/WH-HN2026/raven/internal/dbtest"
)

func TestHostsAndFindingsSortAcrossPages(t *testing.T) {
	pool := dbtest.Fresh(t)
	seed := []string{
		`INSERT INTO hosts (ip, miss_count) VALUES
			('192.0.2.1', 8), ('192.0.2.2', 2), ('192.0.2.10', 2)`,
		`INSERT INTO dojo_findings (id, title, severity, active, date) VALUES
			(11, 'Bravo', 'Critical', true, '2026-01-01'),
			(12, 'alpha', 'Info', false, '2026-01-02'),
			(13, 'Alpha', 'High', true, '2026-01-02')`,
	}
	for _, sql := range seed {
		if _, err := pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	a := &api{Deps: Deps{Pool: pool}}
	for _, tc := range []struct {
		name   string
		list   http.HandlerFunc
		path   string
		column string
		first  string
		second string
	}{
		{"host misses asc", a.listHosts, "/hosts?sort=misses&dir=asc", "ip", `"192.0.2.2"`, `"192.0.2.10"`},
		{"host misses desc", a.listHosts, "/hosts?sort=misses&dir=desc", "ip", `"192.0.2.1"`, `"192.0.2.2"`},
		{"finding title asc", a.listFindings, "/findings?sort=title&dir=asc", "id", "13", "12"},
		{"finding title desc", a.listFindings, "/findings?sort=title&dir=desc", "id", "11", "13"},
		{"finding severity asc", a.listFindings, "/findings?sort=severity&dir=asc", "id", "12", "13"},
		{"finding severity desc", a.listFindings, "/findings?sort=severity&dir=desc", "id", "11", "13"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for offset, want := range []string{tc.first, tc.second} {
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, tc.path+"&limit=1&offset="+strconv.Itoa(offset), nil)
				tc.list(w, req)
				r := w.Result()
				if r.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(r.Body)
					r.Body.Close()
					t.Fatalf("page %d: %d %s", offset, r.StatusCode, body)
				}
				var page list[map[string]json.RawMessage]
				err := json.NewDecoder(r.Body).Decode(&page)
				r.Body.Close()
				if err != nil || page.Total != 3 || len(page.Items) != 1 {
					t.Fatalf("page %d: %+v, %v", offset, page, err)
				}
				if got := string(page.Items[0][tc.column]); got != want {
					t.Errorf("page %d: %s, want %s", offset, got, want)
				}
			}
		})
	}
}
