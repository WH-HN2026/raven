package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListRejectsInvalidSort(t *testing.T) {
	a := &api{} // Invalid parameters must be rejected before reading from storage.
	for _, tc := range []struct {
		name string
		list http.HandlerFunc
	}{
		{"hosts", a.listHosts},
		{"findings", a.listFindings},
		{"changes", a.getChanges},
		{"runs", a.listRuns},
		{"services", a.listServices},
		{"technologies", a.listTechnologies},
		{"targets", a.listTargets},
		{"profiles", a.listProfiles},
		{"schedules", a.listSchedules},
		{"signatures", a.listSignatures},
		{"users", a.listUsers},
	} {
		for _, query := range []string{"sort=unsupported_column", "dir=sideways"} {
			t.Run(tc.name+"/"+query, func(t *testing.T) {
				w := httptest.NewRecorder()
				tc.list(w, httptest.NewRequest(http.MethodGet, "/api/"+tc.name+"?"+query, nil))
				if w.Code != http.StatusBadRequest {
					t.Fatalf("got %d, want 400: %s", w.Code, w.Body)
				}
			})
		}
	}
}
