package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeStore map[string]*User

func (f fakeStore) UserForToken(_ context.Context, token string) (*User, error) {
	return f[token], nil
}

func TestRequire(t *testing.T) {
	store := fakeStore{
		"t-admin":    {ID: 1, Username: "a", Role: RoleAdmin},
		"t-editor":   {ID: 2, Username: "e", Role: RoleEditor},
		"t-operator": {ID: 3, Username: "o", Role: RoleOperator},
		"t-viewer":   {ID: 4, Username: "v", Role: RoleViewer},
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	tests := []struct {
		token string
		perm  Permission
		want  int
	}{
		{"", PermRead, http.StatusUnauthorized},
		{"bogus", PermRead, http.StatusUnauthorized},
		{"t-viewer", PermRead, http.StatusOK},
		{"t-viewer", PermHostsEdit, http.StatusForbidden},
		{"t-viewer", PermTargetsWrite, http.StatusForbidden},
		{"t-operator", PermHostsEdit, http.StatusOK},
		{"t-operator", PermTargetsWrite, http.StatusForbidden},
		{"t-editor", PermTargetsWrite, http.StatusOK},
		{"t-editor", PermUsersAdmin, http.StatusForbidden},
		{"t-admin", PermUsersAdmin, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.token+"/"+string(tt.perm), func(t *testing.T) {
			h := Sessions(store)(Require(tt.perm)(ok))
			req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
			if tt.token != "" {
				req.AddCookie(&http.Cookie{Name: CookieName, Value: tt.token})
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body)
			}
		})
	}
}

func TestCSRF(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	tests := []struct {
		method, header string
		want           int
	}{
		{http.MethodGet, "", http.StatusOK},
		{http.MethodHead, "", http.StatusOK},
		{http.MethodPost, "", http.StatusForbidden},
		{http.MethodPost, "0", http.StatusForbidden},
		{http.MethodPost, "1", http.StatusOK},
		{http.MethodPut, "", http.StatusForbidden},
		{http.MethodPatch, "", http.StatusForbidden},
		{http.MethodDelete, "", http.StatusForbidden},
		{http.MethodDelete, "1", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.method+"/"+tt.header, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/x", nil)
			if tt.header != "" {
				req.Header.Set(CSRFHeader, tt.header)
			}
			rec := httptest.NewRecorder()
			CSRF(ok).ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
