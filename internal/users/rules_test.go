package users

import (
	"errors"
	"strings"
	"testing"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/auth"
)

func ptr[T any](v T) *T { return &v }

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		pw string
		ok bool
	}{
		{"", false},
		{"short", false},
		{"elevenchars", false},
		{"twelve chars", true},
		{"zażółć gęślą", true}, // 12 runes, more bytes
		{"żółćżółćżół", false}, // 11 runes, 22 bytes
		{strings.Repeat("x", 256), true},
		{strings.Repeat("x", 257), false},
	}
	for _, tt := range tests {
		err := ValidatePassword(tt.pw)
		if (err == nil) != tt.ok {
			t.Errorf("ValidatePassword(%q) = %v, want ok=%v", tt.pw, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidatePassword(%q) error %v is not ErrInvalid", tt.pw, err)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	for name, ok := range map[string]bool{
		"alice": true, "a.b-c_d@agh": true, "A1": true,
		"": false, " alice": false, ".alice": false, "al ice": false, "al/ice": false,
		strings.Repeat("a", 64): true, strings.Repeat("a", 65): false,
	} {
		if err := ValidateUsername(name); (err == nil) != ok {
			t.Errorf("ValidateUsername(%q) = %v, want ok=%v", name, err, ok)
		}
	}
}

func TestPlanUpdate(t *testing.T) {
	const self, other, admin2 = 1, 2, 3
	admin := state{Role: auth.RoleAdmin}
	viewer := state{Role: auth.RoleViewer}
	disabledAdmin := state{Role: auth.RoleAdmin, Disabled: true}
	oneAdmin := []int64{other}
	twoAdmins := []int64{self, other}
	tests := []struct {
		name    string
		actor   int64
		target  int64
		cur     state
		patch   Patch
		admins  []int64
		want    state
		revoke  bool
		wantErr error
	}{
		{"no-op patch keeps sessions", self, other, viewer, Patch{}, twoAdmins, viewer, false, nil},
		{"promote viewer revokes", self, other, viewer, Patch{Role: ptr(auth.RoleEditor)}, twoAdmins, state{Role: auth.RoleEditor}, true, nil},
		{"same role is not a change", self, other, viewer, Patch{Role: ptr(auth.RoleViewer)}, twoAdmins, viewer, false, nil},
		{"disable revokes", self, other, viewer, Patch{Disabled: ptr(true)}, twoAdmins, state{Role: auth.RoleViewer, Disabled: true}, true, nil},
		{"enable doesn't revoke", self, other, state{Role: auth.RoleViewer, Disabled: true}, Patch{Disabled: ptr(false)}, twoAdmins, viewer, false, nil},
		{"password reset revokes", self, other, viewer, Patch{Password: ptr("new password 123")}, twoAdmins, viewer, true, nil},
		{"short password rejected", self, other, viewer, Patch{Password: ptr("short")}, twoAdmins, viewer, false, ErrInvalid},
		{"unknown role rejected", self, other, viewer, Patch{Role: ptr(auth.Role("root"))}, twoAdmins, viewer, false, ErrInvalid},

		{"self-demotion", self, self, admin, Patch{Role: ptr(auth.RoleEditor)}, twoAdmins, admin, false, ErrForbidden},
		{"self-disable", self, self, admin, Patch{Disabled: ptr(true)}, twoAdmins, admin, false, ErrForbidden},
		{"own password reset allowed", self, self, admin, Patch{Password: ptr("new password 123")}, twoAdmins, admin, true, nil},

		{"demote one of two admins", self, other, admin, Patch{Role: ptr(auth.RoleViewer)}, twoAdmins, viewer, true, nil},
		{"demote last admin", admin2, other, admin, Patch{Role: ptr(auth.RoleViewer)}, oneAdmin, admin, false, ErrForbidden},
		{"disable last admin", admin2, other, admin, Patch{Disabled: ptr(true)}, oneAdmin, admin, false, ErrForbidden},
		{"disabled admin may be demoted", self, other, disabledAdmin, Patch{Role: ptr(auth.RoleViewer)}, []int64{self}, state{Role: auth.RoleViewer, Disabled: true}, true, nil},
		{"re-enable admin", self, other, disabledAdmin, Patch{Disabled: ptr(false)}, []int64{self}, admin, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, revoke, err := planUpdate(tt.actor, tt.target, tt.cur, tt.patch, tt.admins)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want || revoke != tt.revoke {
				t.Fatalf("got %+v revoke=%v, want %+v revoke=%v", got, revoke, tt.want, tt.revoke)
			}
		})
	}
}

func TestCheckDelete(t *testing.T) {
	admin := state{Role: auth.RoleAdmin}
	tests := []struct {
		name          string
		actor, target int64
		cur           state
		admins        []int64
		wantErr       error
	}{
		{"delete self", 1, 1, admin, []int64{1, 2}, ErrForbidden},
		{"delete viewer", 1, 2, state{Role: auth.RoleViewer}, []int64{1}, nil},
		{"delete other admin", 1, 2, admin, []int64{1, 2}, nil},
		{"delete last admin", 1, 2, admin, []int64{2}, ErrForbidden},
		{"delete disabled admin", 1, 2, state{Role: auth.RoleAdmin, Disabled: true}, []int64{1}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDelete(tt.actor, tt.target, tt.cur, tt.admins)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
