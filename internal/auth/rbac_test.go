package auth

import "testing"

func TestRolePermissions(t *testing.T) {
	all := Permissions(RoleAdmin)
	// want[perm] = roles that must have it; every other role must not.
	want := map[Permission][]Role{
		PermRead:            {RoleAdmin, RoleEditor, RoleOperator, RoleViewer},
		PermExport:          {RoleAdmin, RoleEditor, RoleOperator, RoleViewer},
		PermFindingsEdit:    {RoleAdmin, RoleEditor, RoleOperator},
		PermHostsEdit:       {RoleAdmin, RoleEditor, RoleOperator},
		PermTargetsWrite:    {RoleAdmin, RoleEditor},
		PermScopeWrite:      {RoleAdmin, RoleEditor},
		PermProfilesWrite:   {RoleAdmin, RoleEditor},
		PermSchedulesWrite:  {RoleAdmin, RoleEditor},
		PermSignaturesWrite: {RoleAdmin, RoleEditor},
		PermImport:          {RoleAdmin, RoleEditor},
		PermRunsControl:     {RoleAdmin, RoleEditor},
		PermUsersAdmin:      {RoleAdmin},
		PermTokensAdmin:     {RoleAdmin},
		PermSettingsAdmin:   {RoleAdmin},
		PermGlobalScope:     {RoleAdmin},
		PermAuditRead:       {RoleAdmin},
	}
	if len(want) != len(all) {
		t.Fatalf("admin has %d permissions, table covers %d: update the test", len(all), len(want))
	}
	roles := []Role{RoleAdmin, RoleEditor, RoleOperator, RoleViewer}
	for perm, allowed := range want {
		for _, r := range roles {
			exp := false
			for _, a := range allowed {
				exp = exp || a == r
			}
			if got := Can(r, perm); got != exp {
				t.Errorf("Can(%s, %s) = %v, want %v", r, perm, got, exp)
			}
		}
	}
	if Can("root", PermRead) || ValidRole("root") {
		t.Error("unknown role must have no permissions")
	}
}
