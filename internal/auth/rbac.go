package auth

import "slices"

// Role is one of the four roles from requirement 13 (architecture §6).
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleEditor   Role = "editor"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Permission names an action. Handlers declare one with Require(perm); the
// SPA receives the user's list from GET /api/auth/me and hides controls with
// useCan(perm). Keep the strings in sync with web/src/auth/permissions.ts.
type Permission string

const (
	// viewer
	PermRead   Permission = "read"   // read everything
	PermExport Permission = "export" // export hosts/services/findings/changes

	// operator: modify existing data, no create/delete
	PermFindingsEdit Permission = "findings:edit" // triage, severity, notes
	PermHostsEdit    Permission = "hosts:edit"    // owner, criticality, notes, tags, overrides

	// editor: add / delete / modify
	PermTargetsWrite    Permission = "targets:write"
	PermScopeWrite      Permission = "scope:write" // per-profile include/exclude lists
	PermProfilesWrite   Permission = "profiles:write"
	PermSchedulesWrite  Permission = "schedules:write"
	PermSignaturesWrite Permission = "signatures:write"
	PermImport          Permission = "import"
	PermRunsControl     Permission = "runs:control" // start / stop scans

	// admin
	PermUsersAdmin     Permission = "users:admin"    // users, roles
	PermTokensAdmin    Permission = "tokens:admin"   // API tokens (MCP)
	PermSettingsAdmin  Permission = "settings:admin" // Dojo connection, global rate limits
	PermGlobalScope    Permission = "scope:global"   // global blacklist
	PermAuditRead      Permission = "audit:read"
	PermScanAggressive Permission = "scan:aggressive" // create/edit/delete/schedule aggressive profiles and their scope
)

var (
	viewerPerms   = []Permission{PermRead, PermExport}
	operatorPerms = append(slices.Clone(viewerPerms), PermFindingsEdit, PermHostsEdit)
	editorPerms   = append(slices.Clone(operatorPerms),
		PermTargetsWrite, PermScopeWrite, PermProfilesWrite, PermSchedulesWrite,
		PermSignaturesWrite, PermImport, PermRunsControl)
	adminPerms = append(slices.Clone(editorPerms),
		PermUsersAdmin, PermTokensAdmin, PermSettingsAdmin, PermGlobalScope, PermAuditRead, PermScanAggressive)
)

// rolePerms is the single role → permissions map.
var rolePerms = map[Role][]Permission{
	RoleAdmin:    adminPerms,
	RoleEditor:   editorPerms,
	RoleOperator: operatorPerms,
	RoleViewer:   viewerPerms,
}

// ValidRole reports whether r is one of the four roles.
func ValidRole(r Role) bool {
	_, ok := rolePerms[r]
	return ok
}

// Permissions returns the role's permissions (nil for an unknown role).
func Permissions(r Role) []Permission {
	return slices.Clone(rolePerms[r])
}

// Can reports whether role r has permission p.
func Can(r Role, p Permission) bool {
	return slices.Contains(rolePerms[r], p)
}
