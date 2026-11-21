// Package users is user administration (task P2): CRUD with the safety rules
// in this file, session revocation and audit_log. The HTTP handlers and the
// MCP server call Store.
package users

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/WH-HN2026/raven/internal/auth"
)

var (
	ErrNotFound = errors.New("user not found")
	ErrConflict = errors.New("username already exists")
	ErrInvalid  = errors.New("invalid input")
	// ErrForbidden: the change would lock the actor or everyone out.
	ErrForbidden = errors.New("not allowed")
)

// MinPasswordLen is the password policy (length only, per NIST 800-63B).
const MinPasswordLen = 12

const maxPasswordLen = 256

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// ValidatePassword enforces the password policy.
func ValidatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen {
		return fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, MinPasswordLen)
	}
	if n > maxPasswordLen {
		return fmt.Errorf("%w: password must be at most %d characters", ErrInvalid, maxPasswordLen)
	}
	return nil
}

// ValidateUsername: 1–64 chars, letters, digits and . _ @ -, starting alphanumeric.
func ValidateUsername(name string) error {
	if !usernameRe.MatchString(name) {
		return fmt.Errorf("%w: username must be 1-64 characters of letters, digits, '.', '_', '@', '-'", ErrInvalid)
	}
	return nil
}

func validateRole(r auth.Role) error {
	if !auth.ValidRole(r) {
		return fmt.Errorf("%w: unknown role %q", ErrInvalid, r)
	}
	return nil
}

// Patch is a partial update; nil fields are unchanged.
type Patch struct {
	Role     *auth.Role `json:"role,omitempty"`
	Disabled *bool      `json:"disabled,omitempty"`
	Password *string    `json:"password,omitempty"`
}

// state is the part of a user row that a Patch can change.
type state struct {
	Role     auth.Role
	Disabled bool
}

func isEnabledAdmin(s state) bool { return s.Role == auth.RoleAdmin && !s.Disabled }

// planUpdate validates p against the rules and returns the new state and
// whether the target's sessions must be revoked. enabledAdmins are the IDs of
// all enabled admins (locked by the caller).
func planUpdate(actorID, targetID int64, cur state, p Patch, enabledAdmins []int64) (next state, revoke bool, err error) {
	next = cur
	if p.Role != nil {
		if err := validateRole(*p.Role); err != nil {
			return cur, false, err
		}
		next.Role = *p.Role
	}
	if p.Disabled != nil {
		next.Disabled = *p.Disabled
	}
	if p.Password != nil {
		if err := ValidatePassword(*p.Password); err != nil {
			return cur, false, err
		}
	}
	if actorID == targetID {
		if next.Role != cur.Role {
			return cur, false, fmt.Errorf("%w: you can't change your own role", ErrForbidden)
		}
		if next.Disabled && !cur.Disabled {
			return cur, false, fmt.Errorf("%w: you can't disable yourself", ErrForbidden)
		}
	}
	if isEnabledAdmin(cur) && !isEnabledAdmin(next) && lastAdmin(targetID, enabledAdmins) {
		return cur, false, fmt.Errorf("%w: can't demote or disable the last enabled admin", ErrForbidden)
	}
	revoke = next.Role != cur.Role || (next.Disabled && !cur.Disabled) || p.Password != nil
	return next, revoke, nil
}

// checkDelete validates deleting target by actor.
func checkDelete(actorID, targetID int64, cur state, enabledAdmins []int64) error {
	if actorID == targetID {
		return fmt.Errorf("%w: you can't delete yourself", ErrForbidden)
	}
	if isEnabledAdmin(cur) && lastAdmin(targetID, enabledAdmins) {
		return fmt.Errorf("%w: can't delete the last enabled admin", ErrForbidden)
	}
	return nil
}

func lastAdmin(id int64, enabledAdmins []int64) bool {
	return len(enabledAdmins) <= 1 && (len(enabledAdmins) == 0 || slices.Contains(enabledAdmins, id))
}
