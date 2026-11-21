// Package audit writes the audit_log. Every mutation calls Log.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

// Redacted replaces the value of a sensitive key in an audit diff.
const Redacted = "[redacted]"

// sensitiveKeys are diff keys whose values are never stored: audit_log.diff
// is plaintext jsonb, so the plaintext of _enc fields (notes, banners, HTTP
// headers/cookies/certs, artifact content) and credentials must not land in
// it (architecture §5 "Encryption"). A key matches when it equals one of
// these or ends in "_"+one of them (e.g. "new_password"). Boolean values are
// kept, so `"notes_changed": true`-style markers still work.
var sensitiveKeys = []string{
	"notes", "banner", "headers", "cookies", "tls_cert", "cert", "content",
	"password", "token", "secret", "key",
}

func sensitive(k string) bool {
	k = strings.ToLower(k)
	if strings.HasSuffix(k, "_enc") {
		return true
	}
	for _, s := range sensitiveKeys {
		if k == s || strings.HasSuffix(k, "_"+s) {
			return true
		}
	}
	return false
}

// redact walks a decoded JSON value and replaces non-boolean values of
// sensitive keys with Redacted.
func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if _, isBool := e.(bool); sensitive(k) && !isBool && e != nil {
				x[k] = Redacted
			} else {
				x[k] = redact(e)
			}
		}
	case []any:
		for i, e := range x {
			x[i] = redact(e)
		}
	}
	return v
}

// Diff marshals diff for audit_log.diff with sensitive values redacted.
func Diff(diff any) ([]byte, error) {
	if diff == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(diff)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(redact(v))
}

// Log records an action. userID nil = system or anonymous (e.g. failed login).
// diff is marshalled to JSON; values under sensitive keys (see sensitiveKeys)
// are replaced with Redacted, but callers should still not pass secrets.
func Log(ctx context.Context, q *gen.Queries, userID *int64, action, object, objectID string, diff any) error {
	b, err := Diff(diff)
	if err != nil {
		return fmt.Errorf("audit %s: marshal diff: %w", action, err)
	}
	if err := q.InsertAudit(ctx, gen.InsertAuditParams{
		UserID: userID, Action: action, Object: object, ObjectID: objectID, Diff: b,
	}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	return nil
}
