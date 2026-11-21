// Package audit writes the audit_log. Every mutation calls Log.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
)

// Log records an action. userID nil = system or anonymous (e.g. failed login).
// diff is marshalled to JSON; it must never contain secrets or plaintext of _enc fields.
func Log(ctx context.Context, q *gen.Queries, userID *int64, action, object, objectID string, diff any) error {
	if diff == nil {
		diff = map[string]any{}
	}
	b, err := json.Marshal(diff)
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
