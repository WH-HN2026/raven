package signatures

import (
	"cmp"
	"slices"
	"strings"
)

func compareSignatures(column string, a, b Signature, aName, bName string) int {
	switch column {
	case "severity":
		return cmp.Compare(slices.Index(severities, a.Severity), slices.Index(severities, b.Severity))
	case "tags":
		return cmp.Compare(strings.ToLower(strings.Join(a.Tags, ", ")), strings.ToLower(strings.Join(b.Tags, ", ")))
	case "source":
		return compareFlag(b.Builtin, a.Builtin) // Built-in, Custom
	case "validation":
		return compareFlag(a.Valid, b.Valid) // Invalid, Valid
	case "status":
		return compareFlag(a.Enabled, b.Enabled) // Disabled, Enabled
	default:
		return cmp.Compare(strings.ToLower(aName), strings.ToLower(bName))
	}
}

func compareFlag(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	default:
		return -1
	}
}
