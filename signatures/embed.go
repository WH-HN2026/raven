// Package signatures embeds the built-in signature pack: safe nuclei
// templates (see README.md) loaded into the signatures table on startup by
// internal/signatures.
package signatures

import "embed"

// FS holds the templates (*.yaml at the top level; testdata is not embedded).
//
//go:embed *.yaml
var FS embed.FS
