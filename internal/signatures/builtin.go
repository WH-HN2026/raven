package signatures

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	pack "github.com/WH-HN2026/zadanie-agh-asi/signatures"
)

// Pack returns the built-in templates embedded from signatures/.
func Pack() ([]Builtin, error) {
	entries, err := fs.ReadDir(pack.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("read signature pack: %w", err)
	}
	var out []Builtin
	for _, e := range entries {
		if e.IsDir() || !templateFile(e.Name()) {
			continue
		}
		b, err := fs.ReadFile(pack.FS, e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		out = append(out, Builtin{File: e.Name(), YAML: string(b)})
	}
	return out, nil
}

// LoadBuiltins seeds/updates the built-in pack on startup. Failures are
// logged, not fatal: the app works without the pack.
func LoadBuiltins(ctx context.Context, pool *pgxpool.Pool) {
	p, err := Pack()
	if err == nil {
		err = (&Store{Pool: pool}).SyncBuiltins(ctx, p)
	}
	if err != nil {
		slog.Error("load built-in signatures", "err", err)
		return
	}
	slog.Info("built-in signatures loaded", "count", len(p))
}
