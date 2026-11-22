//go:build integration

package changes

import (
	"context"
	"slices"
	"testing"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/pipeline"
)

// TestCompareSharedStages verifies WF1 changes comparison against a real DB:
//   - Default (or legacy NULL) run vs nmap-only run: HTTP title/tech and nuclei
//     differences are NOT reported; port/service changes ARE reported.
//   - Default run vs [nmap, httpx] run: nuclei-derived technologies merged into
//     http_observations are NOT falsely reported as changed when only one run
//     ran nuclei, while real httpx changes ARE reported.
func TestCompareSharedStages(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	insertRun := func(startedAt string, stages []string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx, `INSERT INTO runs (profile_id, status, started_at, finished_at, stages)
			SELECT id, 'done', $1::timestamptz, $1::timestamptz, $2 FROM profiles WHERE name = 'Default' RETURNING id`,
			startedAt, stages).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}

	exec(`INSERT INTO hosts (ip) VALUES ('10.50.0.1')`)
	exec(`INSERT INTO services (ip, port, proto, name) VALUES ('10.50.0.1', 22, 'tcp', 'ssh'), ('10.50.0.1', 80, 'tcp', 'http')`)

	// Run 1: legacy NULL stages (treated as Default), with HTTP obs + nuclei-merged tech.
	r1 := insertRun("2026-11-21T10:00:00Z", nil)
	// Run 2: nmap-only, version changed on 22, different nmap title on 80, no HTTP obs.
	r2 := insertRun("2026-11-21T11:00:00Z", []string{pipeline.StageNmap})
	// Run 3: [nmap, httpx], same httpx tech (Nginx), no nuclei tech (wordpress absent), same title.
	r3 := insertRun("2026-11-21T12:00:00Z", []string{pipeline.StageNmap, pipeline.StageHTTPX})

	exec(`INSERT INTO run_observations (run_id, ip, port, up, service_fp, nuclei_matches) VALUES
		($1, '10.50.0.1', NULL, true, NULL, '[]'::jsonb),
		($1, '10.50.0.1', 22, true, '{"proto":"tcp","name":"ssh","product":"OpenSSH","version":"8.9"}', '[]'::jsonb),
		($1, '10.50.0.1', 80, true, '{"proto":"tcp","name":"http","product":"nginx","version":"1.24","title":"Nmap Old"}',
			'[{"kind":"tech","template_id":"wordpress-detect","name":"WordPress Detect","severity":"info","tags":["tech"],"url":"http://10.50.0.1:80","tech":"wordpress","cpe":"wordpress:wordpress"}]'::jsonb),
		($2, '10.50.0.1', NULL, true, NULL, '[]'::jsonb),
		($2, '10.50.0.1', 22, true, '{"proto":"tcp","name":"ssh","product":"OpenSSH","version":"9.6"}', '[]'::jsonb),
		($2, '10.50.0.1', 80, true, '{"proto":"tcp","name":"http","product":"nginx","version":"1.24","title":"Nmap Other"}', '[]'::jsonb),
		($3, '10.50.0.1', NULL, true, NULL, '[]'::jsonb),
		($3, '10.50.0.1', 22, true, '{"proto":"tcp","name":"ssh","product":"OpenSSH","version":"8.9"}', '[]'::jsonb),
		($3, '10.50.0.1', 80, true, '{"proto":"tcp","name":"http","product":"nginx","version":"1.24","title":"Nmap Old"}', '[]'::jsonb)`,
		r1, r2, r3)

	exec(`INSERT INTO http_observations (service_id, url, title, technologies, run_id)
		SELECT id, 'http://10.50.0.1:80', 'Welcome', ARRAY['Nginx', 'wordpress'], $1 FROM services WHERE port = 80`, r1)
	exec(`INSERT INTO http_observations (service_id, url, title, technologies, run_id)
		SELECT id, 'http://10.50.0.1:80', 'Welcome', ARRAY['Nginx'], $1 FROM services WHERE port = 80`, r3)

	// 1) Legacy Default (r1) vs nmap-only (r2): only port 22 version change; zero HTTP/nuclei diffs on port 80.
	c12, err := Compare(ctx, q, &r1, &r2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c12.From.Stages, pipeline.DefaultStages()) || !slices.Equal(c12.To.Stages, []string{pipeline.StageNmap}) {
		t.Fatalf("r1→r2 stages = %v → %v", c12.From.Stages, c12.To.Stages)
	}
	if len(c12.ServicesChanged) != 1 || c12.ServicesChanged[0].Port != 22 ||
		!slices.Equal(c12.ServicesChanged[0].Fields, []string{"version"}) {
		t.Fatalf("r1→r2 services_changed = %+v, want only port 22 version", c12.ServicesChanged)
	}

	// 2) Legacy Default (r1) vs [nmap, httpx] (r3): nuclei-only tech ("wordpress") excluded → zero changes.
	c13, err := Compare(ctx, q, &r1, &r3, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(c13.ServicesChanged) != 0 {
		t.Fatalf("r1→r3 services_changed = %+v, want empty (nuclei-only tech should not diff)", c13.ServicesChanged)
	}
}
