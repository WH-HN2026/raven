//go:build integration

package db_test

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/WH-HN2026/raven/internal/db"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/pipeline"
)

const (
	lb1Version = 20261121224954 // organizers_lab_profile
	lb6Version = 20261121235950 // seeded_default_aggressive_profiles
)

type seededProfile struct {
	name, ports       string
	nmapRate, nucRate int32
	stages            []string
}

func seededProfiles(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string]seededProfile {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT name, ports, nmap_max_rate, nuclei_rate, stages FROM profiles`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]seededProfile{}
	for rows.Next() {
		var p seededProfile
		if err := rows.Scan(&p.name, &p.ports, &p.nmapRate, &p.nucRate, &p.stages); err != nil {
			t.Fatal(err)
		}
		out[p.name] = p
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func countDockerHostScope(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM scope_entries WHERE value = '172.17.0.1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSeededProfilesDefaultAndAggressive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool := dbtest.Fresh(t)

	got := seededProfiles(t, ctx, pool)
	if len(got) != 2 {
		t.Fatalf("seeded profiles = %v, want exactly Default and Aggressive", got)
	}
	def, ok := got[pipeline.DefaultProfileName]
	if !ok {
		t.Fatalf("no %q profile: %v", pipeline.DefaultProfileName, got)
	}
	if !slices.Equal(def.stages, pipeline.DefaultStages()) || pipeline.IsAggressive(def.stages) {
		t.Fatalf("Default stages = %v, want %v (not aggressive)", def.stages, pipeline.DefaultStages())
	}
	agg, ok := got[pipeline.AggressiveProfileName]
	if !ok {
		t.Fatalf("no %q profile: %v", pipeline.AggressiveProfileName, got)
	}
	if !slices.Equal(agg.stages, pipeline.AggressiveStages()) || !pipeline.IsAggressive(agg.stages) {
		t.Fatalf("Aggressive stages = %v, want %v", agg.stages, pipeline.AggressiveStages())
	}
	if agg.ports != def.ports || agg.nmapRate != def.nmapRate || agg.nucRate != def.nucRate {
		t.Fatalf("Aggressive settings %+v differ from Default %+v", agg, def)
	}
	if n := countDockerHostScope(t, ctx, pool); n != 0 {
		t.Fatalf("172.17.0.1 scope entries = %d, want 0", n)
	}
	var schedules int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schedules`).Scan(&schedules); err != nil || schedules != 0 {
		t.Fatalf("schedules = %d (err %v), want 0", schedules, err)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log a JOIN profiles p ON a.object_id = p.id::text
		WHERE p.name = 'Aggressive' AND a.action = 'profiles.create' AND a.object = 'profile'
		  AND (a.diff->>'aggressive')::boolean AND a.user_id IS NULL`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("Aggressive profiles.create audit rows = %d (err %v), want 1", audits, err)
	}
}

// A used "Organizers' lab" (it has runs) is kept as an ordinary profile; its
// seeded scope rows go anyway. Down restores LB1's seed.
func TestSeededProfilesKeepUsedOrganizersLab(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := db.Open(ctx, dbtest.FreshURL(t), dbtest.Key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, lb1Version); err != nil {
		t.Fatal(err)
	}
	if n := countDockerHostScope(t, ctx, pool); n != 2 {
		t.Fatalf("after LB1: 172.17.0.1 scope entries = %d, want 2", n)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runs (profile_id, status) SELECT id, 'done' FROM profiles WHERE name = 'Organizers'' lab'`); err != nil {
		t.Fatal(err)
	}

	if _, err := provider.UpTo(ctx, lb6Version); err != nil {
		t.Fatal(err)
	}
	got := seededProfiles(t, ctx, pool)
	for _, name := range []string{"Default", "Aggressive", "Organizers' lab"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("after LB6: no %q profile: %v", name, got)
		}
	}
	if _, ok := got["default"]; ok {
		t.Fatalf("after LB6: 'default' not renamed: %v", got)
	}
	if n := countDockerHostScope(t, ctx, pool); n != 0 {
		t.Fatalf("after LB6: 172.17.0.1 scope entries = %d, want 0", n)
	}

	if _, err := provider.DownTo(ctx, lb1Version); err != nil {
		t.Fatal(err)
	}
	got = seededProfiles(t, ctx, pool)
	if _, ok := got["default"]; !ok {
		t.Fatalf("after Down: no 'default': %v", got)
	}
	if _, ok := got["Aggressive"]; ok {
		t.Fatalf("after Down: Aggressive still there: %v", got)
	}
	if n := countDockerHostScope(t, ctx, pool); n != 2 {
		t.Fatalf("after Down: 172.17.0.1 scope entries = %d, want 2", n)
	}
}
