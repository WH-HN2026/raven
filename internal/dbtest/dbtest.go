//go:build integration

// Package dbtest gives integration tests a fresh, migrated database on the
// server of ASI_DATABASE_URL (scripts/wt-env.sh). Only built with -tags integration.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db"
)

const Key = "integration-test-key-0123456789abcdef"

// Fresh creates and migrates a throwaway database; it is dropped after the test.
func Fresh(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), FreshURL(t), Key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close) // runs before FreshURL's DROP DATABASE (cleanups are LIFO)
	if err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

// FreshURL creates an empty throwaway database and returns its URL.
func FreshURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("ASI_DATABASE_URL")
	if base == "" {
		t.Skip("ASI_DATABASE_URL not set (run scripts/wt-env.sh)")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "asi_it_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}
