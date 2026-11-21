//go:build integration

package db_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/db"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
)

func TestMigrateAndEncryptionRoundTrip(t *testing.T) {
	url := dbtest.FreshURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	key := "integration-test-key-0123456789abcdef"
	pool, err := db.Open(ctx, url, key)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// Idempotent: a second run applies nothing and doesn't fail.
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	// All core tables (architecture §5) and River's tables exist.
	for _, table := range []string{
		"users", "sessions", "api_tokens", "scope_entries", "targets", "profiles", "schedules",
		"runs", "batches", "hosts", "services", "http_observations", "run_observations",
		"signatures", "artifacts", "dojo_assets", "dojo_findings", "audit_log", "river_job",
	} {
		var ok bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&ok); err != nil || !ok {
			t.Errorf("table %s missing (err=%v)", table, err)
		}
	}

	q := gen.New(pool)
	const secret = "Set-Cookie: session=TOPSECRET-plaintext-marker"
	ct, err := q.Encrypt(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 || bytes.Contains(ct, []byte("TOPSECRET")) {
		t.Fatalf("ciphertext contains plaintext: %q", ct)
	}
	pt, err := q.Decrypt(ctx, ct)
	if err != nil || pt != secret {
		t.Fatalf("decrypt = %q, %v", pt, err)
	}

	// Stored in a real _enc column: the bytes on disk are not plaintext.
	if _, err := pool.Exec(ctx,
		`INSERT INTO hosts (ip, notes_enc) VALUES ('10.0.0.1', asi_enc($1))`, secret); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	var dec string
	if err := pool.QueryRow(ctx, `SELECT notes_enc, asi_dec(notes_enc) FROM hosts WHERE ip = '10.0.0.1'`).Scan(&raw, &dec); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("TOPSECRET")) || dec != secret {
		t.Fatalf("notes_enc raw=%q dec=%q", raw, dec)
	}

	// A connection with a different key can't read it.
	other, err := db.Open(ctx, url, "a-completely-different-key-9876543210")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.QueryRow(ctx, `SELECT asi_dec(notes_enc) FROM hosts WHERE ip = '10.0.0.1'`).Scan(&dec); err == nil {
		t.Fatal("decrypt with the wrong key succeeded")
	}
}
