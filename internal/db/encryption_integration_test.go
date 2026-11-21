//go:build integration

package db_test

import (
	"bytes"
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/audit"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/db/gen"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/dbtest"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/pipeline"
)

// TestEncryptedColumnsAtRest writes a distinct marker into every *_enc column
// (through the real ingest path where one exists), then checks the raw bytes
// in the DB don't contain it, asi_dec returns it, and a connection without
// asi.enc_key can neither decrypt nor encrypt. Architecture §5 "Encryption".
func TestEncryptedColumnsAtRest(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	q := gen.New(pool)

	ip := netip.MustParseAddr("10.66.0.7")
	markers := map[string]string{
		"hosts.notes_enc":                "MARKER-NOTES-owner-is-alice",
		"services.banner_enc":            "MARKER-BANNER-SSH-2.0-OpenSSH_9.6",
		"http_observations.headers_enc":  "MARKER-HEADERS-X-Internal-Host: db01",
		"http_observations.cookies_enc":  "MARKER-COOKIES-session=abc123",
		"http_observations.tls_cert_enc": "MARKER-TLSCERT-CN=intranet.example",
		"artifacts.content_enc":          "<nmaprun>MARKER-ARTIFACT-raw-xml</nmaprun>",
	}

	// Every _enc column in the schema must be covered here.
	rows, err := pool.Query(ctx, `SELECT table_name || '.' || column_name, data_type FROM information_schema.columns
		WHERE table_schema = 'public' AND column_name LIKE '%\_enc' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var c [2]string
		return c, r.Scan(&c[0], &c[1])
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != len(markers) {
		t.Errorf("schema has %d _enc columns %v, test covers %d: add the new ones to this test", len(cols), cols, len(markers))
	}
	for _, c := range cols {
		if _, ok := markers[c[0]]; !ok {
			t.Errorf("_enc column %s is not covered by this test", c[0])
		}
		if c[1] != "bytea" {
			t.Errorf("%s is %s, want bytea", c[0], c[1])
		}
	}

	// A run + batch for the ingest.
	var runID, batchID int64
	if err := pool.QueryRow(ctx, `INSERT INTO runs (profile_id) SELECT id FROM profiles WHERE name = 'default' RETURNING id`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO batches (run_id, seq, ips) VALUES ($1, 0, ARRAY[$2::inet]) RETURNING id`, runID, ip).Scan(&batchID); err != nil {
		t.Fatal(err)
	}

	// Banner + artifact: the real ingest path (S3).
	ports, err := pipeline.ParsePorts("22")
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Ingest(ctx, q, pipeline.IngestInput{
		RunID: runID, BatchID: batchID, Scanner: "nmap", Raw: []byte(markers["artifacts.content_enc"]),
		Plan: pipeline.Plan{
			Up:       []netip.Addr{ip},
			Hosts:    []pipeline.HostRow{{IP: ip}},
			Services: []pipeline.ServiceRow{{IP: ip, Port: 22, Proto: "tcp", Name: "ssh", Banner: markers["services.banner_enc"]}},
		},
		Ports: ports, Seen: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Host notes: no write path on main yet (D6); same asi_enc call the edit query uses.
	if _, err := pool.Exec(ctx, `UPDATE hosts SET notes_enc = asi_enc($2) WHERE ip = $1`, ip, markers["hosts.notes_enc"]); err != nil {
		t.Fatal(err)
	}
	// HTTP observation: the query S7's ingest uses (pipeline.ingestHTTP is unexported).
	if n, err := q.InsertHTTPObservation(ctx, gen.InsertHTTPObservationParams{
		Ip: ip, Port: 22, Url: "https://10.66.0.7/", Status: pgtype.Int4{Int32: 200, Valid: true},
		Headers: markers["http_observations.headers_enc"], Cookies: markers["http_observations.cookies_enc"],
		TlsCert: markers["http_observations.tls_cert_enc"], Redirects: []byte("[]"),
		Technologies: []string{}, RunID: &runID, ObservedAt: time.Now(),
	}); err != nil || n != 1 {
		t.Fatalf("insert http observation: n=%d err=%v", n, err)
	}

	// The audit_log never carries the plaintext either.
	if err := audit.Log(ctx, q, nil, "hosts.update", "host", ip.String(),
		map[string]any{"notes": map[string]string{"from": "", "to": markers["hosts.notes_enc"]}}); err != nil {
		t.Fatal(err)
	}
	var diff string
	if err := pool.QueryRow(ctx, `SELECT diff::text FROM audit_log WHERE action = 'hosts.update'`).Scan(&diff); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(diff, "MARKER") {
		t.Errorf("audit_log.diff contains plaintext: %s", diff)
	}

	where := map[string]string{
		"hosts":             "ip = '10.66.0.7'",
		"services":          "ip = '10.66.0.7'",
		"http_observations": "run_id = " + strconv.FormatInt(runID, 10),
		"artifacts":         "run_id = " + strconv.FormatInt(runID, 10),
	}
	noKey, err := pgx.Connect(ctx, pool.Config().ConnString()) // plain connection: asi.enc_key not set
	if err != nil {
		t.Fatal(err)
	}
	defer noKey.Close(context.Background())

	for col, marker := range markers {
		table, column, _ := strings.Cut(col, ".")
		sel := `SELECT ` + column + `, asi_dec(` + column + `) FROM ` + table + ` WHERE ` + where[table]
		var raw []byte
		var plain string
		if err := pool.QueryRow(ctx, sel).Scan(&raw, &plain); err != nil {
			t.Errorf("%s: %v", col, err)
			continue
		}
		if len(raw) == 0 || bytes.Contains(raw, []byte(marker)) || bytes.Contains(raw, []byte("MARKER")) {
			t.Errorf("%s: raw bytes contain the plaintext (%d bytes)", col, len(raw))
		}
		if plain != marker {
			t.Errorf("%s: asi_dec = %q, want %q", col, plain, marker)
		}
		// Without the key the ciphertext is unreadable.
		if err := noKey.QueryRow(ctx, `SELECT asi_dec(`+column+`) FROM `+table+` WHERE `+where[table]).Scan(&plain); err == nil {
			t.Errorf("%s: decrypted without asi.enc_key: %q", col, plain)
		}
	}

	// Without the key nothing can be written encrypted either.
	var ct []byte
	if err := noKey.QueryRow(ctx, `SELECT asi_enc('x')`).Scan(&ct); err == nil {
		t.Error("asi_enc worked without asi.enc_key")
	}
	// The pool's connections really carry the key (set in AfterConnect), and it is the configured one.
	var key string
	if err := pool.QueryRow(ctx, `SELECT current_setting('asi.enc_key')`).Scan(&key); err != nil || key != dbtest.Key {
		t.Errorf("asi.enc_key on pool = %q, %v", key, err)
	}
}
