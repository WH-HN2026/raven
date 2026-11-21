package db

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// sensitiveName matches column names that hold data which must be stored
// encrypted (architecture §5 "Encryption"): such columns end in _enc.
var sensitiveName = regexp.MustCompile(`(^|_)(notes?|banner|headers?|cookies?|cert|certificate|content|body|password|token|secret|key)(_|$)`)

// plaintextAllowed are sensitive-looking columns that are deliberately not
// encrypted; docs/architecture.md §5 "Encryption" lists the reasons.
var plaintextAllowed = map[string]string{
	"users.password_hash":   "argon2id hash, not the password",
	"sessions.token_hash":   "SHA-256 of the session token, used as lookup key",
	"api_tokens.token_hash": "SHA-256 of the API token, used as lookup key",
	"targets.note":          "operator label of a target from the import file, shown in lists",
	"scope_entries.note":    "operator label of a scope entry, shown in lists",
}

// column is a column a migration adds, with its type.
type column struct{ table, name, typ, file string }

var (
	createTable = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.*?)\n\);`)
	alterTable  = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(\w+)\s+(.*?);`)
	addColumn   = regexp.MustCompile(`(?i)ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+(\w+)`)
	renameCol   = regexp.MustCompile(`(?i)RENAME\s+COLUMN\s+\w+\s+TO\s+(\w+)`)
	colDef      = regexp.MustCompile(`^\s*(\w+)\s+(\w+)`)
	notColumn   = map[string]bool{"check": true, "unique": true, "primary": true, "foreign": true, "constraint": true, "exclude": true, "like": true}
	lineComment = regexp.MustCompile(`--[^\n]*`)
)

// migrationColumns returns every column added by the Up part of the embedded migrations.
func migrationColumns(t *testing.T) []column {
	t.Helper()
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations: %v", err)
	}
	var cols []column
	for _, f := range files {
		b, err := fs.ReadFile(migrations, f)
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(b), "-- +goose Down")
		up = lineComment.ReplaceAllString(up, "")
		for _, m := range createTable.FindAllStringSubmatch(up, -1) {
			for line := range strings.SplitSeq(m[2], "\n") {
				d := colDef.FindStringSubmatch(line)
				if d == nil || notColumn[strings.ToLower(d[1])] {
					continue
				}
				cols = append(cols, column{m[1], d[1], strings.ToLower(d[2]), f})
			}
		}
		for _, m := range alterTable.FindAllStringSubmatch(up, -1) {
			for _, a := range addColumn.FindAllStringSubmatch(m[2], -1) {
				cols = append(cols, column{m[1], a[1], strings.ToLower(a[2]), f})
			}
			for _, r := range renameCol.FindAllStringSubmatch(m[2], -1) {
				cols = append(cols, column{m[1], r[1], "", f})
			}
		}
	}
	return cols
}

// TestSensitiveColumnsAreEncrypted fails when a migration adds a column whose
// name looks sensitive without the _enc suffix (or an entry in
// plaintextAllowed), or an _enc column that is not bytea.
func TestSensitiveColumnsAreEncrypted(t *testing.T) {
	cols := migrationColumns(t)
	seen := map[string]bool{}
	for _, c := range cols {
		full := c.table + "." + c.name
		seen[full] = true
		name := strings.ToLower(c.name)
		if strings.HasSuffix(name, "_enc") {
			if c.typ != "" && c.typ != "bytea" {
				t.Errorf("%s: %s is %s, _enc columns must be bytea written with raven_enc", c.file, full, c.typ)
			}
			continue
		}
		if sensitiveName.MatchString(name) {
			if _, ok := plaintextAllowed[full]; !ok {
				t.Errorf("%s: %s looks sensitive: name it *_enc (bytea, raven_enc/raven_dec) or add it to plaintextAllowed with a reason and document it in architecture §5", c.file, full)
			}
		}
	}
	// The parser must actually see the known columns, or the check is vacuous.
	for _, want := range []string{
		"hosts.notes_enc", "services.banner_enc", "http_observations.headers_enc",
		"http_observations.cookies_enc", "http_observations.tls_cert_enc", "artifacts.content_enc",
		"run_observations.nuclei_evidence_enc", "users.password_hash", "targets.note", "batches.error",
	} {
		if !seen[want] {
			t.Errorf("migration parser missed column %s", want)
		}
	}
	for k := range plaintextAllowed {
		if !seen[k] {
			t.Errorf("plaintextAllowed has %s, which no migration creates: remove it", k)
		}
	}
}

func TestSensitiveName(t *testing.T) {
	for name, want := range map[string]bool{
		"notes": true, "note": true, "banner": true, "raw_headers": true, "cookie": true,
		"tls_cert": true, "content": true, "response_body": true, "password": true,
		"api_token": true, "client_secret": true, "private_key": true,
		"ip": false, "port": false, "title": false, "notebook": false, "keyword": false,
		"contents_count": false, "hostnames": false, "dojo_asset_id": false,
	} {
		if got := sensitiveName.MatchString(name); got != want {
			t.Errorf("sensitiveName(%q) = %v, want %v", name, got, want)
		}
	}
}
