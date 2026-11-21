//go:build integration

package dojo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/dbtest"
)

// TestIntegrationWriteThrough: against the shared Dojo and a throwaway DB.
// It imports an nmap scan into its own organization "raven-it-d6-<random>",
// syncs the mirror, then edits a finding through EditFinding/AddNote and
// checks Dojo, the mirror and audit_log. It deletes only what it created.
func TestIntegrationWriteThrough(t *testing.T) {
	base := os.Getenv("RAVEN_DOJO_URL")
	if base == "" {
		t.Skip("RAVEN_DOJO_URL not set")
	}
	pool := dbtest.Fresh(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	token := os.Getenv("RAVEN_DOJO_TOKEN")
	if token == "" {
		var err error
		if token, err = ObtainToken(ctx, base, os.Getenv("DD_ADMIN_USER"), os.Getenv("DD_ADMIN_PASSWORD")); err != nil {
			t.Fatal(err)
		}
	}
	c := NewHTTPClient(base, token)
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	slug := "raven-it-d6-" + hex.EncodeToString(rnd)
	ip := fmt.Sprintf("198.18.%d.%d", rnd[0], rnd[1]) // RFC 2544 benchmark range, never scanned
	t.Logf("slug %s ip %s", slug, ip)

	org, err := c.GetOrCreateOrganization(ctx, slug)
	must(t, err)
	t.Cleanup(func() { deleteObj(t, c, "organizations", org.ID) })
	asset, err := c.GetOrCreateAsset(ctx, AssetSpec{Name: ip, Description: "D6 integration test", OrganizationID: org.ID, Tags: []string{"raven", slug}})
	must(t, err)
	t.Cleanup(func() { deleteObj(t, c, "assets", asset.ID) })
	eng, err := c.GetOrCreateEngagement(ctx, EngagementSpec{AssetID: asset.ID, Name: "RAVEN: it"})
	must(t, err)
	test, err := c.GetOrCreateTest(ctx, TestSpec{EngagementID: eng.ID, ScanType: "Nmap Scan", Title: "nmap"})
	must(t, err)
	_, err = c.ReimportScan(ctx, ImportRequest{
		ScanType: "Nmap Scan", TestID: test.ID, FileName: "nmap.xml", File: open(t, "testdata/nmap_3ports.xml"),
		CloseOldFindings: true, Tags: []string{"raven", slug}, TagFindings: true, ScanDate: time.Now(),
	})
	must(t, err)
	_, err = (&Syncer{Client: c, Pool: pool, OrganizationID: org.ID}).SyncOnce(ctx)
	must(t, err)

	var id int64
	must(t, pool.QueryRow(ctx, `SELECT id FROM dojo_findings WHERE title ILIKE 'Open port: 22/tcp'`).Scan(&id))
	var actor int64 // audit_log.user_id references users
	must(t, pool.QueryRow(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('d6', 'x', 'operator') RETURNING id`).Scan(&actor))

	dojoFinding := func() Finding {
		t.Helper()
		var f Finding
		must(t, c.do(ctx, http.MethodGet, "/api/v2/findings/"+itoa(id)+"/", nil, nil, &f))
		return f
	}
	type row struct {
		severity                     string
		active, riskAccepted, falseP bool
		verified                     bool
	}
	mirror := func() row {
		t.Helper()
		var r row
		must(t, pool.QueryRow(ctx, `SELECT severity, active, risk_accepted, false_p, verified FROM dojo_findings WHERE id = $1`, id).
			Scan(&r.severity, &r.active, &r.riskAccepted, &r.falseP, &r.verified))
		return r
	}

	// Not ready: nothing is sent.
	if _, err := EditFinding(ctx, pool, nil, &actor, id, FindingPatch{Severity: wp("High")}, ""); !errors.Is(err, ErrNotReady) {
		t.Fatalf("nil client: %v", err)
	}
	// Unknown finding.
	if _, err := EditFinding(ctx, pool, c, &actor, 1<<40, FindingPatch{Severity: wp("High")}, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown finding: %v", err)
	}
	// A contradiction is rejected before Dojo.
	if _, err := EditFinding(ctx, pool, c, &actor, id, FindingPatch{RiskAccepted: wp(true), Active: wp(true)}, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("active+risk_accepted: %v", err)
	}

	// Severity + risk acceptance: Dojo and the mirror both change.
	got, err := EditFinding(ctx, pool, c, &actor, id, FindingPatch{Severity: wp("high"), RiskAccepted: wp(true)}, "http://dojo.example")
	must(t, err)
	if got.Severity != "High" || !got.RiskAccepted || got.Active || got.DojoURL != "http://dojo.example/finding/"+itoa(id) {
		t.Fatalf("EditFinding result = %+v", got)
	}
	if f := dojoFinding(); f.Severity != "High" || !f.RiskAccepted || f.Active {
		t.Fatalf("dojo after risk accept: severity %s risk_accepted %v active %v", f.Severity, f.RiskAccepted, f.Active)
	}
	if m := mirror(); m.severity != "High" || !m.riskAccepted || m.active {
		t.Fatalf("mirror after risk accept: %+v", m)
	}

	// Reopen: active=true implies risk_accepted=false.
	_, err = EditFinding(ctx, pool, c, &actor, id, FindingPatch{Active: wp(true)}, "")
	must(t, err)
	if f := dojoFinding(); !f.Active || f.RiskAccepted {
		t.Fatalf("dojo after reopen: active %v risk_accepted %v", f.Active, f.RiskAccepted)
	}
	if m := mirror(); !m.active || m.riskAccepted {
		t.Fatalf("mirror after reopen: %+v", m)
	}

	// False positive: clears active and verified.
	_, err = EditFinding(ctx, pool, c, &actor, id, FindingPatch{Verified: wp(true)}, "")
	must(t, err)
	_, err = EditFinding(ctx, pool, c, &actor, id, FindingPatch{FalseP: wp(true)}, "")
	must(t, err)
	if f := dojoFinding(); !f.FalseP || f.Verified || f.Active {
		t.Fatalf("dojo after false positive: %+v", f)
	}
	if m := mirror(); !m.falseP || m.verified || m.active {
		t.Fatalf("mirror after false positive: %+v", m)
	}

	// Note.
	note := "D6 note " + slug
	must(t, AddNote(ctx, pool, c, &actor, id, note))
	var notes struct {
		Notes []struct {
			Entry string `json:"entry"`
		} `json:"notes"`
	}
	must(t, c.do(ctx, http.MethodGet, "/api/v2/findings/"+itoa(id)+"/notes/", nil, nil, &notes))
	found := false
	for _, n := range notes.Notes {
		found = found || n.Entry == note
	}
	if !found {
		t.Fatalf("note not in Dojo: %+v", notes)
	}
	if err := AddNote(ctx, pool, c, &actor, id, "  "); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty note: %v", err)
	}

	// audit_log: one row per successful edit, with before/after, note text never logged.
	var n int
	var diff string
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'finding.update' AND object_id = $1 AND user_id = $2`, itoa(id), actor).Scan(&n))
	if n != 4 {
		t.Fatalf("finding.update audit rows = %d, want 4", n)
	}
	must(t, pool.QueryRow(ctx, `SELECT diff::text FROM audit_log WHERE action = 'finding.update' ORDER BY id LIMIT 1`).Scan(&diff))
	if !strings.Contains(diff, `"before"`) || !strings.Contains(diff, `"severity": "High"`) {
		t.Fatalf("first audit diff = %s", diff)
	}
	must(t, pool.QueryRow(ctx, `SELECT diff::text FROM audit_log WHERE action = 'finding.note'`).Scan(&diff))
	if strings.Contains(diff, slug) {
		t.Fatalf("note text in audit: %s", diff)
	}
}
