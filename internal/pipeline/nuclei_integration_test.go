//go:build integration

package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
)

type replayNuclei struct {
	nuclei.Scanner
	result *scanner.Result
	err    error
}

func (f *replayNuclei) Run(_ context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	if !slices.Equal(in.URLs, []string{"http://172.30.0.17:80"}) ||
		!slices.Equal(in.IPs, []netip.Addr{netip.MustParseAddr("172.30.0.17")}) ||
		opt.RateLimit != 25 || !slices.Equal(opt.Tags, []string{"tech"}) {
		return nil, errors.New("unexpected nuclei input or options")
	}
	return f.result, f.err
}

func TestNucleiBatchIngest(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := t.Context()
	q := gen.New(pool)
	var profileID int64
	if err := pool.QueryRow(ctx, `UPDATE profiles SET nuclei_tags = ARRAY['tech'] WHERE name = 'default' RETURNING id`).Scan(&profileID); err != nil {
		t.Fatal(err)
	}
	prof, err := q.GetProfile(ctx, profileID)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("172.30.0.17")
	raw, err := os.ReadFile("../scanner/nuclei/testdata/lab-http.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	all, err := nuclei.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	match, err := nuclei.Parse(all.PerIP(ip))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "stores the match and encrypted evidence"},
		{name: "preserves nmap and httpx after scanner failure", err: errors.New("nuclei exited")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			run, err := q.InsertRun(ctx, gen.InsertRunParams{ProfileID: prof.ID, Status: "running", StartedAt: &now, HostsTotal: 1, Stats: []byte("{}")})
			if err != nil {
				t.Fatal(err)
			}
			ips := []netip.Addr{ip}
			batchID, err := q.InsertBatch(ctx, gen.InsertBatchParams{RunID: run.ID, Seq: 1, Ips: ips})
			if err != nil {
				t.Fatal(err)
			}
			b, err := q.StartBatch(ctx, batchID)
			if err != nil {
				t.Fatal(err)
			}
			s, err := New(pool, Config{Scanner: nmap.New(nmap.Config{}), Nuclei: &replayNuclei{result: match, err: tt.err}})
			if err != nil {
				t.Fatal(err)
			}
			nmapRes := &scanner.Result{Raw: []byte("<nmaprun/>"), Observations: []scanner.Observation{
				{Kind: scanner.ObsHost, IP: ip, Up: true},
				{Kind: scanner.ObsService, IP: ip, Port: 80, Proto: "tcp", Service: "http"},
			}}
			web := &scanner.Result{Raw: []byte("{}"), Observations: []scanner.Observation{
				{Kind: scanner.ObsHTTP, IP: ip, Port: 80, URL: "http://172.30.0.17:80", HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"Apache"}}},
				{Kind: scanner.ObsHTTP, IP: ip, Port: 80, URL: "http://wordpress.raven.lab:80", HTTP: &scanner.HTTPInfo{Status: 200}},
			}}
			detection, err := s.scanNuclei(ctx, b, prof, web)
			if err != nil || (detection == nil) != (tt.err != nil) {
				t.Fatalf("scanNuclei: detection present=%v, error=%v", detection != nil, err)
			}
			if _, err := s.ingestBatch(ctx, b, prof, nil, nmapRes, web, detection, now); err != nil {
				t.Fatal(err)
			}
			if got := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner IN ('nmap', 'httpx')`, run.ID); got != 2 {
				t.Fatalf("baseline artifact count = %d", got)
			}
			if tt.err != nil {
				if got := count(t, pool, `SELECT count(*) FROM artifacts WHERE run_id = $1 AND scanner = 'nuclei'`, run.ID); got != 0 {
					t.Fatal("stored an artifact after a failed nuclei pass")
				}
				return
			}
			var matches, evidence, artifact string
			if err := pool.QueryRow(ctx, `
				SELECT nuclei_matches->0->>'template_id', raven_dec(nuclei_evidence_enc)
				FROM run_observations WHERE run_id = $1 AND ip = $2 AND port = 80`, run.ID, ip).Scan(&matches, &evidence); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT raven_dec(content_enc) FROM artifacts WHERE run_id = $1 AND scanner = 'nuclei'`, run.ID).Scan(&artifact); err != nil {
				t.Fatal(err)
			}
			if matches != "wordpress-detect" || evidence != `[["7.1.5"]]` || artifact != string(match.Raw) {
				t.Fatalf("incorrect match or encrypted evidence: %q %q", matches, evidence)
			}
			if got := count(t, pool, `
				SELECT count(*) FROM http_observations WHERE run_id = $1
				AND url = 'http://172.30.0.17:80' AND technologies @> ARRAY['Apache', 'wordpress']`, run.ID); got != 1 {
				t.Fatal("nuclei technology was not merged into the confirmed HTTP observation")
			}
		})
	}
}
