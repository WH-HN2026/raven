package cve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

// PassResult summarizes one match pass.
type PassResult struct {
	Services int   // candidates looked at
	Matches  int   // rows written
	Removed  int64 // rows deleted (service gone or no longer matching)
}

// RunPass matches every open service against the dataset and replaces the
// cve_matches table's content in one transaction. Only cve_matches is
// written; services and hosts are read-only here.
func RunPass(ctx context.Context, pool *pgxpool.Pool, m *Matcher, now time.Time) (PassResult, error) {
	var res PassResult
	now = now.UTC().Truncate(time.Microsecond) // Postgres precision, for the stale check
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		q := gen.New(tx)
		rows, err := q.ListCVECandidates(ctx)
		if err != nil {
			return fmt.Errorf("list cve candidates: %w", err)
		}
		res.Services = len(rows)
		for _, r := range rows {
			mt := m.Match(Instance{IP: r.Ip, Port: r.Port, Proto: r.Proto, CPE: r.Cpe,
				Product: r.Product, Version: r.Version, Banner: r.Banner})
			if mt == nil {
				continue
			}
			hits, err := json.Marshal(mt.Hits)
			if err != nil {
				return err
			}
			ids := make([]string, len(mt.Hits))
			for i, h := range mt.Hits {
				ids[i] = h.ID
			}
			if err := q.UpsertCVEMatch(ctx, gen.UpsertCVEMatchParams{
				Ip: mt.IP, Port: mt.Port, Proto: mt.Proto, Product: mt.Name, Cpe: mt.CPE, Version: mt.Version,
				CveIds: ids, Hits: hits, MaxCvss: float32(mt.MaxCVSS), Kev: int32(mt.KEV), Distro: mt.Distro,
				Confidence: mt.Confidence, Severity: mt.Severity, Now: now,
			}); err != nil {
				return fmt.Errorf("upsert cve match %s:%d: %w", mt.IP, mt.Port, err)
			}
			res.Matches++
		}
		res.Removed, err = q.DeleteStaleCVEMatches(ctx, now)
		if err != nil {
			return fmt.Errorf("delete stale cve matches: %w", err)
		}
		return nil
	})
	return res, err
}

func fromRow(r gen.CveMatch) (Match, error) {
	m := Match{IP: r.Ip, Port: r.Port, Proto: r.Proto, Name: r.Product, CPE: r.Cpe, Version: r.Version,
		MaxCVSS: float64(r.MaxCvss), KEV: int(r.Kev), Distro: r.Distro, Confidence: r.Confidence,
		Severity: r.Severity, MatchedAt: r.MatchedAt, Hits: []Hit{}}
	if err := json.Unmarshal(r.Hits, &m.Hits); err != nil {
		return m, fmt.Errorf("cve match %s:%d hits: %w", r.Ip, r.Port, err)
	}
	return m, nil
}

// List returns the stored matches, of one IP if ip is valid, highest CVSS first.
func List(ctx context.Context, pool *pgxpool.Pool, ip netip.Addr) ([]Match, error) {
	var arg *netip.Addr
	if ip.IsValid() {
		u := ip.Unmap()
		arg = &u
	}
	rows, err := gen.New(pool).ListCVEMatches(ctx, arg)
	if err != nil {
		return nil, fmt.Errorf("list cve matches: %w", err)
	}
	out := make([]Match, 0, len(rows))
	for _, r := range rows {
		m, err := fromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// PushHost is one IP whose CVE findings must be (re)pushed.
type PushHost struct {
	IP        netip.Addr
	Hostnames []string
	Profile   string  // profile of the last run that saw it up ("" = none)
	Matches   []Match // may be empty: closes the findings pushed before
	Hash      string
}

// Hash identifies a match set: what the Dojo findings are built from.
func Hash(ms []Match) string {
	if len(ms) == 0 {
		return ""
	}
	h := sha256.New()
	for _, m := range ms {
		fmt.Fprintf(h, "%s|%s|%s|%d|%t\n", m.UID(), m.Severity, m.Confidence, m.KEV, m.Distro)
		for _, x := range m.Hits {
			fmt.Fprintf(h, "%s,", x.ID)
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PushCandidates returns the active hosts whose match set changed since the
// last push. Non-responding hosts are never returned, so their findings
// stay as they are (AGENTS.md: never reimport a host that didn't respond).
func PushCandidates(ctx context.Context, pool *pgxpool.Pool) ([]PushHost, error) {
	q := gen.New(pool)
	hosts, err := q.ListCVEPushHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cve push hosts: %w", err)
	}
	all, err := List(ctx, pool, netip.Addr{})
	if err != nil {
		return nil, err
	}
	byIP := map[netip.Addr][]Match{}
	for _, m := range all {
		byIP[m.IP] = append(byIP[m.IP], m)
	}
	var out []PushHost
	for _, h := range hosts {
		ms := byIP[h.Ip]
		hash := Hash(ms)
		if h.Pushed && hash == h.PushedHash {
			continue
		}
		out = append(out, PushHost{IP: h.Ip, Hostnames: h.Hostnames, Profile: h.Profile, Matches: ms, Hash: hash})
	}
	return out, nil
}

// MarkPushed records the match set now in Dojo for ip.
func MarkPushed(ctx context.Context, pool *pgxpool.Pool, ip netip.Addr, hash string, at time.Time) error {
	if err := gen.New(pool).SetCVEPushed(ctx, gen.SetCVEPushedParams{Ip: ip, Hash: hash, PushedAt: at}); err != nil {
		return fmt.Errorf("mark cve pushed %s: %w", ip, err)
	}
	return nil
}
