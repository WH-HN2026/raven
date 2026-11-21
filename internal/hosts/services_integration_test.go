//go:build integration

package hosts

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/WH-HN2026/raven/internal/dbtest"
)

func TestListServicesAndTechnologies(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	Seed(t, pool)

	// Add a CVE match for OpenSSH on 10.10.0.3:22 and nginx on 10.10.0.2:443.
	for _, stmt := range []string{
		`INSERT INTO cve_matches (ip, port, proto, product, cpe, version, cve_ids, hits, max_cvss, kev, distro, confidence, severity, matched_at, updated_at) VALUES
			('10.10.0.3', 22, 'tcp', 'OpenSSH', 'openbsd:openssh', '9.6', '{CVE-2024-0001,CVE-2024-0002}', '[{"id":"CVE-2024-0001","cvss":9.8,"kev":true,"epss":0.9},{"id":"CVE-2024-0002","cvss":7.5,"kev":false,"epss":0.2}]', 9.8, 1, false, 'high', 'Critical', now(), now()),
			('10.10.0.2', 443, 'tcp', 'nginx', 'f5:nginx', '1.25.3', '{CVE-2024-0003}', '[{"id":"CVE-2024-0003","cvss":6.5,"kev":false,"epss":0.1}]', 6.5, 0, false, 'high', 'Medium', now(), now())`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}

	port := func(n int) *int { return &n }
	pfx := func(s string) *netip.Prefix { p := netip.MustParsePrefix(s); return &p }

	for _, tc := range []struct {
		name string
		f    ServiceFilter
		want []string // "ip:port"
	}{
		{"all", ServiceFilter{Limit: 50}, []string{"10.10.0.2:21", "10.10.0.2:80", "10.10.0.2:443", "10.10.0.3:22", "10.20.0.4:443"}},
		{"state open", ServiceFilter{State: "open", Limit: 50}, []string{"10.10.0.2:80", "10.10.0.2:443", "10.10.0.3:22"}},
		{"state gone", ServiceFilter{State: "gone", Limit: 50}, []string{"10.10.0.2:21", "10.20.0.4:443"}},
		{"port 443", ServiceFilter{Port: port(443), Limit: 50}, []string{"10.10.0.2:443", "10.20.0.4:443"}},
		{"proto udp none", ServiceFilter{Proto: "udp", Limit: 50}, []string{}},
		{"product override OpenResty", ServiceFilter{Product: "openresty", Limit: 50}, []string{"10.10.0.2:80"}},
		{"product nginx excludes overridden 80", ServiceFilter{Product: "nginx", Limit: 50}, []string{"10.10.0.2:443"}},
		{"technology WordPress", ServiceFilter{Technology: "wordpress", Limit: 50}, []string{"10.10.0.2:80"}},
		{"technology OpenSSH matches product", ServiceFilter{Technology: "OpenSSH", Limit: 50}, []string{"10.10.0.3:22"}},
		{"version 1.25", ServiceFilter{Version: "1.25", Limit: 50}, []string{"10.10.0.2:80", "10.10.0.2:443"}},
		{"ip cidr", ServiceFilter{IP: pfx("10.20.0.0/16"), Limit: 50}, []string{"10.20.0.4:443"}},
		{"q hostname", ServiceFilter{Q: "wp.lab", Limit: 50}, []string{"10.10.0.2:21", "10.10.0.2:80", "10.10.0.2:443"}},
		{"q tech", ServiceFilter{Q: "hikvision", Limit: 50}, []string{"10.20.0.4:443"}},
		{"sort port desc", ServiceFilter{State: "open", Sort: "port", Order: "desc", Limit: 50}, []string{"10.10.0.2:443", "10.10.0.2:80", "10.10.0.3:22"}},
		{"sort product asc", ServiceFilter{State: "open", Sort: "product", Order: "asc", Limit: 50}, []string{"10.10.0.2:443", "10.10.0.2:80", "10.10.0.3:22"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items, total, err := ListServices(ctx, pool, tc.f)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, len(items))
			for i, it := range items {
				got[i] = it.IP.String() + ":" + itoa32(it.Port)
			}
			if !reflect.DeepEqual(got, tc.want) || total != int64(len(tc.want)) {
				t.Fatalf("got %v (total %d), want %v", got, total, tc.want)
			}
		})
	}

	// Verify enriched fields on service items (overrides, technologies, CVE counts).
	items, _, err := ListServices(ctx, pool, ServiceFilter{State: "open", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]ServiceItem{}
	for _, it := range items {
		byKey[it.IP.String()+":"+itoa32(it.Port)] = it
	}
	if s := byKey["10.10.0.2:80"]; s.Product != "OpenResty" || !reflect.DeepEqual(s.Technologies, []string{"Nginx", "PHP", "WordPress"}) || s.CVECount != 0 {
		t.Fatalf("10.10.0.2:80 = %+v", s)
	}
	if s := byKey["10.10.0.3:22"]; s.CVECount != 2 || s.CVESeverity != "Critical" {
		t.Fatalf("10.10.0.3:22 = %+v", s)
	}

	// Technologies aggregation (open services only by default).
	techs, total, err := ListTechnologies(ctx, pool, TechnologyFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total < 4 {
		t.Fatalf("expected >=4 technologies, got %d: %+v", total, techs)
	}
	techMap := map[string]TechnologySummary{}
	for _, ts := range techs {
		techMap[ts.Technology+"|"+ts.Version] = ts
	}
	if wp, ok := techMap["WordPress|"]; !ok || wp.HostCount != 1 || wp.ServiceCount != 1 || wp.CVECount != 0 {
		t.Fatalf("WordPress summary = %+v (all=%+v)", wp, techs)
	}
	if ssh, ok := techMap["OpenSSH|9.6"]; !ok || ssh.HostCount != 1 || ssh.ServiceCount != 1 || ssh.CVEMatchCount != 1 || ssh.CVECount != 2 || ssh.MaxSeverity != "Critical" {
		t.Fatalf("OpenSSH summary = %+v (all=%+v)", ssh, techs)
	}
	// nginx 1.25.3 appears on 10.10.0.2:80 (httpx Nginx + override OpenResty) and 10.10.0.2:443 (product nginx 1.25.3 with 1 CVE).
	// Search and sort by cves desc puts OpenSSH first.
	byCVE, _, err := ListTechnologies(ctx, pool, TechnologyFilter{Sort: "cves", Order: "desc", Limit: 5})
	if err != nil || len(byCVE) == 0 || byCVE[0].Technology != "OpenSSH" {
		t.Fatalf("sort by cves = %+v err=%v", byCVE, err)
	}
	filteredTechs, filteredTotal, err := ListTechnologies(ctx, pool, TechnologyFilter{Q: "word", Limit: 50})
	if err != nil || filteredTotal != 1 || filteredTechs[0].Technology != "WordPress" {
		t.Fatalf("q=word = %+v total=%d err=%v", filteredTechs, filteredTotal, err)
	}

	// Q3: one port can carry several CVE-matched products (httpx WordPress + PHP on :80).
	// The service stays one row with the union of CVEs; each technology gets only its own.
	if _, err := pool.Exec(ctx, `INSERT INTO cve_matches (ip, port, proto, product, cpe, version, cve_ids, hits, max_cvss, kev, distro, confidence, severity, matched_at, updated_at) VALUES
		('10.10.0.2', 80, 'tcp', 'WordPress', 'wordpress:wordpress', '6.4.1', '{CVE-2024-1001,CVE-2024-1002}', '[]', 8.8, 0, false, 'high', 'High', now(), now()),
		('10.10.0.2', 80, 'tcp', 'PHP', 'php:php', '8.1.2', '{CVE-2024-2001}', '[]', 9.8, 1, false, 'high', 'Critical', now(), now())`); err != nil {
		t.Fatal(err)
	}
	items, total, err = ListServices(ctx, pool, ServiceFilter{Limit: 50})
	if err != nil || total != 5 || len(items) != 5 {
		t.Fatalf("multi-match services = %d items, total %d, err %v", len(items), total, err)
	}
	for _, it := range items {
		if it.IP.String() == "10.10.0.2" && it.Port == 80 && (it.CVECount != 3 || it.CVESeverity != "Critical") {
			t.Fatalf("10.10.0.2:80 multi-match = %+v", it)
		}
	}
	techs, _, err = ListTechnologies(ctx, pool, TechnologyFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	techMap = map[string]TechnologySummary{}
	for _, ts := range techs {
		techMap[ts.Technology+"|"+ts.Version] = ts
	}
	for key, want := range map[string]int{"WordPress|": 2, "PHP|": 1, "OpenResty|1.25.3": 0, "Nginx|": 0} {
		if ts, ok := techMap[key]; !ok || ts.CVECount != want || ts.ServiceCount != 1 {
			t.Fatalf("%s = %+v ok=%v, want %d CVEs (all=%+v)", key, ts, ok, want, techs)
		}
	}
}

func TestHostLastEditedBy(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	Seed(t, pool)

	var aliceID, bobID int64
	if err := pool.QueryRow(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('alice', 'x', 'operator') RETURNING id`).Scan(&aliceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users (username, password_hash, role) VALUES ('bob', 'x', 'editor') RETURNING id`).Scan(&bobID); err != nil {
		t.Fatal(err)
	}

	// Initially never edited.
	d, err := Get(ctx, pool, netip.MustParseAddr("10.10.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if d.EditedBy != nil || d.EditedAt != nil {
		t.Fatalf("expected nil edited_by/edited_at before edit, got %v %v", d.EditedBy, d.EditedAt)
	}

	// Alice edits user-owned fields.
	owner := "secops"
	res, err := Edit(ctx, pool, nil, &aliceID, netip.MustParseAddr("10.10.0.3"), Patch{Owner: &owner})
	if err != nil {
		t.Fatal(err)
	}
	if res.EditedBy == nil || *res.EditedBy != "alice" || res.EditedAt == nil {
		t.Fatalf("after alice edit: edited_by=%v edited_at=%v", res.EditedBy, res.EditedAt)
	}

	// Also visible in List.
	list, _, err := List(ctx, pool, Filter{Q: "10.10.0.3", Limit: 10})
	if err != nil || len(list) != 1 || list[0].EditedBy == nil || *list[0].EditedBy != "alice" || list[0].EditedAt == nil {
		t.Fatalf("list after edit: %+v err=%v", list, err)
	}

	// Bob overrides a service on 10.10.0.3 -> updates last edited by to bob.
	var svcID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM services WHERE ip = '10.10.0.3' AND port = 22`).Scan(&svcID); err != nil {
		t.Fatal(err)
	}
	if _, err := EditServiceOverrides(ctx, pool, &bobID, svcID, map[string]json.RawMessage{"product": json.RawMessage(`"Dropbear"`)}); err != nil {
		t.Fatal(err)
	}
	d, err = Get(ctx, pool, netip.MustParseAddr("10.10.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if d.EditedBy == nil || *d.EditedBy != "bob" || d.EditedAt == nil {
		t.Fatalf("after bob service override: edited_by=%v edited_at=%v", d.EditedBy, d.EditedAt)
	}
}

func itoa32(n int32) string {
	return string(json.Number(string(rune(0)))[:0]) + formatInt32(n)
}

func formatInt32(n int32) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
