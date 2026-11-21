//go:build integration

package hosts

import (
	"bytes"
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/WH-HN2026/raven/internal/dbtest"
)

// Seed inserts three hosts with services, encrypted banners/headers/cookies/
// certs (raven_enc), HTTP observations and run observations.
func Seed(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO profiles (name) VALUES ('w3-test') ON CONFLICT DO NOTHING`,
		`INSERT INTO runs (profile_id, status) SELECT id, 'done' FROM profiles WHERE name = 'w3-test'`,
		`INSERT INTO runs (profile_id, status) SELECT id, 'done' FROM profiles WHERE name = 'w3-test'`,
		`INSERT INTO hosts (ip, hostnames, state, miss_count, owner, criticality, user_tags, notes_enc) VALUES
			('10.10.0.2', '{wp.lab}', 'active', 0, 'web team', 'high', '{dmz,prod}', raven_enc('secret note')),
			('10.10.0.3', '{}', 'unstable', 1, '', '', '{prod}', NULL),
			('10.20.0.4', '{iot-cam.lab}', 'inactive', 3, '', '', '{}', NULL)`,
		`INSERT INTO services (ip, port, proto, name, product, version, banner_enc, state, overrides) VALUES
			('10.10.0.2', 80, 'tcp', 'http', 'nginx', '1.25.3', raven_enc('nginx banner'), 'open', '{"product":"OpenResty"}'),
			('10.10.0.2', 443, 'tcp', 'https', 'nginx', '1.25.3', NULL, 'open', '{}'),
			('10.10.0.2', 21, 'tcp', 'ftp', 'vsftpd', '3.0.3', NULL, 'gone', '{}'),
			('10.10.0.3', 22, 'tcp', 'ssh', 'OpenSSH', '9.6', raven_enc('SSH-2.0-OpenSSH_9.6'), 'open', '{}'),
			('10.20.0.4', 443, 'tcp', 'https', '', '', NULL, 'gone', '{}')`,
		// older then newer observation of the same URL: only the newer one is returned.
		`INSERT INTO http_observations (service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc,
			redirects, technologies, run_id, observed_at)
		 SELECT s.id, 'http://10.10.0.2/', 200, 'Old', raven_enc('{"Server":"old"}'), NULL, NULL, '[]', '{Apache}',
			(SELECT min(id) FROM runs), now() - interval '1 day'
		 FROM services s WHERE s.ip = '10.10.0.2' AND s.port = 80`,
		`INSERT INTO http_observations (service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc,
			redirects, technologies, run_id, observed_at)
		 SELECT s.id, 'http://10.10.0.2/', 200, 'WordPress', raven_enc('{"Server":"nginx","X-Environment":"staging"}'),
			raven_enc('["wp_session=abc; HttpOnly"]'), NULL, '["http://10.10.0.2/wp/"]', '{WordPress,PHP,Nginx}',
			(SELECT max(id) FROM runs), now()
		 FROM services s WHERE s.ip = '10.10.0.2' AND s.port = 80`,
		`INSERT INTO http_observations (service_id, url, status, title, tls_cert_enc, technologies, observed_at)
		 SELECT s.id, 'https://10.20.0.4/', NULL, '', raven_enc('CN=cam'), '{Hikvision}', now()
		 FROM services s WHERE s.ip = '10.20.0.4' AND s.port = 443`,
		`INSERT INTO run_observations (run_id, ip, port, up, observed_at) VALUES
			((SELECT min(id) FROM runs), '10.10.0.3', NULL, true, now() - interval '1 day'),
			((SELECT max(id) FROM runs), '10.10.0.3', NULL, false, now()),
			((SELECT max(id) FROM runs), '10.10.0.3', 22, false, now())`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v\n%s", err, s)
		}
	}
}

func TestListFiltersAndDetail(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	Seed(t, pool)

	ips := func(f Filter) ([]string, int64) {
		t.Helper()
		if f.Limit == 0 {
			f.Limit = 50
		}
		items, total, err := List(ctx, pool, f)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, h := range items {
			out = append(out, h.IP.String())
		}
		return out, total
	}
	port := func(n int) *int { return &n }
	all := []string{"10.10.0.2", "10.10.0.3", "10.20.0.4"}
	for _, tc := range []struct {
		name string
		f    Filter
		want []string
	}{
		{"all", Filter{}, all},
		{"state", Filter{State: "unstable"}, []string{"10.10.0.3"}},
		{"port open", Filter{Port: port(443)}, []string{"10.10.0.2"}}, // 10.20.0.4's 443 is gone
		{"port gone only", Filter{Port: port(21)}, []string{}},
		{"tech case-insensitive", Filter{Tech: "wordpress"}, []string{"10.10.0.2"}},
		{"tech other host", Filter{Tech: "Hikvision"}, []string{"10.20.0.4"}},
		{"tag", Filter{Tag: "prod"}, []string{"10.10.0.2", "10.10.0.3"}},
		{"q cidr", Filter{Q: "10.10.0.0/16"}, []string{"10.10.0.2", "10.10.0.3"}},
		{"q ip", Filter{Q: "10.20.0.4"}, []string{"10.20.0.4"}},
		{"q ip text prefix", Filter{Q: "10.2"}, []string{"10.20.0.4"}},
		{"q hostname", Filter{Q: "CAM"}, []string{"10.20.0.4"}},
		{"combined", Filter{Tag: "prod", Port: port(22)}, []string{"10.10.0.3"}},
		{"injection attempt is a plain value", Filter{Q: "'; DROP TABLE hosts; --"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, total := ips(tc.f)
			if !reflect.DeepEqual(got, tc.want) || total != int64(len(tc.want)) {
				t.Fatalf("got %v (total %d), want %v", got, total, tc.want)
			}
		})
	}

	// pagination: total ignores limit/offset
	got, total := ips(Filter{Limit: 1, Offset: 1})
	if !reflect.DeepEqual(got, []string{"10.10.0.3"}) || total != 3 {
		t.Fatalf("page = %v total %d", got, total)
	}

	// list item summary
	items, _, err := List(ctx, pool, Filter{Q: "10.10.0.2", Limit: 10})
	if err != nil || len(items) != 1 {
		t.Fatal(err, items)
	}
	h := items[0]
	if h.OpenServices != 2 || !reflect.DeepEqual(h.OpenPorts, []int32{80, 443}) ||
		!reflect.DeepEqual(h.Technologies, []string{"Apache", "Nginx", "PHP", "WordPress"}) ||
		h.Owner != "web team" || h.Criticality != "high" || !reflect.DeepEqual(h.UserTags, []string{"dmz", "prod"}) ||
		string(h.Overrides) != "{}" {
		t.Fatalf("item = %+v", h)
	}

	// detail with decryption and overrides
	d, err := Get(ctx, pool, netip.MustParseAddr("10.10.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Notes != "secret note" || d.OpenServices != 2 || !reflect.DeepEqual(d.OpenPorts, []int32{80, 443}) {
		t.Fatalf("detail host = %+v notes %q", d.Host, d.Notes)
	}
	if len(d.Services) != 3 || d.Services[2].Port != 21 || d.Services[2].State != "gone" {
		t.Fatalf("services = %+v", d.Services)
	}
	s80 := d.Services[0]
	if s80.Port != 80 || s80.Banner != "nginx banner" || s80.Product != "OpenResty" || s80.Scan.Product != "nginx" ||
		!reflect.DeepEqual(s80.Overridden, []string{"product"}) || s80.Version != "1.25.3" {
		t.Fatalf("service 80 = %+v", s80)
	}
	if s443 := d.Services[1]; s443.Banner != "" || len(s443.Overridden) != 0 || s443.Product != "nginx" {
		t.Fatalf("service 443 = %+v", s443)
	}
	if len(d.HTTP) != 1 {
		t.Fatalf("http = %+v", d.HTTP)
	}
	o := d.HTTP[0]
	if o.Title != "WordPress" || o.Status == nil || *o.Status != 200 || o.ServiceID != s80.ID ||
		!reflect.DeepEqual(o.Headers, map[string]string{"Server": "nginx", "X-Environment": "staging"}) ||
		!reflect.DeepEqual(o.Cookies, []string{"wp_session=abc; HttpOnly"}) ||
		!reflect.DeepEqual(o.Redirects, []string{"http://10.10.0.2/wp/"}) || o.TLSCert != "" {
		t.Fatalf("http obs = %+v", o)
	}
	if !reflect.DeepEqual(d.Technologies, []string{"Nginx", "PHP", "WordPress"}) {
		t.Fatalf("technologies = %v", d.Technologies)
	}

	// timeline: host-level rows only, newest first
	d3, err := Get(ctx, pool, netip.MustParseAddr("10.10.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d3.Timeline) != 2 || d3.Timeline[0].Up || !d3.Timeline[1].Up || len(d3.HTTP) != 0 || d3.Notes != "" {
		t.Fatalf("10.10.0.3 = %+v", d3)
	}
	d4, err := Get(ctx, pool, netip.MustParseAddr("10.20.0.4"))
	if err != nil || len(d4.HTTP) != 1 || d4.HTTP[0].TLSCert != "CN=cam" || d4.HTTP[0].Status != nil ||
		len(d4.HTTP[0].Headers) != 0 || len(d4.HTTP[0].Cookies) != 0 {
		t.Fatalf("10.20.0.4 = %+v %v", d4, err)
	}

	if _, err := Get(ctx, pool, netip.MustParseAddr("10.99.0.1")); err != ErrNotFound {
		t.Fatalf("missing host err = %v", err)
	}

	// the stored values really are ciphertext
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT banner_enc FROM services WHERE ip = '10.10.0.2' AND port = 80`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("nginx banner")) {
		t.Fatal("banner stored in plaintext")
	}
}
