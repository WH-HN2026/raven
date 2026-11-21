package nuclei

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/WH-HN2026/raven/internal/scanner"
)

func TestBuildArgs(t *testing.T) {
	for _, tt := range []struct {
		name, protocol, tags string
		custom               bool
		requested            []string
		rate                 int
		wantErr              bool
	}{
		{name: "official", protocol: "http", requested: []string{"panel", "rce", "ssl,tech", "tech", "-t", "tech"}, rate: 17, tags: "tech,panel"},
		{name: "TLS", protocol: "ssl", requested: []string{"ssl", "bruteforce"}, rate: 2, tags: "ssl"},
		{name: "custom", protocol: "http", custom: true, requested: []string{"cve"}, rate: 9},
		{name: "invalid rate", protocol: "http", requested: []string{"tech"}, wantErr: true},
		{name: "only disallowed tags", protocol: "http", requested: []string{"cve", "fuzzing"}, rate: 1, wantErr: true},
		{name: "unsafe protocol", protocol: "tcp", requested: []string{"tech"}, rate: 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args, err := BuildArgs(scanner.Options{Tags: tt.requested, RateLimit: tt.rate}, tt.protocol, []string{"safe.yaml"}, tt.custom)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("built args for invalid input: %v", args)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			value := func(flag string) string {
				if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
					return args[i+1]
				}
				return ""
			}
			for _, flag := range []string{"-no-interactsh", "-disable-update-check", "-duc", "-auth=false", "-no-httpx", "-disable-redirects", "-jsonl"} {
				if !slices.Contains(args, flag) {
					t.Errorf("missing %s in %v", flag, args)
				}
			}
			for _, tag := range []string{"intrusive", "dos", "fuzz", "bruteforce", "rce", "sqli", "xss", "lfi", "ssrf"} {
				if !slices.Contains(strings.Split(value("-etags"), ","), tag) {
					t.Errorf("missing excluded tag %s", tag)
				}
			}
			if value("-exclude-type") != "code,headless,javascript" {
				t.Errorf("unexpected excluded protocols: %q", value("-exclude-type"))
			}
			if value("-rl") != strconv.Itoa(tt.rate) || value("-tags") != tt.tags || value("-type") != tt.protocol || value("-t") != "safe.yaml" {
				t.Errorf("unexpected flag values: %v", args)
			}
		})
	}
}

func TestBuildInput(t *testing.T) {
	ip := netip.MustParseAddr("172.30.0.17")
	outside := netip.MustParseAddr("172.30.0.18")
	obs := func(ip netip.Addr, u string, status int) scanner.Observation {
		return scanner.Observation{Kind: scanner.ObsHTTP, IP: ip, Port: 80, URL: u, HTTP: &scanner.HTTPInfo{Status: status}}
	}
	in := BuildInput([]netip.Addr{ip}, []scanner.Observation{
		obs(ip, "http://172.30.0.17:80", 200),
		obs(ip, "http://172.30.0.17/", 200),
		obs(ip, "http://172.30.0.17:80/redirected", 200),
		obs(ip, "http://172.30.0.17:81", 200),
		obs(ip, "http://172.30.0.17:80?query", 200),
		obs(ip, "http://172.30.0.18:80", 200),
		obs(outside, "http://172.30.0.18:80", 200),
		obs(ip, "http://wordpress.raven.lab:80", 200),
		obs(ip, "https://172.30.0.17:80", 0),
	})
	if !slices.Equal(in.IPs, []netip.Addr{ip}) || !slices.Equal(in.URLs, []string{"http://172.30.0.17:80"}) {
		t.Fatalf("unexpected input: %+v", in)
	}
	s := &Scanner{Binary: "must-not-run"}
	if _, err := s.Run(context.Background(), scanner.Input{IPs: []netip.Addr{ip}, URLs: []string{"http://172.30.0.18:80"}}, scanner.Options{RateLimit: 10}); err == nil || !strings.Contains(err.Error(), "batch IP") {
		t.Fatalf("accepted URL outside batch: %v", err)
	}
}

func TestParseLab(t *testing.T) {
	httpRaw, err := os.ReadFile("testdata/lab-http.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	sslRaw, err := os.ReadFile("testdata/lab-ssl.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	raw := append(bytes.Clone(httpRaw), sslRaw...)
	res, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		ip, name, id, cpe, origin, path string
		kind                            scanner.ObservationKind
		port                            uint16
	}{
		{"172.30.0.17", "WordPress Detect", "wordpress-detect", "wordpress:wordpress", "http://172.30.0.17:80", "/wp-admin/install.php", scanner.ObsTech, 80},
		{"172.30.0.21", "Tomcat Exposed - Detect", "apache-tomcat-exposed", "apache:tomcat", "http://172.30.0.21:8080", "/manager/status", scanner.ObsMatch, 8080},
		{"172.30.0.24", "Expired SSL Certificate", "expired-ssl", "", "https://172.30.0.24:443", "", scanner.ObsMatch, 443},
	} {
		t.Run(tt.id, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			perIP := res.PerIP(ip)
			replayed, err := Parse(perIP)
			if err != nil || len(replayed.Observations) != 1 {
				t.Fatalf("per-IP replay got %q, %v", perIP, err)
			}
			o := replayed.Observations[0]
			if o.Kind != tt.kind || o.URL != tt.origin+tt.path || o.Port != tt.port || o.CPE != tt.cpe || o.IP != ip || o.At.IsZero() {
				t.Fatalf("unexpected observation: %+v", o)
			}
			if o.Match == nil || o.Match.SourceURL != tt.origin || o.Match.Name != tt.name || o.Match.TemplateID != tt.id || len(o.Match.Tags) == 0 {
				t.Fatalf("unexpected match: %+v", o.Match)
			}
			if tt.id == "wordpress-detect" && (o.Tech != "wordpress" || o.Version != "7.1.5" || !slices.Equal(o.Match.Extracted, []string{"7.1.5"})) {
				t.Fatalf("unexpected WordPress fingerprint: %+v, %+v", o, o.Match)
			}
			if tt.id == "expired-ssl" && (o.Match.Severity != "low" || !slices.Equal(o.Match.Extracted, []string{"2020-01-01 00:00:00 +0000 UTC"})) {
				t.Fatalf("unexpected TLS evidence: %+v", o.Match)
			}
		})
	}
	if !bytes.Equal(res.Raw, raw) || len(res.Observations) != 3 || len(res.PerIP(netip.MustParseAddr("172.30.0.19"))) != 0 {
		t.Fatal("raw artifact or per-IP filtering was incorrect")
	}
	scoped, err := parse(raw, map[string]netip.Addr{"http://172.30.0.21:8080": netip.MustParseAddr("172.30.0.21")})
	if err != nil || len(scoped.Observations) != 1 {
		t.Fatalf("scope filtering: %+v, %v", scoped, err)
	}
	if _, err := Parse([]byte("not JSON")); err == nil {
		t.Fatal("accepted malformed JSON")
	}
}
