package httpx

import (
	"bufio"
	"bytes"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

func TestBuildArgs(t *testing.T) {
	for _, tt := range []struct {
		name string
		ips  []netip.Addr
		rate int
		want []string
	}{
		{
			name: "only fixed flags and validated values",
			ips:  []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
			rate: 17,
			want: []string{
				"-silent", "-json", "-title", "-sc", "-irh", "-tls-grab", "-favicon", "-td",
				"-fhr", "-include-chain", "-nfs", "-disable-update-check", "-auth=false", "-cdn=false",
				"-rl", "17", "-allow", "192.0.2.1,192.0.2.2",
			},
		},
		{name: "missing rate", ips: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		{name: "negative rate", ips: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, rate: -1},
		{name: "empty scope", rate: 5},
		{name: "invalid address", ips: []netip.Addr{{}}, rate: 5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildArgs(tt.ips, scanner.Options{RateLimit: tt.rate})
			if (err != nil) != (tt.want == nil) || !slices.Equal(got, tt.want) {
				t.Fatalf("BuildArgs = %v, %v, want %v", got, err, tt.want)
			}
		})
	}
}

func TestBuildInput(t *testing.T) {
	up := netip.MustParseAddr("192.0.2.1")
	ssh := netip.MustParseAddr("192.0.2.2")
	down := netip.MustParseAddr("192.0.2.3")
	outside := netip.MustParseAddr("192.0.2.4")
	in := scanner.Input{
		IPs: []netip.Addr{up, ssh, down},
		Hostnames: map[netip.Addr][]string{
			up: {"Web.Example.", "web.example", "site.example", "evil.example/path", "192.0.2.7"},
		},
	}
	observations := []scanner.Observation{
		{Kind: scanner.ObsHost, IP: up, Up: true},
		{Kind: scanner.ObsHost, IP: ssh, Up: true},
		{Kind: scanner.ObsHost, IP: down, Up: false},
		{Kind: scanner.ObsHost, IP: outside, Up: true},
		{Kind: scanner.ObsService, IP: up, Port: 80, Proto: "tcp", Service: "http"},
		{Kind: scanner.ObsService, IP: up, Port: 80, Proto: "tcp", Service: "http"},
		{Kind: scanner.ObsService, IP: up, Port: 9443, Proto: "tcp", Service: "ssl/http-alt"},
		{Kind: scanner.ObsService, IP: up, Port: 443, Proto: "udp", Service: "https"},
		{Kind: scanner.ObsService, IP: ssh, Port: 22, Proto: "tcp", Service: "ssh"},
		{Kind: scanner.ObsService, IP: down, Port: 8080, Proto: "tcp", Service: "http-proxy"},
		{Kind: scanner.ObsService, IP: outside, Port: 80, Proto: "tcp", Service: "http"},
	}
	got := BuildInput(in, observations)
	want := []string{
		"http://192.0.2.1:80", "http://site.example:80", "http://web.example:80",
		"https://192.0.2.1:9443", "https://site.example:9443", "https://web.example:9443",
	}
	if !slices.Equal(got.URLs, want) || !slices.Equal(got.IPs, []netip.Addr{up}) {
		t.Fatalf("BuildInput = %v on %v, want %v on %v", got.URLs, got.IPs, want, up)
	}
}

func TestParseNginxFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/nginx.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Raw, raw) || len(res.Observations) != 6 {
		t.Fatalf("got %d observations, want 3 HTTP responses and 3 technologies", len(res.Observations))
	}
	var httpByHost = make(map[string]scanner.Observation)
	for _, obs := range res.Observations {
		switch obs.Kind {
		case scanner.ObsHTTP:
			httpByHost[obs.URL] = obs
		case scanner.ObsTech:
			if obs.Tech != "Nginx:1.30.7" || obs.IP.IsUnspecified() || obs.Port == 0 || obs.At.IsZero() {
				t.Errorf("technology observation = %+v", obs)
			}
		default:
			t.Errorf("unexpected observation kind %q", obs.Kind)
		}
	}

	plain := httpByHost["http://172.21.0.2:80"]
	if plain.HTTP == nil || plain.HTTP.Title != "ASI nginx fixture" || plain.HTTP.FaviconHash != "1617003604" {
		t.Fatalf("HTTP info = %+v", plain.HTTP)
	}
	tls := httpByHost["https://asi-s7-nginx:443"]
	if tls.IP.String() != "172.21.0.2" || tls.Hostname != "asi-s7-nginx" || tls.Port != 443 || tls.Proto != "tcp" || tls.HTTP == nil {
		t.Fatalf("HTTPS observation = %+v", tls)
	}
	h := tls.HTTP
	if h.Status != 200 || h.Title != "ASI TLS fixture" || h.Headers["X-Environment"] != "staging" {
		t.Fatalf("HTTPS info = %+v", h)
	}
	if !slices.Equal(h.Cookies, []string{"session=fixture; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure", "theme=light; Path=/"}) {
		t.Errorf("cookies = %q", h.Cookies)
	}
	if !bytes.Contains([]byte(h.TLSCert), []byte(`"subject_cn":"asi-s7-nginx"`)) {
		t.Errorf("TLS data = %s", h.TLSCert)
	}
	if !slices.Equal(h.Redirects, []string{"https://asi-s7-nginx/home"}) || !slices.Equal(h.Technologies, []string{"Nginx:1.30.7"}) {
		t.Errorf("redirects = %v, technologies = %v", h.Redirects, h.Technologies)
	}

	for _, tt := range []struct {
		ip   string
		want int
	}{
		{"::ffff:172.21.0.2", 2},
		{"172.21.0.3", 1},
		{"172.21.0.4", 0},
	} {
		t.Run(tt.ip, func(t *testing.T) {
			filtered := res.PerIP(netip.MustParseAddr(tt.ip))
			if bytes.Count(filtered, []byte("\n")) != tt.want {
				t.Fatalf("PerIP(%s) has wrong number of records", tt.ip)
			}
			lines := bufio.NewScanner(bytes.NewReader(filtered))
			for lines.Scan() {
				if !bytes.Contains(raw, lines.Bytes()) {
					t.Error("PerIP modified the original JSON")
				}
			}
		})
	}
}

func TestParseFailedAndMalformed(t *testing.T) {
	raw := []byte("{\"input\":\"http://192.0.2.1:80\",\"failed\":true}\n\n")
	got, err := Parse(raw)
	if err != nil || len(got.Observations) != 0 || len(got.PerIP(netip.MustParseAddr("192.0.2.1"))) != 0 {
		t.Fatalf("failed probe gave %v, %v", got, err)
	}
	if _, err := Parse(append(raw, []byte("invalid JSON")...)); err == nil {
		t.Fatal("malformed output was accepted")
	}
}
