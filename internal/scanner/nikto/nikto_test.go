package nikto

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

func TestBuildArgs(t *testing.T) {
	allowed := AllowedFlags()
	forbidden := []string{"-id", "-evasion", "-mutate", "-mutate-options", "-Plugins", "-update", "-useproxy", "-Option"}

	tests := []struct {
		name    string
		url     string
		out     string
		rate    int
		maxTime time.Duration
		timeout time.Duration
		want    []string
	}{
		{
			name: "http ipv4 default caps",
			url:  "http://172.30.0.19:80",
			out:  "/tmp/out.json",
			rate: 25,
			want: []string{
				"-h", "http://172.30.0.19:80",
				"-nossl",
				"-Tuning", "123be",
				"-Pause", "0.04",
				"-maxtime", "300s",
				"-timeout", "10",
				"-Format", "json",
				"-output", "/tmp/out.json",
				"-nointeractive",
				"-nocheck",
				"-ask", "no",
				"-nolookup",
			},
		},
		{
			name:    "https ipv4 custom caps",
			url:     "https://172.30.0.23:443",
			out:     "/tmp/tls.json",
			rate:    10,
			maxTime: 120 * time.Second,
			timeout: 5 * time.Second,
			want: []string{
				"-h", "https://172.30.0.23:443",
				"-ssl",
				"-Tuning", "123be",
				"-Pause", "0.1",
				"-maxtime", "120s",
				"-timeout", "5",
				"-Format", "json",
				"-output", "/tmp/tls.json",
				"-nointeractive",
				"-nocheck",
				"-ask", "no",
				"-nolookup",
			},
		},
		{
			name: "high rate floored at MinPause",
			url:  "http://172.30.0.21:8080/",
			out:  "/tmp/tomcat.json",
			rate: 500,
			want: []string{
				"-h", "http://172.30.0.21:8080",
				"-nossl",
				"-Tuning", "123be",
				"-Pause", "0.01",
				"-maxtime", "300s",
				"-timeout", "10",
				"-Format", "json",
				"-output", "/tmp/tomcat.json",
				"-nointeractive",
				"-nocheck",
				"-ask", "no",
				"-nolookup",
			},
		},
		{
			name: "ipv6 literal adds -ipv6",
			url:  "http://[fd00::1]:8080",
			out:  "/tmp/v6.json",
			rate: 1,
			want: []string{
				"-h", "http://[fd00::1]:8080",
				"-nossl",
				"-Tuning", "123be",
				"-Pause", "1",
				"-maxtime", "300s",
				"-timeout", "10",
				"-Format", "json",
				"-output", "/tmp/v6.json",
				"-nointeractive",
				"-nocheck",
				"-ask", "no",
				"-nolookup",
				"-ipv6",
			},
		},
		{name: "zero rate rejected", url: "http://172.30.0.19:80", out: "/tmp/o.json", rate: 0},
		{name: "negative rate rejected", url: "http://172.30.0.19:80", out: "/tmp/o.json", rate: -5},
		{name: "hostname rejected", url: "http://example.com:80", out: "/tmp/o.json", rate: 10},
		{name: "missing port rejected", url: "http://172.30.0.19", out: "/tmp/o.json", rate: 10},
		{name: "path rejected", url: "http://172.30.0.19:80/admin", out: "/tmp/o.json", rate: 10},
		{name: "query rejected", url: "http://172.30.0.19:80?a=1", out: "/tmp/o.json", rate: 10},
		{name: "userinfo rejected", url: "http://u:p@172.30.0.19:80", out: "/tmp/o.json", rate: 10},
		{name: "comma list rejected", url: "http://172.30.0.19:80,172.30.0.20:80", out: "/tmp/o.json", rate: 10},
		{name: "ftp scheme rejected", url: "ftp://172.30.0.19:21", out: "/tmp/o.json", rate: 10},
		{name: "empty output rejected", url: "http://172.30.0.19:80", out: "", rate: 10},
		{name: "dash output rejected", url: "http://172.30.0.19:80", out: "-evil.json", rate: 10},
		{name: "negative maxtime rejected", url: "http://172.30.0.19:80", out: "/tmp/o.json", rate: 10, maxTime: -time.Second},
		{name: "negative timeout rejected", url: "http://172.30.0.19:80", out: "/tmp/o.json", rate: 10, timeout: -time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildArgs(tt.url, tt.out, scanner.Options{RateLimit: tt.rate}, tt.maxTime, tt.timeout)
			if tt.want == nil {
				if err == nil {
					t.Fatalf("BuildArgs succeeded with %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildArgs unexpected error: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("BuildArgs =\n  %v\nwant:\n  %v", got, tt.want)
			}
			// Audit every flag against the allowlist and forbidden list.
			for _, tok := range got {
				if strings.HasPrefix(tok, "-") {
					if !slices.Contains(allowed, tok) {
						t.Errorf("emitted non-allowlisted flag %q", tok)
					}
					if slices.Contains(forbidden, tok) {
						t.Errorf("emitted forbidden flag %q", tok)
					}
				}
			}
			// Verify tuning excludes all active exploitation / DoS categories.
			ti := slices.Index(got, "-Tuning")
			if ti < 0 || ti+1 >= len(got) || got[ti+1] != "123be" {
				t.Fatalf("unexpected -Tuning in %v", got)
			}
			for _, bad := range "4567890acdx" {
				if strings.ContainsRune(got[ti+1], bad) {
					t.Errorf("tuning %q contains disallowed category %q", got[ti+1], bad)
				}
			}
		})
	}
}

func TestBuildInput(t *testing.T) {
	ip1 := netip.MustParseAddr("172.30.0.19")
	ip2 := netip.MustParseAddr("172.30.0.21")
	outside := netip.MustParseAddr("172.30.0.25")
	obs := func(ip netip.Addr, port uint16, u string, status int) scanner.Observation {
		return scanner.Observation{Kind: scanner.ObsHTTP, IP: ip, Port: port, URL: u, HTTP: &scanner.HTTPInfo{Status: status}}
	}
	in := BuildInput([]netip.Addr{ip1, ip2}, []scanner.Observation{
		obs(ip1, 80, "http://172.30.0.19:80", 200),
		obs(ip1, 80, "http://172.30.0.19:80/", 200),      // duplicate canonical origin
		obs(ip1, 80, "http://172.30.0.19:80/admin", 200), // non-root path ignored
		obs(ip1, 80, "http://nginx.raven.lab:80", 200),   // hostname ignored
		obs(ip2, 8080, "http://172.30.0.21:8080", 401),   // 401 is still a live HTTP origin
		obs(ip2, 8080, "http://172.30.0.21:8080", 0),     // failed probe ignored
		obs(outside, 80, "http://172.30.0.25:80", 200),   // outside batch ignored
		{Kind: scanner.ObsService, IP: ip1, Port: 80},    // non-HTTP observation ignored
	})
	wantURLs := []string{"http://172.30.0.19:80", "http://172.30.0.21:8080"}
	wantIPs := []netip.Addr{ip1, ip2}
	if !slices.Equal(in.URLs, wantURLs) || !slices.Equal(in.IPs, wantIPs) {
		t.Fatalf("BuildInput = %+v, want URLs=%v IPs=%v", in, wantURLs, wantIPs)
	}
}

func TestRunScopeEnvAndCancel(t *testing.T) {
	ip1 := netip.MustParseAddr("172.30.0.19")
	ip2 := netip.MustParseAddr("172.30.0.20")

	// Reject out-of-batch URL before invoking binary.
	if _, err := (&Scanner{Binary: "must-not-run"}).Run(
		context.Background(),
		scanner.Input{IPs: []netip.Addr{ip1}, URLs: []string{"http://172.30.0.20:80"}},
		scanner.Options{RateLimit: 10},
	); err == nil {
		t.Fatal("accepted URL outside batch IPs")
	}

	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.txt")
	envFile := filepath.Join(dir, "env.txt")
	fakeBin := filepath.Join(dir, "fake-nikto")
	script := `#!/bin/sh
out=""
host=""
prev=""
for a in "$@"; do
  printf '%s\n' "$a" >> "` + argsFile + `"
  if [ "$prev" = "-output" ]; then out="$a"; fi
  if [ "$prev" = "-h" ]; then host="$a"; fi
  prev="$a"
done
env > "` + envFile + `"
ip=$(printf '%s' "$host" | sed -E 's|https?://([^:]+):([0-9]+)|\1|')
port=$(printf '%s' "$host" | sed -E 's|https?://([^:]+):([0-9]+)|\2|')
cat > "$out" <<JSON
[{"host":"$ip","ip":"$ip","port":"$port","server_banner":"nginx","vulnerabilities":[{"id":"999103","method":"GET","url":"/","msg":"The X-Content-Type-Options header is not set."}]}]
JSON
`
	if err := os.WriteFile(fakeBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HTTP_PROXY", "http://evil.proxy:8080")
	t.Setenv("RAVEN_SECRET", "must-not-leak")

	s := &Scanner{Binary: fakeBin, MaxTime: 60 * time.Second, Timeout: 5 * time.Second, Concurrency: 2}
	res, err := s.Run(context.Background(), scanner.Input{
		IPs:  []netip.Addr{ip1, ip2},
		URLs: []string{"http://172.30.0.19:80", "http://172.30.0.20:80"},
	}, scanner.Options{RateLimit: 20})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Observations) != 2 {
		t.Fatalf("got %d observations, want 2", len(res.Observations))
	}
	if len(res.PerIP(ip1)) == 0 || len(res.PerIP(ip2)) == 0 || res.PerIP(netip.MustParseAddr("172.30.0.25")) != nil {
		t.Fatalf("PerIP filtering failed")
	}

	envBytes, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envBytes), "HTTP_PROXY") || strings.Contains(string(envBytes), "RAVEN_SECRET") {
		t.Fatalf("leaked host env into nikto process: %s", envBytes)
	}

	// Verify ctx cancellation kills a hanging process promptly.
	hangBin := filepath.Join(dir, "hang-nikto")
	if err := os.WriteFile(hangBin, []byte("#!/bin/sh\nsleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, err = (&Scanner{Binary: hangBin}).Run(ctx, scanner.Input{
		IPs:  []netip.Addr{ip1},
		URLs: []string{"http://172.30.0.19:80"},
	}, scanner.Options{RateLimit: 10})
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	if dur := time.Since(t0); dur > 3*time.Second {
		t.Fatalf("cancelled process took %s to terminate, want <3s", dur)
	}
}

func TestParseMultiPortMergeAndEmpty(t *testing.T) {
	raw := []byte(`[
		{"host":"172.30.0.19","ip":"172.30.0.19","port":80,"vulnerabilities":[{"id":"1","method":"GET","url":"/","msg":"Finding on 80"}]},
		{"host":"172.30.0.19","ip":"172.30.0.19","port":"443","ssl_info":{"cn":"example"},"vulnerabilities":[{"id":"2","method":"GET","url":"/tls","msg":"Finding on 443"}]},
		{"host":"172.30.0.20","ip":"172.30.0.20","port":"80","vulnerabilities":[]}
	]`)
	res, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Observations) != 2 {
		t.Fatalf("got %d observations, want 2", len(res.Observations))
	}
	if res.Observations[1].URL != "https://172.30.0.19:443/tls" {
		t.Errorf("HTTPS observation URL = %q, want https://172.30.0.19:443/tls", res.Observations[1].URL)
	}

	// Multi-port IP must merge into a 1-element array for DefectDojo's NiktoJSONParser.
	per19 := res.PerIP(netip.MustParseAddr("172.30.0.19"))
	var reps []HostReport
	if err := json.Unmarshal(per19, &reps); err != nil {
		t.Fatalf("unmarshal PerIP(.19): %v", err)
	}
	if len(reps) != 1 || len(reps[0].Vulnerabilities) != 2 {
		t.Fatalf("merged PerIP(.19) = %s, want 1 host report with 2 vulns", per19)
	}
	if !strings.HasPrefix(reps[0].Vulnerabilities[1].Msg, "[port 443] ") {
		t.Errorf("second port vuln msg = %q, want [port 443] prefix", reps[0].Vulnerabilities[1].Msg)
	}

	// Scanned IP with 0 vulns still emits a valid empty report so Dojo closes old findings.
	per20 := res.PerIP(netip.MustParseAddr("172.30.0.20"))
	var reps20 []HostReport
	if err := json.Unmarshal(per20, &reps20); err != nil || len(reps20) != 1 || len(reps20[0].Vulnerabilities) != 0 {
		t.Fatalf("PerIP(.20) = %s (%v), want 1 host report with 0 vulns", per20, err)
	}

	// Unscanned IP returns nil so Dojo preserves prior findings.
	if got := res.PerIP(netip.MustParseAddr("172.30.0.21")); got != nil {
		t.Fatalf("PerIP(.21) = %s, want nil", got)
	}

	// Malformed JSON rejected.
	if _, err := Parse([]byte("not json")); err == nil {
		t.Fatal("accepted malformed JSON")
	}
}

func TestParseLabFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/lab.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse lab.json: %v", err)
	}
	if len(res.Observations) != 28 {
		t.Fatalf("got %d observations, want 28 (4 lab hosts x 7 items)", len(res.Observations))
	}

	for _, tc := range []struct {
		ip        string
		port      uint16
		scheme    string
		wantSub   string
		wantCount int
	}{
		{"172.30.0.19", 80, "http", "permissions-policy", 7},
		{"172.30.0.20", 80, "http", "x-environment", 7},
		{"172.30.0.21", 8080, "http", "Apache Tomcat", 7},
		{"172.30.0.23", 443, "https", "permissions-policy", 7},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			ip := netip.MustParseAddr(tc.ip)
			per := res.PerIP(ip)
			if len(per) == 0 {
				t.Fatalf("PerIP(%s) returned empty", tc.ip)
			}
			var reps []HostReport
			if err := json.Unmarshal(per, &reps); err != nil {
				t.Fatalf("PerIP(%s) invalid JSON: %v", tc.ip, err)
			}
			if len(reps) != 1 || len(reps[0].Vulnerabilities) != tc.wantCount {
				t.Fatalf("PerIP(%s) reps=%d vulns=%d, want 1/%d", tc.ip, len(reps), len(reps[0].Vulnerabilities), tc.wantCount)
			}
			replayed, err := Parse(per)
			if err != nil || len(replayed.Observations) != tc.wantCount {
				t.Fatalf("replay PerIP(%s): obs=%d err=%v", tc.ip, len(replayed.Observations), err)
			}
			found := false
			for _, o := range replayed.Observations {
				if o.IP != ip || o.Port != tc.port || o.At.IsZero() || o.Match == nil {
					t.Errorf("unexpected observation: %+v", o)
				}
				if !strings.HasPrefix(o.URL, tc.scheme+"://"+tc.ip+":") {
					t.Errorf("URL %q does not start with %s://%s:", o.URL, tc.scheme, tc.ip)
				}
				if strings.Contains(o.Match.Name, tc.wantSub) {
					found = true
				}
			}
			if !found {
				t.Errorf("did not find %q in observations for %s", tc.wantSub, tc.ip)
			}
		})
	}
}
