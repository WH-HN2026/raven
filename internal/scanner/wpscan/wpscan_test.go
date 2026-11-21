package wpscan

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

func TestBuildArgsAllowlist(t *testing.T) {
	got, err := BuildArgs("http://172.30.0.17:80/", "/tmp/out.json", "/tmp/cache", "/tmp/cookies.txt",
		scanner.Options{RateLimit: 25}, false)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	want := []string{
		"--url", "http://172.30.0.17:80",
		"--no-update",
		"--no-banner",
		"--format", "json",
		"--output", "/tmp/out.json",
		"--cache-dir", "/tmp/cache",
		"--cookie-jar", "/tmp/cookies.txt",
		"--enumerate", "p,t,cb,dbe,u1-5",
		"--detection-mode", "mixed",
		"--plugins-detection", "passive",
		"--themes-detection", "passive",
		"--users-detection", "passive",
		"--throttle", "40",
		"--request-timeout", "15",
		"--connect-timeout", "10",
		"--max-threads", "2",
		"--max-scan-duration", "120",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("BuildArgs =\n  %q\nwant:\n  %q", got, want)
	}

	// Ensure forbidden flags never appear.
	forbidden := []string{
		"--api-token", "--enterprise-db-token", "--passwords", "-P",
		"--usernames", "-U", "--password-attack", "--random-user-agent",
		"--rua", "--update", "--wp-auth", "--http-auth",
	}
	for _, f := range forbidden {
		if slices.Contains(got, f) {
			t.Errorf("forbidden flag %q appeared in argv %q", f, got)
		}
	}

	// --disable-tls-checks is appended only for HTTPS when explicitly enabled.
	gotHTTPWithTLSFlag, err := BuildArgs("http://172.30.0.17:80", "/tmp/out.json", "/tmp/cache", "/tmp/c",
		scanner.Options{RateLimit: 50}, true)
	if err != nil {
		t.Fatalf("BuildArgs http: %v", err)
	}
	if slices.Contains(gotHTTPWithTLSFlag, "--disable-tls-checks") {
		t.Errorf("HTTP URL should not include --disable-tls-checks: %q", gotHTTPWithTLSFlag)
	}
	gotHTTPS, err := BuildArgs("https://172.30.0.17:443", "/tmp/out.json", "/tmp/cache", "/tmp/c",
		scanner.Options{RateLimit: 2000}, true)
	if err != nil {
		t.Fatalf("BuildArgs https: %v", err)
	}
	if !slices.Contains(gotHTTPS, "--disable-tls-checks") {
		t.Errorf("HTTPS URL with disableTLS=true missing --disable-tls-checks: %q", gotHTTPS)
	}
	// Very high rate limit clamps throttle to 1ms.
	if i := slices.Index(gotHTTPS, "--throttle"); i < 0 || gotHTTPS[i+1] != "1" {
		t.Errorf("high rate limit should clamp throttle to 1ms, got %q", gotHTTPS)
	}

	// Validation errors.
	for _, tc := range []struct {
		name string
		url  string
		rate int
	}{
		{"zero rate", "http://172.30.0.17:80", 0},
		{"negative rate", "http://172.30.0.17:80", -5},
		{"bad scheme", "ftp://172.30.0.17:21", 10},
		{"non-root path", "http://172.30.0.17:80/wp-admin", 10},
		{"userinfo", "http://admin:pass@172.30.0.17:80", 10},
	} {
		if _, err := BuildArgs(tc.url, "/tmp/o", "/tmp/c", "/tmp/j", scanner.Options{RateLimit: tc.rate}, false); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestBuildInputFiltersWordPressOnly(t *testing.T) {
	ipWP := netip.MustParseAddr("172.30.0.17")
	ipJoomla := netip.MustParseAddr("172.30.0.18")
	ipWPByNuclei := netip.MustParseAddr("172.30.0.19")
	ipOutOfBatch := netip.MustParseAddr("172.30.0.99")

	webObs := []scanner.Observation{
		{Kind: scanner.ObsHTTP, IP: ipWP, Port: 80, URL: "http://172.30.0.17:80",
			HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"Apache HTTP Server:2.4.71", "WordPress:7.1.5"}}},
		{Kind: scanner.ObsHTTP, IP: ipJoomla, Port: 80, URL: "http://172.30.0.18:80",
			HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"Joomla:6.0", "PHP:8.4"}}},
		{Kind: scanner.ObsHTTP, IP: ipWPByNuclei, Port: 8080, URL: "http://172.30.0.19:8080",
			HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"Nginx"}}},
		{Kind: scanner.ObsHTTP, IP: ipOutOfBatch, Port: 80, URL: "http://172.30.0.99:80",
			HTTP: &scanner.HTTPInfo{Status: 200, Technologies: []string{"WordPress"}}},
	}
	nucleiObs := []scanner.Observation{
		{Kind: scanner.ObsTech, IP: ipWPByNuclei, Port: 8080, URL: "http://172.30.0.19:8080/wp-login.php",
			Product: "wordpress", CPE: "wordpress:wordpress", Tech: "wordpress",
			Match: &scanner.MatchInfo{TemplateID: "wordpress-detect", SourceURL: "http://172.30.0.19:8080", Tags: []string{"tech", "wordpress"}}},
		// Also duplicate detection on ipWP must not duplicate the URL.
		{Kind: scanner.ObsTech, IP: ipWP, Port: 80, URL: "http://172.30.0.17:80/wp-admin/install.php",
			Product: "wordpress", CPE: "wordpress:wordpress", Tech: "wordpress",
			Match: &scanner.MatchInfo{TemplateID: "wordpress-detect", SourceURL: "http://172.30.0.17:80"}},
	}

	in := BuildInput([]netip.Addr{ipWP, ipJoomla, ipWPByNuclei}, webObs, nucleiObs)
	wantURLs := []string{"http://172.30.0.17:80", "http://172.30.0.19:8080"}
	if !slices.Equal(in.URLs, wantURLs) {
		t.Fatalf("URLs = %v, want %v", in.URLs, wantURLs)
	}
	wantIPs := []netip.Addr{ipWP, ipWPByNuclei}
	if !slices.Equal(in.IPs, wantIPs) {
		t.Fatalf("IPs = %v, want %v", in.IPs, wantIPs)
	}

	// Batch with only Joomla → empty input.
	empty := BuildInput([]netip.Addr{ipJoomla}, webObs, nucleiObs)
	if len(empty.URLs) != 0 || len(empty.IPs) != 0 {
		t.Fatalf("Joomla-only batch = %+v, want empty", empty)
	}
}

func TestParseLabFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/lab-wordpress.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	res, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	ipWP := netip.MustParseAddr("172.30.0.17")
	ipJoomla := netip.MustParseAddr("172.30.0.18")

	var foundCore, foundTheme bool
	for _, o := range res.Observations {
		if o.IP != ipWP || o.Port != 80 || o.Kind != scanner.ObsTech {
			t.Errorf("unexpected observation: %+v", o)
		}
		if o.Product == "WordPress" && o.Version == "7.1.5" && o.CPE == "wordpress:wordpress:7.1.5" && o.Tech == "WordPress:7.1.5" {
			foundCore = true
		}
		if o.Product == "twentytwentyfive" && o.Version == "1.5" {
			foundTheme = true
		}
	}
	if !foundCore {
		t.Errorf("missing WordPress 7.1.5 observation in %+v", res.Observations)
	}
	if !foundTheme {
		t.Errorf("missing twentytwentyfive 1.5 observation in %+v", res.Observations)
	}

	perWP := res.PerIP(ipWP)
	if len(perWP) == 0 {
		t.Fatal("PerIP(172.30.0.17) returned empty")
	}
	var doc map[string]any
	if err := json.Unmarshal(perWP, &doc); err != nil {
		t.Fatalf("PerIP output is not valid JSON object: %v", err)
	}
	if doc["target_ip"] != "172.30.0.17" {
		t.Errorf("target_ip = %v, want 172.30.0.17", doc["target_ip"])
	}
	if got := res.PerIP(ipJoomla); got != nil {
		t.Errorf("PerIP(172.30.0.18) = %s, want nil", got)
	}
}

func TestParseMultiIPAndMerge(t *testing.T) {
	ip1 := netip.MustParseAddr("172.30.0.17")
	ip2 := netip.MustParseAddr("172.30.0.19")
	ndjson := strings.Join([]string{
		`{"start_time":1700000000,"target_url":"http://172.30.0.17:80/","target_ip":"172.30.0.17","version":{"number":"6.4.1"},"interesting_findings":[{"url":"http://172.30.0.17/readme.html","to_s":"readme","type":"readme","references":{},"interesting_entries":[]}],"plugins":{"akismet":{"slug":"akismet","version":{"number":"5.0"}}}}`,
		`{"start_time":1700000005,"target_url":"http://172.30.0.17:8080/","target_ip":"172.30.0.17","version":{"number":"6.4.1"},"interesting_findings":[{"url":"http://172.30.0.17:8080/xmlrpc.php","to_s":"xmlrpc","type":"xmlrpc","references":{},"interesting_entries":[]}],"plugins":{"jetpack":{"slug":"jetpack","version":{"number":"12.0"}}}}`,
		`{"start_time":1700000010,"target_url":"http://172.30.0.19:80/","target_ip":"172.30.0.19","version":{"number":"5.9.0"},"interesting_findings":[]}`,
	}, "\n")

	res, err := Parse([]byte(ndjson))
	if err != nil {
		t.Fatalf("Parse ndjson: %v", err)
	}

	var doc1 struct {
		InterestingFindings []any          `json:"interesting_findings"`
		Plugins             map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal(res.PerIP(ip1), &doc1); err != nil {
		t.Fatalf("unmarshal merged ip1: %v", err)
	}
	if len(doc1.InterestingFindings) != 2 {
		t.Errorf("merged interesting_findings = %d, want 2", len(doc1.InterestingFindings))
	}
	if len(doc1.Plugins) != 2 {
		t.Errorf("merged plugins = %d, want 2", len(doc1.Plugins))
	}

	var doc2 map[string]any
	if err := json.Unmarshal(res.PerIP(ip2), &doc2); err != nil {
		t.Fatalf("unmarshal ip2: %v", err)
	}
	if doc2["target_ip"] != "172.30.0.19" {
		t.Errorf("ip2 target_ip = %v", doc2["target_ip"])
	}
}

func TestRunEnvIsolationAndExitCodes(t *testing.T) {
	// Ensure API token env vars never leak into the subprocess.
	t.Setenv("WPSCAN_API_TOKEN", "secret-token-must-not-leak")
	t.Setenv("WPSCAN_ENTERPRISE_DB_TOKEN", "enterprise-secret-must-not-leak")

	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "fake-wpscan.sh")
	script := `#!/bin/sh
set -eu
if [ -n "${WPSCAN_API_TOKEN:-}" ] || [ -n "${WPSCAN_ENTERPRISE_DB_TOKEN:-}" ]; then
  echo "LEAKED_API_TOKEN" >&2
  exit 99
fi
out=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    --url) url="$2"; shift 2 ;;
    *) shift ;;
  esac
done
cat > "$out" <<EOF
{"start_time":1700000000,"target_url":"$url","target_ip":"172.30.0.17","version":{"number":"6.4.1"},"interesting_findings":[]}
EOF
exit "${FAKE_EXIT:-0}"
`
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("172.30.0.17")
	in := scanner.Input{IPs: []netip.Addr{ip}, URLs: []string{"http://172.30.0.17:80"}}
	sc := &Scanner{Binary: fakeBin, DBDir: dir, PerURLTimeout: 10 * time.Second}

	// Exit code 0 succeeds and receives no leaked tokens.
	res, err := sc.Run(context.Background(), in, scanner.Options{RateLimit: 25})
	if err != nil {
		t.Fatalf("Run exit 0: %v", err)
	}
	if len(res.PerIP(ip)) == 0 {
		t.Fatal("expected non-empty PerIP output")
	}

	// Exit code 5 (WPScan::ExitCode::VULNERABLE) also counts as success.
	binExit5 := filepath.Join(dir, "fake-wpscan-5.sh")
	if err := os.WriteFile(binExit5, []byte(strings.ReplaceAll(script, `"${FAKE_EXIT:-0}"`, "5")), 0755); err != nil {
		t.Fatal(err)
	}
	sc5 := &Scanner{Binary: binExit5, DBDir: dir, PerURLTimeout: 10 * time.Second}
	if _, err := sc5.Run(context.Background(), in, scanner.Options{RateLimit: 25}); err != nil {
		t.Fatalf("Run exit 5 should succeed, got: %v", err)
	}

	// Exit code 4 (WPScan::ExitCode::ERROR) fails.
	binExit4 := filepath.Join(dir, "fake-wpscan-4.sh")
	if err := os.WriteFile(binExit4, []byte(strings.ReplaceAll(script, `"${FAKE_EXIT:-0}"`, "4")), 0755); err != nil {
		t.Fatal(err)
	}
	sc4 := &Scanner{Binary: binExit4, DBDir: dir, PerURLTimeout: 10 * time.Second}
	if _, err := sc4.Run(context.Background(), in, scanner.Options{RateLimit: 25}); err == nil {
		t.Fatal("Run exit 4 should fail, got nil")
	}
}
