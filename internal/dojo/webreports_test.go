package dojo

import (
	"bytes"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/httpx"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../scanner/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func parsedFixture(t *testing.T, parse ParseFunc, raw []byte) *scanner.Result {
	t.Helper()
	result, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestWebReportsByRespondingIP(t *testing.T) {
	web := parsedFixture(t, httpx.Parse, fixture(t, "httpx/testdata/nginx.jsonl"))
	detection := parsedFixture(t, nuclei.Parse, fixture(t, "nuclei/testdata/lab-http.jsonl"))
	wp := netip.MustParseAddr("172.30.0.17")
	tomcat := netip.MustParseAddr("172.30.0.21")
	nginx := netip.MustParseAddr("172.21.0.2")
	noWeb := netip.MustParseAddr("172.30.0.27")

	// Add confirmed HTTP origins for the two real nuclei matches. The real
	// httpx fixture independently covers nginx and a vhost at the same IP.
	web.Observations = append(web.Observations,
		scanner.Observation{IP: wp, Kind: scanner.ObsHTTP, Port: 80, URL: "http://172.30.0.17:80", HTTP: &scanner.HTTPInfo{Status: 200}},
		scanner.Observation{IP: tomcat, Kind: scanner.ObsHTTP, Port: 8080, URL: "http://172.30.0.21:8080", HTTP: &scanner.HTTPInfo{Status: 200}},
	)
	reports, tags := webReports([]netip.Addr{wp, tomcat, nginx, noWeb}, web, detection)
	for _, tc := range []struct {
		ip          netip.Addr
		want        []string
		wantContent []string
		wantTags    []string
	}{
		{wp, []string{"Nuclei Scan"}, []string{`"template-id":"wordpress-detect"`}, []string{"tech:wordpress"}},
		{tomcat, []string{"Nuclei Scan"}, []string{`"template-id":"apache-tomcat-exposed"`}, []string{"panel:tomcat"}},
		{nginx, []string{"httpx Scan", "Nuclei Scan"}, []string{"raven-s7-nginx:443", "[]"}, []string{"tech:nginx", "env:staging", "host:raven-s7-nginx"}},
		{noWeb, nil, nil, nil},
	} {
		t.Run(tc.ip.String(), func(t *testing.T) {
			got := reports[tc.ip]
			if len(got) != len(tc.want) {
				t.Fatalf("got %d reports, want %d", len(got), len(tc.want))
			}
			for i, r := range got {
				if r.scanType != tc.want[i] || !bytes.Contains(r.content, []byte(tc.wantContent[i])) {
					t.Errorf("report %d is %s, want %s with %q", i, r.scanType, tc.want[i], tc.wantContent[i])
				}
				if r.scanType == "httpx Scan" && (bytes.Contains(r.content, []byte("172.21.0.3")) || bytes.Count(r.content, []byte("\n")) != 1) {
					t.Error("expected exactly the two nginx IP and vhost JSON lines")
				}
				if r.scanType == "Nuclei Scan" && bytes.Contains(r.content, []byte("\n")) {
					t.Error("expected one nuclei record for this IP")
				}
			}
			for _, tag := range tc.wantTags {
				if !slices.Contains(tags[tc.ip], tag) {
					t.Errorf("tags %v lack %s", tags[tc.ip], tag)
				}
			}
		})
	}
	if _, ok := reports[netip.MustParseAddr("172.21.0.3")]; ok {
		t.Error("nonresponding IP got a report")
	}
	if got, _ := webReports([]netip.Addr{nginx}, web, nil); len(got[nginx]) != 1 {
		t.Error("missing nuclei artifact must preserve prior findings")
	}
}

func TestEnvironmentTags(t *testing.T) {
	for _, tc := range []struct{ hostname, title, header, tag string }{
		{"", "", " Stg ", "env:staging"},
		{"app-staging.example", "", "", "env:staging"},
		{"", "RAVEN Staging", "", "env:staging"},
		{"app-staging.example", "", "prod", "env:production"},
		{"", "Restaging", "unrecognized", ""},
	} {
		got := observationTags(scanner.Observation{Hostname: tc.hostname, HTTP: &scanner.HTTPInfo{
			Title: tc.title, Headers: map[string]string{"X-Environment": tc.header},
		}})
		got = slices.DeleteFunc(got, func(tag string) bool { return !strings.HasPrefix(tag, "env:") })
		if len(got) == 0 && tc.tag == "" {
			continue
		}
		if !slices.Equal(got, []string{tc.tag}) {
			t.Errorf("%q/%q/%q: got %v, want %q", tc.hostname, tc.title, tc.header, got, tc.tag)
		}
	}
}
