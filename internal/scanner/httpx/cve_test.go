package httpx

import (
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/scanner"
)

func TestFixtureWebTechCVEMatchesAndDedup(t *testing.T) {
	raw, err := os.ReadFile("testdata/webtech.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Verify httpx.Parse maps web technologies to normalized CPEs on ObsTech.
	gotCPEs := map[string]string{}
	var instances []cve.Instance
	for _, o := range res.Observations {
		if o.Kind == scanner.ObsTech {
			gotCPEs[o.Tech] = o.CPE
		}
		if o.Kind == scanner.ObsHTTP && o.HTTP != nil {
			instances = append(instances, cve.InstancesFromHTTPTech(o.IP, int32(o.Port), o.Proto, nil, o.HTTP.Technologies)...)
		}
	}
	for tech, wantCPE := range map[string]string{
		"WordPress:6.4.1":           "wordpress:wordpress:6.4.1",
		"Apache Tomcat:9.0.10":      "apache:tomcat:9.0.10",
		"Apache HTTP Server:2.4.49": "apache:http_server:2.4.49",
	} {
		if gotCPEs[tech] != wantCPE {
			t.Errorf("ObsTech[%q].CPE = %q, want %q", tech, gotCPEs[tech], wantCPE)
		}
	}

	m, err := cve.Default()
	if err != nil {
		t.Fatal(err)
	}

	// Combine an nmap service reporting Apache httpd 2.4.49 (with alias CPE
	// apache:httpd) on the SAME port 172.30.0.17:80 as httpx's Apache HTTP
	// Server:2.4.49 + WordPress:6.4.1.
	wpIP := netip.MustParseAddr("172.30.0.17")
	combined := append([]cve.Instance{
		{
			IP: wpIP, Port: 80, Proto: "tcp",
			CPE: "apache:httpd:2.4.49", Product: "Apache httpd", Version: "2.4.49",
		},
	}, instances...)

	matches := m.MatchAll(combined)
	if len(matches) != 3 {
		t.Fatalf("got %d matches, want 3 (nmap+httpx Apache deduped + WordPress + Tomcat): %+v", len(matches), matches)
	}

	byUID := map[string]cve.Match{}
	for _, mt := range matches {
		byUID[mt.UID()] = mt
	}
	hasCVE := func(mt cve.Match, id string) bool {
		return slices.ContainsFunc(mt.Hits, func(h cve.Hit) bool { return h.ID == id })
	}

	// Apache 2.4.49: deduplicated to one finding, canonical CPE apache:http_server.
	ap, ok := byUID["172.30.0.17:80:apache:http_server:2.4.49"]
	if !ok {
		t.Fatalf("missing deduplicated Apache match in %v", byUID)
	}
	if !hasCVE(ap, "CVE-2021-41773") {
		t.Errorf("Apache 2.4.49 missing CVE-2021-41773: %v", ap.Hits)
	}

	// WordPress 6.4.1 on same port 80: separate product instance with right CVEs.
	wp, ok := byUID["172.30.0.17:80:wordpress:wordpress:6.4.1"]
	if !ok {
		t.Fatalf("missing WordPress match in %v", byUID)
	}
	for _, wantID := range []string{"CVE-2024-31211", "CVE-2024-31210"} {
		if !hasCVE(wp, wantID) {
			t.Errorf("WordPress 6.4.1 missing %s (got %d hits)", wantID, len(wp.Hits))
		}
	}

	// Apache Tomcat 9.0.10 on port 8080: right CVEs.
	tc, ok := byUID["172.30.0.21:8080:apache:tomcat:9.0.10"]
	if !ok {
		t.Fatalf("missing Tomcat match in %v", byUID)
	}
	for _, wantID := range []string{"CVE-2019-0232", "CVE-2019-0199"} {
		if !hasCVE(tc, wantID) {
			t.Errorf("Tomcat 9.0.10 missing %s (got %d hits)", wantID, len(tc.Hits))
		}
	}
}
