package cve

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.10", -1},
		{"1.2.10", "1.2.3", 1},
		{"1.2", "1.2.0", 0},
		{"8.9p1", "8.9", 1},
		{"8.9p1", "9.0", -1},
		{"8.9p1", "8.9p2", -1},
		{"7.4", "7.4p1", -1},
		{"2.4.49", "2.4.49-r0", 0},
		{"2.4.49-r0", "2.4.50", -1},
		{"1.18.0-6ubuntu14", "1.18.0", 0},
		{"7.4p1-10+deb9u7", "7.4p1", 0},
		{"2.0rc1", "2.0", -1},
		{"2.0-rc1", "2.0", -1},
		{"1.0.0-beta1", "1.0.0", -1},
		{"1.0.2k", "1.0.2", 1},
		{"1.0.2k", "1.0.2l", -1},
		{"1.0a", "1.0.1", -1},
		{"v2.4.1", "2.4.1", 0},
		{"10.0", "9.9.9", 1},
		{"5.4.0", "5.4.0", 0},
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestInRange(t *testing.T) {
	tests := []struct {
		v    string
		r    Range
		want bool
	}{
		{"2.4.49", Range{Exact: "2.4.49"}, true},
		{"2.4.49-r0", Range{Exact: "2.4.49"}, true},
		{"2.4.50", Range{Exact: "2.4.49"}, false},
		{"2.4.49", Range{StartIncl: "2.4.0", EndExcl: "2.4.50"}, true},
		{"2.4.50", Range{StartIncl: "2.4.0", EndExcl: "2.4.50"}, false},
		{"2.4.50", Range{EndIncl: "2.4.50"}, true},
		{"2.2.34", Range{StartIncl: "2.4.0", EndIncl: "2.4.50"}, false},
		{"2.4.0", Range{StartExcl: "2.4.0", EndIncl: "2.4.50"}, false},
		// OpenSSH portable releases: 7.4p1 is the 7.4 release.
		{"7.4p1", Range{EndIncl: "7.4"}, true},
		{"7.4p1", Range{EndExcl: "7.4"}, false},
		{"7.4p1", Range{EndExcl: "7.5"}, true},
		{"7.4", Range{Exact: "7.4p1"}, true},
		{"7.4p1", Range{Exact: "7.4"}, true},
		{"7.4p2", Range{Exact: "7.4p1"}, false},
		{"8.9p1", Range{EndExcl: "8.9p1"}, false},
		{"8.9p1", Range{EndExcl: "9.3p2"}, true},
		{"9.0", Range{StartIncl: "8.9p1", EndExcl: "9.3p2"}, true},
		{"1.0", Range{}, false},
	}
	for _, tt := range tests {
		if got := InRange(tt.v, tt.r); got != tt.want {
			t.Errorf("InRange(%q, %+v) = %v, want %v", tt.v, tt.r, got, tt.want)
		}
	}
}

func TestExtractVersionAndDistro(t *testing.T) {
	tests := []struct {
		in      string
		version string
		distro  bool
	}{
		{"2.4.49", "2.4.49", false},
		{"7.4p1 Debian 10+deb9u7", "7.4p1", true},
		{"8.9p1 Ubuntu 3ubuntu0.10", "8.9p1", true},
		{"2.4.37 ((Red Hat Enterprise Linux))", "2.4.37", true},
		{"7.4 el8", "7.4", true},
		{"1.20.1-14.el9", "1.20.1-14.el9", true},
		{"2.4.49-r0", "2.4.49-r0", true},
		{"1.18.0", "1.18.0", false},
		{"Exim smtpd", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		if got := ExtractVersion(tt.in); got != tt.version {
			t.Errorf("ExtractVersion(%q) = %q, want %q", tt.in, got, tt.version)
		}
		if got := DistroBuild(tt.in); got != tt.distro {
			t.Errorf("DistroBuild(%q) = %v, want %v", tt.in, got, tt.distro)
		}
	}
	if DistroBuild("SF-Port80-TCP:V=7.99%P=x86_64-alpine-linux-musl%r(GetRequest,10,\"HTTP/1.1 200 OK\")") {
		t.Error("DistroBuild matched scanner platform in nmap SF-Port fingerprint")
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		cvss        float64
		kev, distro bool
		want        string
	}{
		{9.8, false, false, "Critical"},
		{7.5, false, false, "High"},
		{7.5, true, false, "Critical"},
		{9.8, true, false, "Critical"},
		{5.3, false, false, "Medium"},
		{5.3, true, false, "High"},
		{3.1, false, false, "Low"},
		{0, false, false, "Info"},
		{9.8, true, true, "Low"},
		{0, false, true, "Info"},
	}
	for _, tt := range tests {
		if got := Severity(tt.cvss, tt.kev, tt.distro); got != tt.want {
			t.Errorf("Severity(%v, %v, %v) = %q, want %q", tt.cvss, tt.kev, tt.distro, got, tt.want)
		}
	}
}

func TestCPEForTech(t *testing.T) {
	tests := []struct {
		in, cpe, version string
		ok               bool
	}{
		{"Nginx:1.19.0", "f5:nginx", "1.19.0", true},
		{"Apache HTTP Server:2.4.49", "apache:http_server", "2.4.49", true},
		{"Apache httpd", "apache:http_server", "", true},
		{"WordPress", "wordpress:wordpress", "", true},
		{"Joomla", `joomla:joomla\!`, "", true},
		{"OpenSSH", "openbsd:openssh", "", true},
		{"Microsoft IIS httpd", "microsoft:internet_information_services", "", true},
		{"apache-detect", "apache:http_server", "", true},
		{"PHP:8.1.2", "php:php", "8.1.2", true},
		{"Exim smtpd", "exim:exim", "", true},
		{"Apache Tomcat", "apache:tomcat", "", true},
		{"Apache Tomcat:9.0.10", "apache:tomcat", "9.0.10", true},
		{"Apache Tomcat/9.0.10", "apache:tomcat", "9.0.10", true},
		{"WordPress:6.4.1", "wordpress:wordpress", "6.4.1", true},
		// names the organizers' lab built-in signatures emit (template id / name)
		{"raven-traefik-api", "traefik:traefik", "", true},
		{"Traefik dashboard API", "traefik:traefik", "", true},
		{"Traefik:3.1.7", "traefik:traefik", "3.1.7", true},
		{"raven-gitea-version", "gitea:gitea", "", true},
		{"Gitea version in footer", "gitea:gitea", "", true},
		{"Gitea:28.4.0", "gitea:gitea", "28.4.0", true},
		{"raven-adminer-login", "adminer:adminer", "", true},
		{"Adminer login", "adminer:adminer", "", true},
		{"Adminer:6.3.0", "adminer:adminer", "6.3.0", true},
		{"raven-phpmyadmin-login", "phpmyadmin:phpmyadmin", "", true},
		{"phpMyAdmin login", "phpmyadmin:phpmyadmin", "", true},
		{"raven-rabbitmq-management", "vmware:rabbitmq", "", true},
		{"RabbitMQ management panel", "vmware:rabbitmq", "", true},
		{"vsftpd", "beasts:vsftpd", "", true},
		{"raven-toxiproxy-api", "", "", false},
		{"raven-npm-admin", "", "", false},
		{"raven-dvwa-login", "", "", false},
		{"jQuery UI", "", "", false},
		{"Bootstrap", "", "", false},
	}
	for _, tt := range tests {
		c, v, ok := CPEForTech(tt.in)
		if c != tt.cpe || v != tt.version || ok != tt.ok {
			t.Errorf("CPEForTech(%q) = %q, %q, %v; want %q, %q, %v", tt.in, c, v, ok, tt.cpe, tt.version, tt.ok)
		}
	}
}

func TestProductsAndTechTargetsExist(t *testing.T) {
	prods := Products()
	if len(prods) < 50 {
		t.Fatalf("products.txt has %d products, want ≥ 50", len(prods))
	}
	known := map[string]bool{}
	for _, p := range prods {
		for _, c := range p.NVD {
			known[c] = true
		}
	}
	for k, c := range techSynonyms {
		if !known[c] {
			t.Errorf("techSynonyms[%q] = %q, which is not an NVD name in products.txt", k, c)
		}
	}
}

// testDB is a tiny hand-written dataset so matcher tests don't depend on
// what NVD returned when the data was generated.
func testDB() *DB {
	return &DB{
		CVEs: map[string]Record{
			"CVE-2021-41773": {CVSS: 7.5, KEV: true, EPSS: 0.94},
			"CVE-2021-42013": {CVSS: 9.8, KEV: true, EPSS: 0.94},
			"CVE-2021-44790": {CVSS: 9.8},
			"CVE-2018-15473": {CVSS: 5.3},
			"CVE-2023-38408": {CVSS: 9.8},
			"CVE-2016-0777":  {CVSS: 6.5},
			"CVE-2015-1419":  {CVSS: 5.0},
		},
		Products: map[string][]Affect{
			"apache:http_server": {
				{ID: "CVE-2021-41773", Ranges: []Range{{Exact: "2.4.49"}}},
				{ID: "CVE-2021-42013", Ranges: []Range{{Exact: "2.4.49"}, {Exact: "2.4.50"}}},
				{ID: "CVE-2021-44790", Ranges: []Range{{EndIncl: "2.4.51"}}},
			},
			"openbsd:openssh": {
				{ID: "CVE-2018-15473", Ranges: []Range{{EndIncl: "7.7"}}},
				{ID: "CVE-2023-38408", Ranges: []Range{{EndExcl: "9.3p2"}}},
				{ID: "CVE-2016-0777", Ranges: []Range{{StartIncl: "5.4", EndExcl: "7.1p2"}}},
			},
			"vsftpd_project:vsftpd": {
				{ID: "CVE-2015-1419", Ranges: []Range{{EndIncl: "3.0.2"}}},
			},
		},
	}
}

func TestMatch(t *testing.T) {
	m := NewMatcher(testDB(), Products())
	ip := netip.MustParseAddr("172.30.0.25")
	tests := []struct {
		name     string
		in       Instance
		want     int // hits; 0 = no match
		kev      int
		severity string
		conf     string
		uid      string
	}{
		{"apache exact", Instance{IP: ip, Port: 80, CPE: "apache:http_server:2.4.49", Product: "Apache httpd", Version: "2.4.49"},
			3, 2, "Critical", ConfidenceHigh, "172.30.0.25:80:apache:http_server:2.4.49"},
		{"apache newer", Instance{IP: ip, Port: 80, CPE: "apache:http_server:2.4.52", Version: "2.4.52"}, 0, 0, "", "", ""},
		{"apache no cpe, product name only", Instance{IP: ip, Port: 8080, Product: "Apache httpd", Version: "2.4.50"},
			2, 1, "Critical", ConfidenceHigh, "172.30.0.25:8080:apache:http_server:2.4.50"},
		{"apache distro", Instance{IP: ip, Port: 80, CPE: "apache:http_server:2.4.49", Version: "2.4.49", Banner: "Apache/2.4.49 (Debian)"},
			3, 2, "Low", ConfidenceLow, ""},
		{"openssh 7.4 lab banner", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh:7.4", Product: "OpenSSH", Version: "7.4"},
			2, 0, "Critical", ConfidenceHigh, "172.30.0.25:22:openbsd:openssh:7.4"},
		{"openssh debian", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh:7.4p1", Version: "7.4p1 Debian 10+deb9u7"},
			2, 0, "Low", ConfidenceLow, ""},
		{"openssh 7.1p1", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh", Version: "7.1p1"}, 3, 0, "", "", ""},
		{"no version", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh", Product: "OpenSSH"}, 0, 0, "", "", ""},
		{"untracked", Instance{IP: ip, Port: 9, CPE: "acme:widget:1.0", Product: "Widget", Version: "1.0"}, 0, 0, "", "", ""},
		{"alias cpe", Instance{IP: ip, Port: 80, CPE: "apache:httpd:2.4.49", Version: ""}, 3, 2, "", "", ""},
		{"vsftpd nmap cpe alias", Instance{IP: ip, Port: 21, CPE: "vsftpd:vsftpd:3.0.2", Product: "vsftpd", Version: "3.0.2"},
			1, 0, "Medium", ConfidenceHigh, "172.30.0.25:21:beasts:vsftpd:3.0.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.Match(tt.in)
			if tt.want == 0 {
				if got != nil {
					t.Fatalf("want no match, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want %d hits, got no match", tt.want)
			}
			if len(got.Hits) != tt.want {
				t.Errorf("hits = %d, want %d (%v)", len(got.Hits), tt.want, got.Hits)
			}
			if got.KEV != tt.kev {
				t.Errorf("KEV hits = %d, want %d", got.KEV, tt.kev)
			}
			if tt.severity != "" && got.Severity != tt.severity {
				t.Errorf("severity = %q, want %q", got.Severity, tt.severity)
			}
			if tt.conf != "" && got.Confidence != tt.conf {
				t.Errorf("confidence = %q, want %q", got.Confidence, tt.conf)
			}
			if tt.uid != "" && got.UID() != tt.uid {
				t.Errorf("uid = %q, want %q", got.UID(), tt.uid)
			}
			for i := 1; i < len(got.Hits); i++ {
				if got.Hits[i].CVSS > got.Hits[i-1].CVSS {
					t.Errorf("hits not sorted by CVSS: %v", got.Hits)
				}
			}
		})
	}
}

// TestEmbeddedData checks the committed dataset loads and knows the lab's
// demo versions (L1 announces Apache/2.4.49 and OpenSSH_7.4).
func TestEmbeddedData(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	ap := m.Match(Instance{CPE: "apache:http_server:2.4.49", Product: "Apache httpd", Version: "2.4.49"})
	if ap == nil || ap.KEV == 0 || !hasHit(ap, "CVE-2021-41773") {
		t.Fatalf("Apache 2.4.49 should match CVE-2021-41773 (KEV), got %+v", ap)
	}
	if ap.Severity != "Critical" {
		t.Errorf("Apache 2.4.49 severity = %s, want Critical", ap.Severity)
	}
	ssh := m.Match(Instance{CPE: "openbsd:openssh:7.4", Product: "OpenSSH", Version: "7.4"})
	if ssh == nil || !hasHit(ssh, "CVE-2018-15473") {
		t.Fatalf("OpenSSH 7.4 should match CVE-2018-15473, got %+v", ssh)
	}
	t.Logf("%s %s: %d CVEs, %s %s: %d CVEs", ap.Name, ap.Version, len(ap.Hits), ssh.Name, ssh.Version, len(ssh.Hits))
}

func hasHit(m *Match, id string) bool {
	for _, h := range m.Hits {
		if strings.EqualFold(h.ID, id) {
			return true
		}
	}
	return false
}

func TestReport(t *testing.T) {
	m := Match{
		IP: netip.MustParseAddr("172.30.0.21"), Port: 80, Proto: "tcp",
		Name: "Apache httpd", Version: "2.4.49", CPE: "apache:http_server", Confidence: ConfidenceHigh,
		Hits: []Hit{
			{ID: "CVE-2021-41773", CVSS: 7.5, EPSS: 0.91, KEV: true},
			{ID: "CVE-2021-40438", CVSS: 5.1, EPSS: 0.23},
			{ID: "CVE-2021-41524"},
		},
	}
	for _, tc := range []struct {
		name              string
		distro            bool
		confidence        string
		scannerConfidence int
		severities        []string
	}{
		{"upstream", false, ConfidenceHigh, 1, []string{"Critical", "Medium", "Info"}},
		{"distribution", true, ConfidenceLow, 6, []string{"Low", "Low", "Info"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m.Distro, m.Confidence = tc.distro, tc.confidence
			b, err := Report([]Match{m}, time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Findings []genericFinding `json:"findings"`
			}
			if err := json.Unmarshal(b, &doc); err != nil || len(doc.Findings) != 3 {
				t.Fatalf("report: %s (%v)", b, err)
			}
			for i, f := range doc.Findings {
				h := m.Hits[i]
				wantTitle := h.ID + " in Apache httpd 2.4.49 (172.30.0.21:80/tcp)"
				wantUID := "172.30.0.21:80:apache:http_server:2.4.49:tcp:" + h.ID
				if f.Title != wantTitle || f.UniqueIDFromTool != wantUID || !slices.Equal(f.VulnerabilityIDs, []string{h.ID}) {
					t.Errorf("finding %d identity: %+v", i, f)
				}
				if f.Severity != tc.severities[i] || f.CVSSv3Score != h.CVSS || f.EPSSScore != h.EPSS || f.KnownExploited != h.KEV {
					t.Errorf("finding %d scores: %+v", i, f)
				}
				if f.ScannerConfidence != tc.scannerConfidence || slices.Contains(f.Tags, TagDistroBuild) != tc.distro ||
					strings.Contains(f.Description, "fixes may be backported") != tc.distro ||
					!strings.Contains(f.Description, h.ID) || !strings.Contains(f.Description, m.CPE) {
					t.Errorf("finding %d evidence: %+v", i, f)
				}
				for _, other := range m.Hits {
					if other.ID != h.ID && strings.Contains(f.Description, other.ID) {
						t.Errorf("finding %s includes %s in its description", h.ID, other.ID)
					}
				}
			}
			if strings.Contains(string(b), `"service":`) {
				t.Error("finding has a service field: Dojo would not close it on reimport")
			}
		})
	}

	if empty, _ := Report(nil, time.Now()); string(empty) != `{"findings":[]}` {
		t.Errorf("empty report = %s", empty)
	}
}

func TestHashTracksFindingMetadata(t *testing.T) {
	matches := []Match{{Hits: []Hit{{ID: "CVE-2021-41773", CVSS: 7.5, EPSS: 0.2}}}}
	before := Hash(matches)
	matches[0].MatchedAt = time.Now()
	if Hash(matches) != before {
		t.Fatal("match timestamp changed the finding hash")
	}
	matches[0].Hits[0].EPSS = 0.9
	if Hash(matches) == before {
		t.Fatal("EPSS change was not reflected in the finding hash")
	}
}

func TestMatchAllDedupAndMultiProduct(t *testing.T) {
	m := NewMatcher(testDB(), Products())
	ip := netip.MustParseAddr("172.30.0.25")
	// Alias CPE from nmap + canonical tech from httpx on the same port → 1 match,
	// with distro detection preserved even if httpx came first.
	got := m.MatchAll([]Instance{
		{IP: ip, Port: 80, Proto: "tcp", Product: "Apache HTTP Server:2.4.49"},
		{IP: ip, Port: 80, Proto: "tcp", CPE: "apache:httpd:2.4.49", Product: "Apache httpd", Version: "2.4.49", Banner: "Apache/2.4.49 (Debian)"},
		{IP: ip, Port: 22, Proto: "tcp", CPE: "openbsd:openssh:7.4", Product: "OpenSSH", Version: "7.4"},
	})
	if len(got) != 2 {
		t.Fatalf("got %d matches, want 2: %+v", len(got), got)
	}
	if got[0].CPE != "apache:http_server" || got[0].UID() != "172.30.0.25:80:apache:http_server:2.4.49" {
		t.Errorf("canonical CPE/UID = %q / %q", got[0].CPE, got[0].UID())
	}
	if !got[0].Distro || got[0].Severity != "Low" {
		t.Errorf("distro cap not preserved across dedup: %+v", got[0])
	}
}
