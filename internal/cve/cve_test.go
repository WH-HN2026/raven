package cve

import (
	"net/netip"
	"strings"
	"testing"
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
		title    string
		severity string
		conf     string
		uid      string
	}{
		{"apache exact", Instance{IP: ip, Port: 80, CPE: "apache:http_server:2.4.49", Product: "Apache httpd", Version: "2.4.49"},
			3, "Apache httpd 2.4.49: 3 known CVEs (2 KEV)", "Critical", ConfidenceHigh, "172.30.0.25:80:apache:http_server:2.4.49"},
		{"apache newer", Instance{IP: ip, Port: 80, CPE: "apache:http_server:2.4.52", Version: "2.4.52"}, 0, "", "", "", ""},
		{"apache no cpe, product name only", Instance{IP: ip, Port: 8080, Product: "Apache httpd", Version: "2.4.50"},
			2, "Apache httpd 2.4.50: 2 known CVEs (1 KEV)", "Critical", ConfidenceHigh, "172.30.0.25:8080:apache:http_server:2.4.50"},
		{"apache distro", Instance{IP: ip, Port: 80, CPE: "apache:http_server:2.4.49", Version: "2.4.49", Banner: "Apache/2.4.49 (Debian)"},
			3, "", "Low", ConfidenceLow, ""},
		{"openssh 7.4 lab banner", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh:7.4", Product: "OpenSSH", Version: "7.4"},
			2, "OpenSSH 7.4: 2 known CVEs (0 KEV)", "Critical", ConfidenceHigh, "172.30.0.25:22:openbsd:openssh:7.4"},
		{"openssh debian", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh:7.4p1", Version: "7.4p1 Debian 10+deb9u7"},
			2, "OpenSSH 7.4p1: 2 known CVEs (0 KEV)", "Low", ConfidenceLow, ""},
		{"openssh 7.1p1", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh", Version: "7.1p1"}, 3, "", "", "", ""},
		{"no version", Instance{IP: ip, Port: 22, CPE: "openbsd:openssh", Product: "OpenSSH"}, 0, "", "", "", ""},
		{"untracked", Instance{IP: ip, Port: 9, CPE: "acme:widget:1.0", Product: "Widget", Version: "1.0"}, 0, "", "", "", ""},
		{"alias cpe", Instance{IP: ip, Port: 80, CPE: "apache:httpd:2.4.49", Version: ""}, 3, "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.Match(tt.in)
			if tt.want == 0 {
				if got != nil {
					t.Fatalf("want no match, got %s", got.Title())
				}
				return
			}
			if got == nil {
				t.Fatalf("want %d hits, got no match", tt.want)
			}
			if len(got.Hits) != tt.want {
				t.Errorf("hits = %d, want %d (%v)", len(got.Hits), tt.want, got.Hits)
			}
			if tt.title != "" && got.Title() != tt.title {
				t.Errorf("title = %q, want %q", got.Title(), tt.title)
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
	t.Logf("%s; %s", ap.Title(), ssh.Title())
}

func hasHit(m *Match, id string) bool {
	for _, h := range m.Hits {
		if strings.EqualFold(h.ID, id) {
			return true
		}
	}
	return false
}
