package hosts

import (
	"strings"
	"testing"
)

func TestSplitTechVersion(t *testing.T) {
	for _, tc := range []struct {
		in      string
		tech    string
		version string
	}{
		{"WordPress:6.4.2", "WordPress", "6.4.2"},
		{"Nginx:1.25.3", "Nginx", "1.25.3"},
		{"Apache HTTP Server:2.4.49", "Apache HTTP Server", "2.4.49"},
		{"WordPress", "WordPress", ""},
		{"HTTP:alt", "HTTP:alt", ""},
		{"  PHP:8.2.15 ", "PHP", "8.2.15"},
		{"", "", ""},
	} {
		t.Run(tc.in, func(t *testing.T) {
			tech, ver := SplitTechVersion(tc.in)
			if tech != tc.tech || ver != tc.version {
				t.Fatalf("SplitTechVersion(%q) = (%q, %q), want (%q, %q)", tc.in, tech, ver, tc.tech, tc.version)
			}
		})
	}
}

func TestServiceOrderBy(t *testing.T) {
	for _, tc := range []struct {
		sort, order string
		wantPrefix  string
	}{
		{"", "", "s.ip ASC"},
		{"ip", "desc", "s.ip DESC"},
		{"port", "asc", "s.port ASC"},
		{"port", "desc", "s.port DESC"},
		{"product", "asc", "lower(" + effProductExpr + ") ASC"},
		{"version", "desc", "lower(" + effVersionExpr + ") DESC"},
		{"state", "desc", "s.state DESC"},
		{"first_seen", "asc", "s.first_seen ASC"},
		{"last_seen", "desc", "s.last_seen DESC"},
		{"bogus", "desc", "s.ip DESC"},
	} {
		t.Run(tc.sort+"/"+tc.order, func(t *testing.T) {
			got := serviceOrderBy(tc.sort, tc.order)
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Fatalf("serviceOrderBy(%q, %q) = %q, want prefix %q", tc.sort, tc.order, got, tc.wantPrefix)
			}
		})
	}
}
