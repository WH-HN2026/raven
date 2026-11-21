package httpapi

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseFindingFilter(t *testing.T) {
	for _, tc := range []struct {
		query    string
		sev      []string
		active   *bool
		ip, q    string
		scanner  string
		errorMsg bool
	}{
		{query: ""},
		{query: "severity=high&severity=Critical,low", sev: []string{"High", "Critical", "Low"}},
		{query: "active=false", active: new(false)},
		{query: "ip=10.0.0.5", ip: "10.0.0.5/32"},
		{query: "ip=10.0.0.0/24", ip: "10.0.0.0/24"},
		{query: "ip=::ffff:10.0.0.5", ip: "10.0.0.5/32"},
		{query: "q=+port+&scanner=nmap", q: "port", scanner: "nmap"},
		{query: "severity=bogus", errorMsg: true},
		{query: "active=maybe", errorMsg: true},
		{query: "ip=not-an-ip", errorMsg: true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			f, msg := parseFindingFilter(httptest.NewRequest("GET", "/api/findings?"+tc.query, nil))
			if (msg != "") != tc.errorMsg {
				t.Fatalf("msg = %q", msg)
			}
			if tc.errorMsg {
				return
			}
			ip := ""
			if f.IP != nil {
				ip = f.IP.String()
			}
			if !reflect.DeepEqual(f.Severities, tc.sev) || !reflect.DeepEqual(f.Active, tc.active) ||
				ip != tc.ip || f.Q != tc.q || f.Scanner != tc.scanner {
				t.Fatalf("filter = %+v (ip %s)", f, ip)
			}
		})
	}
}
