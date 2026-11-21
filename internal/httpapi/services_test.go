package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestParseServiceListFilter(t *testing.T) {
	for _, tc := range []struct {
		query                     string
		port                      int // -1 = nil
		proto, state, ip          string
		product, tech, version, q string
		sort, order               string
		errorMsg                  bool
	}{
		{query: "", port: -1},
		{
			query:   "port=443&proto=TCP&state=open&ip=10.0.0.0/24&product=nginx&technology=WordPress&version=1.25&q=lab&sort=port&order=desc",
			port:    443,
			proto:   "tcp",
			state:   "open",
			ip:      "10.0.0.0/24",
			product: "nginx",
			tech:    "WordPress",
			version: "1.25",
			q:       "lab",
			sort:    "port",
			order:   "desc",
		},
		{
			query: "protocol=udp&tech=Tomcat&ip=10.1.2.3&sort=last_seen&order=asc",
			port:  -1,
			proto: "udp",
			tech:  "Tomcat",
			ip:    "10.1.2.3/32",
			sort:  "last_seen",
			order: "asc",
		},
		{query: "port=0", port: 0},
		{query: "port=70000", errorMsg: true},
		{query: "port=-1", errorMsg: true},
		{query: "port=http", errorMsg: true},
		{query: "proto=sctp", errorMsg: true},
		{query: "state=active", errorMsg: true},
		{query: "ip=not-an-ip", errorMsg: true},
		{query: "sort=banner", errorMsg: true},
		{query: "order=up", errorMsg: true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			f, msg := parseServiceListFilter(httptest.NewRequest("GET", "/api/services?"+tc.query, nil))
			if (msg != "") != tc.errorMsg {
				t.Fatalf("msg = %q, wantErr=%v", msg, tc.errorMsg)
			}
			if tc.errorMsg {
				return
			}
			port := -1
			if f.Port != nil {
				port = *f.Port
			}
			ip := ""
			if f.IP != nil {
				ip = f.IP.String()
			}
			if port != tc.port || f.Proto != tc.proto || f.State != tc.state || ip != tc.ip ||
				f.Product != tc.product || f.Technology != tc.tech || f.Version != tc.version ||
				f.Q != tc.q || f.Sort != tc.sort || f.Order != tc.order {
				t.Fatalf("filter = %+v (port=%d ip=%s)", f, port, ip)
			}
		})
	}
}

func TestParseTechnologyFilter(t *testing.T) {
	for _, tc := range []struct {
		query       string
		state, q    string
		sort, order string
		errorMsg    bool
	}{
		{query: ""},
		{query: "state=all&q=word&sort=cves&order=desc", state: "all", q: "word", sort: "cves", order: "desc"},
		{query: "state=gone&sort=technology&order=asc", state: "gone", sort: "technology", order: "asc"},
		{query: "state=active", errorMsg: true},
		{query: "sort=ip", errorMsg: true},
		{query: "order=down", errorMsg: true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			f, msg := parseTechnologyFilter(httptest.NewRequest("GET", "/api/technologies?"+tc.query, nil))
			if (msg != "") != tc.errorMsg {
				t.Fatalf("msg = %q, wantErr=%v", msg, tc.errorMsg)
			}
			if tc.errorMsg {
				return
			}
			if f.State != tc.state || f.Q != tc.q || f.Sort != tc.sort || f.Order != tc.order {
				t.Fatalf("filter = %+v", f)
			}
		})
	}
}
