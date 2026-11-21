package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestParseHostFilter(t *testing.T) {
	for _, tc := range []struct {
		query        string
		state        string
		port         int // -1 = nil
		tech, tag, q string
		errorMsg     bool
	}{
		{query: "", port: -1},
		{query: "state=unstable&port=443&tech=+WordPress+&tag=dmz&q=10.0.", state: "unstable", port: 443, tech: "WordPress", tag: "dmz", q: "10.0."},
		{query: "port=0", port: 0},
		{query: "state=up", errorMsg: true},
		{query: "port=http", errorMsg: true},
		{query: "port=70000", errorMsg: true},
		{query: "port=-1", errorMsg: true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			f, msg := parseHostFilter(httptest.NewRequest("GET", "/api/hosts?"+tc.query, nil))
			if (msg != "") != tc.errorMsg {
				t.Fatalf("msg = %q", msg)
			}
			if tc.errorMsg {
				return
			}
			port := -1
			if f.Port != nil {
				port = *f.Port
			}
			if f.State != tc.state || port != tc.port || f.Tech != tc.tech || f.Tag != tc.tag || f.Q != tc.q {
				t.Fatalf("filter = %+v", f)
			}
		})
	}
}
