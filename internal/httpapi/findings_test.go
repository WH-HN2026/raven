package httpapi

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseFindingFilter(t *testing.T) {
	id42 := int64(42)
	for _, tc := range []struct {
		query        string
		sev          []string
		active       *bool
		verified     *bool
		falseP       *bool
		outOfScope   *bool
		riskAccepted *bool
		duplicate    *bool
		isMitigated  *bool
		assetID      *int64
		asset        string
		ip, q        string
		scanner      string
		errorMsg     bool
	}{
		{query: ""},
		{query: "severity=high&severity=Critical,low", sev: []string{"High", "Critical", "Low"}},
		{query: "active=false", active: new(false)},
		{query: "verified=true&false_p=false&out_of_scope=true&risk_accepted=false&duplicate=true&is_mitigated=false",
			verified: new(true), falseP: new(false), outOfScope: new(true),
			riskAccepted: new(false), duplicate: new(true), isMitigated: new(false)},
		{query: "asset_id=42&asset=web.lab", assetID: &id42, asset: "web.lab"},
		{query: "ip=10.0.0.5", ip: "10.0.0.5/32"},
		{query: "ip=10.0.0.0/24", ip: "10.0.0.0/24"},
		{query: "ip=::ffff:10.0.0.5", ip: "10.0.0.5/32"},
		{query: "q=+port+&scanner=nmap", q: "port", scanner: "nmap"},
		{query: "severity=bogus", errorMsg: true},
		{query: "active=maybe", errorMsg: true},
		{query: "verified=nope", errorMsg: true},
		{query: "false_p=2", errorMsg: true},
		{query: "out_of_scope=x", errorMsg: true},
		{query: "risk_accepted=x", errorMsg: true},
		{query: "duplicate=x", errorMsg: true},
		{query: "is_mitigated=x", errorMsg: true},
		{query: "asset_id=0", errorMsg: true},
		{query: "asset_id=abc", errorMsg: true},
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
			if !reflect.DeepEqual(f.Severities, tc.sev) ||
				!reflect.DeepEqual(f.Active, tc.active) ||
				!reflect.DeepEqual(f.Verified, tc.verified) ||
				!reflect.DeepEqual(f.FalseP, tc.falseP) ||
				!reflect.DeepEqual(f.OutOfScope, tc.outOfScope) ||
				!reflect.DeepEqual(f.RiskAccepted, tc.riskAccepted) ||
				!reflect.DeepEqual(f.Duplicate, tc.duplicate) ||
				!reflect.DeepEqual(f.IsMitigated, tc.isMitigated) ||
				!reflect.DeepEqual(f.AssetID, tc.assetID) ||
				f.Asset != tc.asset ||
				ip != tc.ip || f.Q != tc.q || f.Scanner != tc.scanner {
				t.Fatalf("filter = %+v (ip %s)", f, ip)
			}
		})
	}
}
