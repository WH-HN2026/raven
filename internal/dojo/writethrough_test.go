package dojo

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizePatch(t *testing.T) {
	open := FindingState{Active: true, Verified: true}
	accepted := FindingState{RiskAccepted: true}
	fp := FindingState{FalseP: true}
	tests := []struct {
		name    string
		cur     FindingState
		in      FindingPatch
		want    FindingPatch
		wantErr string
	}{
		{name: "empty", cur: open, in: FindingPatch{}, wantErr: "nothing to change"},
		{name: "severity normalized", cur: open, in: FindingPatch{Severity: wp("high")}, want: FindingPatch{Severity: wp("High")}},
		{name: "bad severity", cur: open, in: FindingPatch{Severity: wp("urgent")}, wantErr: "severity must be"},
		{name: "risk accept implies inactive", cur: open, in: FindingPatch{RiskAccepted: wp(true)},
			want: FindingPatch{RiskAccepted: wp(true), Active: wp(false)}},
		{name: "risk accept + explicit active", cur: open, in: FindingPatch{RiskAccepted: wp(true), Active: wp(true)},
			wantErr: "can't be risk accepted"},
		{name: "risk accept already inactive", cur: FindingState{}, in: FindingPatch{RiskAccepted: wp(true)},
			want: FindingPatch{RiskAccepted: wp(true)}},
		{name: "false positive clears active and verified", cur: open, in: FindingPatch{FalseP: wp(true)},
			want: FindingPatch{FalseP: wp(true), Active: wp(false), Verified: wp(false)}},
		{name: "false positive + verified", cur: open, in: FindingPatch{FalseP: wp(true), Verified: wp(true)},
			wantErr: "can't be verified"},
		{name: "verify a false positive", cur: fp, in: FindingPatch{Verified: wp(true)}, wantErr: "can't be verified"},
		{name: "reopen risk accepted", cur: accepted, in: FindingPatch{Active: wp(true)},
			want: FindingPatch{Active: wp(true), RiskAccepted: wp(false)}},
		{name: "reopen false positive", cur: fp, in: FindingPatch{Active: wp(true)},
			want: FindingPatch{Active: wp(true), FalseP: wp(false)}},
		{name: "activate a risk accepted explicitly kept", cur: accepted, in: FindingPatch{Active: wp(true), RiskAccepted: wp(true)},
			wantErr: "can't be risk accepted"},
		{name: "mitigate implies inactive", cur: open, in: FindingPatch{IsMitigated: wp(true)},
			want: FindingPatch{IsMitigated: wp(true), Active: wp(false)}},
		{name: "unaccept only", cur: accepted, in: FindingPatch{RiskAccepted: wp(false)},
			want: FindingPatch{RiskAccepted: wp(false)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePatch(tt.cur, tt.in)
			if tt.wantErr != "" {
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want ErrInvalid containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %s, want %s", fmtPatch(got), fmtPatch(tt.want))
			}
		})
	}
}

func fmtPatch(p FindingPatch) string {
	var parts []string
	b := func(n string, v *bool) {
		if v != nil {
			parts = append(parts, n+"="+map[bool]string{true: "true", false: "false"}[*v])
		}
	}
	if p.Severity != nil {
		parts = append(parts, "severity="+*p.Severity)
	}
	b("active", p.Active)
	b("verified", p.Verified)
	b("false_p", p.FalseP)
	b("risk_accepted", p.RiskAccepted)
	b("is_mitigated", p.IsMitigated)
	return "{" + strings.Join(parts, " ") + "}"
}

func TestMergeAssetTags(t *testing.T) {
	tests := []struct {
		name       string
		have, user []string
		want       []string
	}{
		{"adds prefixed user tags", []string{"raven", "host:web.lab"}, []string{"dmz", "prod"},
			[]string{"raven", "host:web.lab", "user:dmz", "user:prod"}},
		{"replaces old user tags", []string{"raven", "user:old", "tech:nginx", "User:Gone"}, []string{"new"},
			[]string{"raven", "tech:nginx", "user:new"}},
		{"no user tags removes only user tags", []string{"raven", "host:a", "panel:admin", "env:prod", "user:x", "set-in-dojo"}, nil,
			[]string{"raven", "host:a", "panel:admin", "env:prod", "set-in-dojo"}},
		{"dedupes", []string{"raven", "RAVEN"}, []string{"a", "a"}, []string{"raven", "user:a"}},
		{"empty asset", nil, []string{"x"}, []string{"user:x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeAssetTags(tt.have, tt.user)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			// RAVEN's own tags always survive.
			for _, h := range tt.have {
				l := strings.ToLower(h)
				if l == TagASI || strings.HasPrefix(l, "host:") || strings.HasPrefix(l, "tech:") ||
					strings.HasPrefix(l, "panel:") || strings.HasPrefix(l, "env:") {
					found := false
					for _, g := range got {
						found = found || strings.EqualFold(g, h)
					}
					if !found {
						t.Fatalf("RAVEN tag %q dropped: %v", h, got)
					}
				}
			}
		})
	}
}

func TestAssetDescription(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.5")
	if got, want := AssetDescription(HostAsset{IP: ip}), "Host 10.0.0.5 (managed by RAVEN)\n"; got != want {
		t.Fatalf("bare: %q", got)
	}
	got := AssetDescription(HostAsset{IP: ip, Owner: "web team", Criticality: "high", Notes: " behind WAF \n"})
	want := "Host 10.0.0.5 (managed by RAVEN)\n\n**Owner:** web team\n**Criticality:** high\n\nbehind WAF\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLazy(t *testing.T) {
	var nilLazy *Lazy
	if nilLazy.Get() != nil {
		t.Fatal("nil Lazy must return nil")
	}
	l := &Lazy{}
	if l.Get() != nil {
		t.Fatal("unset Lazy must return nil")
	}
	c := NewHTTPClient("http://x", "t")
	l.Set(c)
	if l.Get() != WriteClient(c) {
		t.Fatal("Get after Set")
	}
}

func wp[T any](v T) *T { return &v }
