package changes

import (
	"net/netip"
	"reflect"
	"testing"
)

func msp(v int) *int { return &v }

// V7: "slow" and "http_unresponsive" change fields.
func TestDiffResponseTime(t *testing.T) {
	up := map[netip.Addr]bool{ipA: true}
	web := func(ms *int) Fingerprint {
		return Fingerprint{Name: "http", Product: "Traefik", Title: "RAVEN vlab Proxy", ResponseMS: ms}
	}
	silent := Fingerprint{Name: "http", Product: "Traefik"} // port open, no httpx answer
	tests := []struct {
		name string
		a, b Fingerprint
		bWeb bool
		want []string
	}{
		{"same speed", web(msp(5)), web(msp(6)), true, nil},
		{"latency toxic: over the fixed threshold", web(msp(5)), web(msp(3012)), true, []string{FieldSlow}},
		{"3x the previous run and over the floor", web(msp(200)), web(msp(700)), true, []string{FieldSlow}},
		{"3x but tiny", web(msp(1)), web(msp(4)), true, nil},
		{"slow in both runs is not a change", web(msp(3000)), web(msp(3100)), true, nil},
		{"unknown time in a: only the fixed threshold", web(nil), web(msp(1500)), true, nil},
		{"unknown time in b", web(msp(5)), web(nil), true, nil},
		{"timeout toxic: no HTTP answer, port open", web(msp(5)), silent, false, []string{"title", FieldHTTPUnresponsive}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := snap(up, svc{ip: ipA, port: 80, fp: tt.a, http: true})
			b := snap(up, svc{ip: ipA, port: 80, fp: tt.b, http: tt.bWeb})
			got := summarize(Diff(a, b)).changed["10.0.0.1:80"]
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fields = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildSnapshotResponseMS(t *testing.T) {
	obs := []ObsRow{{IP: ipA, Port: -1, Up: true}, {IP: ipA, Port: 80, Up: true}}
	http := []HTTPRow{
		{IP: ipA, Port: 80, Title: "a", ResponseMS: msp(12)},
		{IP: ipA, Port: 80, Title: "b", ResponseMS: msp(3004)},
		{IP: ipA, Port: 80, Title: "c"},
	}
	s := BuildSnapshot(obs, nil, http)
	if got := s.Services[SvcKey{ipA, 80}].FP.ResponseMS; got == nil || *got != 3004 {
		t.Fatalf("ResponseMS = %v, want the slowest URL (3004)", got)
	}
}

func TestCountField(t *testing.T) {
	list := []ServiceChange{
		{Fields: []string{"title", FieldHTTPUnresponsive}},
		{Fields: []string{FieldSlow}},
		{Fields: []string{"version"}},
	}
	if n := countField(list, FieldSlow); n != 1 {
		t.Errorf("slow = %d", n)
	}
	if n := countField(list, FieldHTTPUnresponsive); n != 1 {
		t.Errorf("unresponsive = %d", n)
	}
}
