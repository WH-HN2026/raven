package pipeline

import (
	"net/netip"
	"testing"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

func TestCountHTTPStats(t *testing.T) {
	ip := netip.MustParseAddr("10.77.2.10")
	rows := []gen.RunHTTPResponsesRow{
		{Ip: ip, Port: 80, CurHttp: true, CurMs: 3012, PrevHttp: true, PrevMs: 4},    // latency toxic → slow
		{Ip: ip, Port: 8080, CurHttp: true, CurMs: 3, PrevHttp: true, PrevMs: 2},     // normal
		{Ip: ip, Port: 8666, CurHttp: false, CurMs: -1, PrevHttp: true, PrevMs: 5},   // timeout toxic → unresponsive
		{Ip: ip, Port: 8474, CurHttp: true, CurMs: 700, PrevHttp: true, PrevMs: 200}, // 3x → slow
		{Ip: ip, Port: 81, CurHttp: true, CurMs: 2500, PrevHttp: false, PrevMs: -1},  // new, over the threshold → slow
		{Ip: ip, Port: 443, CurHttp: true, CurMs: -1, PrevHttp: true, PrevMs: 5},     // unknown time
		{Ip: ip, Port: 3000, CurHttp: false, CurMs: -1, PrevHttp: false, PrevMs: -1}, // never answered
	}
	got := CountHTTPStats(rows)
	if want := (HTTPStats{Slow: 3, Unresponsive: 1}); got != want {
		t.Fatalf("CountHTTPStats = %+v, want %+v", got, want)
	}
}
