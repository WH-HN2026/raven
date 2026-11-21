package httpx

import (
	"os"
	"testing"

	"github.com/WH-HN2026/raven/internal/scanner"
)

func TestResponseMS(t *testing.T) {
	for in, want := range map[string]int{
		"545.464µs": 1, "4.070795ms": 4, "3.004211873s": 3004, "1m0.5s": 60500, "0s": 0,
	} {
		if got := responseMS(in); got == nil || *got != want {
			t.Errorf("responseMS(%q) = %v, want %d", in, got, want)
		}
	}
	for _, in := range []string{"", "fast", "-1s"} {
		if got := responseMS(in); got != nil {
			t.Errorf("responseMS(%q) = %d, want nil", in, *got)
		}
	}
}

func TestSlow(t *testing.T) {
	for _, tt := range []struct {
		ms, prev int
		want     bool
	}{
		{3004, -1, true}, // fixed threshold without history
		{2000, 2500, true},
		{1999, -1, false},
		{1999, 1000, false},
		{600, 200, true}, // 3x and over the floor
		{599, 199, true},
		{499, 100, false}, // 3x but under the floor
		{4, 1, false},
		{-1, 5, false}, // unknown
	} {
		if got := Slow(tt.ms, tt.prev); got != tt.want {
			t.Errorf("Slow(%d, %d) = %v, want %v", tt.ms, tt.prev, got, tt.want)
		}
	}
}

// Recorded httpx lines carry `time`; it becomes HTTPInfo.ResponseMS.
func TestParseResponseTime(t *testing.T) {
	for file, want := range map[string]map[string]int{
		"testdata/nginx.jsonl": {
			"http://172.21.0.2:80": 1, "http://172.21.0.3:80": 1, "https://raven-s7-nginx:443": 4,
		},
		"testdata/toxic-latency.jsonl": {"http://10.77.2.10:80": 3043, "http://10.77.2.11:8666": 3043},
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, o := range res.Observations {
			if o.Kind == scanner.ObsHTTP {
				if o.HTTP.ResponseMS == nil {
					t.Fatalf("%s %s: no response time", file, o.URL)
				}
				got[o.URL] = *o.HTTP.ResponseMS
			}
		}
		for url, ms := range want {
			// Recorded network timings: within 10% of the expected value, or ±1 ms.
			if d := got[url] - ms; d < -ms/10-1 || d > ms/10+1 {
				t.Errorf("%s %s: %d ms, want ~%d", file, url, got[url], ms)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want URLs %v", file, got, want)
		}
	}
}
