package cve

import (
	"net/netip"
	"testing"
)

func TestInstancesFromWPScanAndMatch(t *testing.T) {
	ip := netip.MustParseAddr("172.30.0.17")

	report := []byte(`{
		"target_url": "http://172.30.0.17:80/",
		"target_ip": "172.30.0.17",
		"version": {"number": "4.7.5", "status": "insecure"},
		"main_theme": {"slug": "twentytwentyfive", "version": {"number": "1.0"}},
		"plugins": {
			"akismet": {"slug": "akismet", "version": {"number": "5.3.1"}},
			"jquery": {"slug": "jquery", "version": {"number": "3.4.0"}}
		},
		"themes": {
			"twentytwentyfour": {"slug": "twentytwentyfour", "version": {"number": "1.2"}}
		}
	}`)

	instances := InstancesFromWPScanJSON(ip, 80, "tcp", report)
	if len(instances) != 2 {
		t.Fatalf("got %d instances (%+v), want 2 (WordPress core + tracked jquery)", len(instances), instances)
	}
	if instances[0].CPE != "wordpress:wordpress:4.7.5" || instances[0].Version != "4.7.5" {
		t.Errorf("instance[0] = %+v, want wordpress:wordpress:4.7.5", instances[0])
	}
	if instances[1].CPE != "jquery:jquery:3.4.0" || instances[1].Version != "3.4.0" {
		t.Errorf("instance[1] = %+v, want jquery:jquery:3.4.0", instances[1])
	}

	// Verify matching against the committed offline CVE dataset.
	m, err := Default()
	if err != nil {
		t.Fatalf("cve.Default: %v", err)
	}
	matches := m.MatchAll(instances)
	var foundWP bool
	for _, mt := range matches {
		if mt.CPE == "wordpress:wordpress" && mt.Version == "4.7.5" && len(mt.Hits) > 0 {
			foundWP = true
		}
	}
	if !foundWP {
		t.Fatalf("expected WordPress 4.7.5 to match CVEs in committed dataset, got %+v", matches)
	}

	// Empty or invalid reports emit no instances.
	if got := InstancesFromWPScanJSON(ip, 80, "tcp", nil); len(got) != 0 {
		t.Errorf("nil input = %+v, want empty", got)
	}
	if got := InstancesFromWPScanJSON(ip, 80, "tcp", []byte("not json")); len(got) != 0 {
		t.Errorf("invalid json = %+v, want empty", got)
	}
	if got := InstancesFromWPScanJSON(ip, 80, "tcp", []byte(`{"version":null,"plugins":{"akismet":{"slug":"akismet","version":{"number":"5.0"}}}}`)); len(got) != 0 {
		t.Errorf("untracked-only report = %+v, want empty", got)
	}
}
