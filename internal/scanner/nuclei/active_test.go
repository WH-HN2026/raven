package nuclei

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

func TestBuildActiveArgs(t *testing.T) {
	dirs := []string{"/opt/nuclei-templates/http/cves", "/opt/nuclei-templates/http/fuzzing"}

	t.Run("exact allowlisted argv", func(t *testing.T) {
		args, err := BuildActiveArgs(
			scanner.Options{RateLimit: 50, Tags: []string{"dos", "rce"}, Signatures: []string{"/tmp/custom.yaml"}},
			dirs, 5, 0, 30,
		)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"-silent", "-jsonl", "-omit-raw", "-omit-template",
			"-no-interactsh", "-disable-update-check", "-duc", "-auth=false",
			"-no-httpx", "-disable-redirects",
			"-rl", "50",
			"-timeout", "5",
			"-retries", "0",
			"-mhe", "30",
			"-tags", ActiveTags,
			"-etags", ActiveExcludedTags,
			"-exclude-type", ActiveExcludedTypes,
			"-type", "http",
			"-t", "/opt/nuclei-templates/http/cves",
			"-t", "/opt/nuclei-templates/http/fuzzing",
		}
		if !slices.Equal(args, want) {
			t.Fatalf("argv mismatch:\ngot:  %q\nwant: %q", args, want)
		}
		// Never allow update flags, custom signatures, or excluded tags in -tags.
		for _, forbidden := range []string{"-update", "-ut", "-update-templates", "-dast", "/tmp/custom.yaml"} {
			if slices.Contains(args, forbidden) {
				t.Errorf("forbidden arg %q present in %v", forbidden, args)
			}
		}
		etags := strings.Split(ActiveExcludedTags, ",")
		for _, mustExclude := range []string{"dos", "bruteforce", "default-login", "credential", "oast", "rce", "deserialization", "file-upload"} {
			if !slices.Contains(etags, mustExclude) {
				t.Errorf("missing mandatory excluded tag %q", mustExclude)
			}
		}
	})

	for _, tc := range []struct {
		name         string
		rate         int
		dirs         []string
		timeoutSec   int
		retries      int
		maxHostError int
	}{
		{name: "zero rate", rate: 0, dirs: dirs, timeoutSec: 5, retries: 0, maxHostError: 30},
		{name: "negative rate", rate: -1, dirs: dirs, timeoutSec: 5, retries: 0, maxHostError: 30},
		{name: "zero timeout", rate: 10, dirs: dirs, timeoutSec: 0, retries: 0, maxHostError: 30},
		{name: "retries too high", rate: 10, dirs: dirs, timeoutSec: 5, retries: 2, maxHostError: 30},
		{name: "negative retries", rate: 10, dirs: dirs, timeoutSec: 5, retries: -1, maxHostError: 30},
		{name: "zero mhe", rate: 10, dirs: dirs, timeoutSec: 5, retries: 0, maxHostError: 0},
		{name: "no dirs", rate: 10, dirs: nil, timeoutSec: 5, retries: 0, maxHostError: 30},
		{name: "empty dir", rate: 10, dirs: []string{""}, timeoutSec: 5, retries: 0, maxHostError: 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := BuildActiveArgs(scanner.Options{RateLimit: tc.rate}, tc.dirs, tc.timeoutSec, tc.retries, tc.maxHostError); err == nil {
				t.Fatalf("expected error, got args %v", got)
			}
		})
	}
}

func makeFakeTemplateTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range ActiveTemplateDirs {
		if err := os.MkdirAll(filepath.Join(root, rel), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestActiveScannerRunAndScope(t *testing.T) {
	tplRoot := makeFakeTemplateTree(t)
	fixtureRaw, err := os.ReadFile("testdata/lab-active.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	// Reject out-of-scope URL before running binary.
	ip17 := netip.MustParseAddr("172.30.0.17")
	ip21 := netip.MustParseAddr("172.30.0.21")
	s := NewActive(ActiveConfig{Binary: "must-not-run", TemplatesDir: tplRoot})
	if s.Name() != "nuclei_active" || s.DojoScanType() != "Nuclei Scan" {
		t.Fatalf("unexpected identity: name=%q scanType=%q", s.Name(), s.DojoScanType())
	}
	if _, err := s.Run(context.Background(), scanner.Input{
		IPs:  []netip.Addr{ip17},
		URLs: []string{"http://172.30.0.21:8080"},
	}, scanner.Options{RateLimit: 25}); err == nil || !strings.Contains(err.Error(), "batch IP") {
		t.Fatalf("accepted URL outside batch: %v", err)
	}

	// Run with fake nuclei binary and verify argv, env, stdin, and parsed output.
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.txt")
	stdinFile := filepath.Join(dir, "stdin.txt")
	fixtureCopy := filepath.Join(dir, "fixture.jsonl")
	if err := os.WriteFile(fixtureCopy, fixtureRaw, 0600); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(dir, "fake-nuclei")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > '" + argsFile + "'\n" +
		"cat > '" + stdinFile + "'\n" +
		"cat '" + fixtureCopy + "'\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	active := NewActive(ActiveConfig{
		Binary:        fakeBin,
		TemplatesDir:  tplRoot,
		PerURLTimeout: 10 * time.Second,
		TimeoutSec:    5,
		Retries:       1,
		MaxHostError:  20,
	})
	ip25 := netip.MustParseAddr("172.30.0.25")
	res, err := active.Run(context.Background(), scanner.Input{
		IPs:  []netip.Addr{ip17, ip21, ip25},
		URLs: []string{"http://172.30.0.17:80", "http://172.30.0.21:8080", "http://172.30.0.25:80"},
	}, scanner.Options{RateLimit: 40})
	if err != nil {
		t.Fatalf("ActiveScanner.Run: %v", err)
	}
	if len(res.Observations) != 4 {
		t.Fatalf("got %d observations, want 4", len(res.Observations))
	}
	if len(bytes.TrimSpace(res.PerIP(ip17))) == 0 || len(bytes.TrimSpace(res.PerIP(ip21))) == 0 || len(bytes.TrimSpace(res.PerIP(ip25))) == 0 {
		t.Fatalf("missing PerIP records: 17=%d 21=%d 25=%d", len(res.PerIP(ip17)), len(res.PerIP(ip21)), len(res.PerIP(ip25)))
	}
	if n := bytes.Count(bytes.TrimSpace(res.PerIP(ip21)), []byte("\n")) + 1; n != 2 {
		t.Fatalf("expected 2 records for Tomcat (.21), got %d", n)
	}

	argBytes, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(argBytes)), "\n")
	for _, want := range []string{"-no-interactsh", "-duc", "-disable-redirects", "-rl", "40", "-timeout", "5", "-retries", "1", "-mhe", "20", "-tags", ActiveTags, "-etags", ActiveExcludedTags} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %q in argv %v", want, args)
		}
	}
	stdinBytes, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(stdinBytes)) != "http://172.30.0.17:80\nhttp://172.30.0.21:8080\nhttp://172.30.0.25:80" {
		t.Fatalf("unexpected stdin: %q", string(stdinBytes))
	}
}

func TestActiveScannerPerURLTimeoutKillsProcess(t *testing.T) {
	tplRoot := makeFakeTemplateTree(t)
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "slow-nuclei")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	s := NewActive(ActiveConfig{
		Binary:        fakeBin,
		TemplatesDir:  tplRoot,
		PerURLTimeout: 100 * time.Millisecond,
	})
	ip := netip.MustParseAddr("172.30.0.17")
	start := time.Now()
	_, err := s.Run(context.Background(), scanner.Input{
		IPs:  []netip.Addr{ip},
		URLs: []string{"http://172.30.0.17:80"},
	}, scanner.Options{RateLimit: 10})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("timeout did not kill subprocess promptly: took %v", elapsed)
	}
}

func TestParseLabActiveFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/lab-active.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Observations) != 4 {
		t.Fatalf("got %d observations, want 4", len(res.Observations))
	}
	// Verify every record survives PerIP filtering, including active probes with
	// special characters in matched-at (tomcat-stacktraces, waf-fuzz).
	for _, tc := range []struct {
		ip      string
		wantIDs []string
	}{
		{"172.30.0.17", []string{"wp-user-enum"}},
		{"172.30.0.21", []string{"tomcat-stacktraces", "waf-fuzz"}},
		{"172.30.0.25", []string{"apache-detect"}},
	} {
		ip := netip.MustParseAddr(tc.ip)
		replayed, err := Parse(res.PerIP(ip))
		if err != nil {
			t.Fatalf("%s replay: %v", tc.ip, err)
		}
		var gotIDs []string
		for _, o := range replayed.Observations {
			if o.Match != nil {
				gotIDs = append(gotIDs, o.Match.TemplateID)
			}
		}
		if !slices.Equal(gotIDs, tc.wantIDs) {
			t.Fatalf("%s template IDs = %v, want %v", tc.ip, gotIDs, tc.wantIDs)
		}
	}
}
