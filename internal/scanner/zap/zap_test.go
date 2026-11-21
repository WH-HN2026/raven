package zap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

type apiCall struct {
	Path   string
	Query  url.Values
	APIKey string
}

type fakeZAP struct {
	mu           sync.Mutex
	calls        []apiCall
	spiderPolls  int
	ascanPolls   int
	passivePolls int
	scanners     []map[string]string
	xmlByOrigin  map[string]string
	failOrigin   string
	blockAscan   chan struct{}
}

func (f *fakeZAP) handler(wantKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("apikey") != "" {
			http.Error(w, "api key must not be in query string", http.StatusBadRequest)
			return
		}
		gotKey := r.Header.Get(apiKeyHeader)
		if gotKey != wantKey {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, apiCall{
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			APIKey: gotKey,
		})
		f.mu.Unlock()

		writeJSON := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}

		switch r.URL.Path {
		case "/JSON/core/action/newSession/":
			writeJSON(map[string]string{"Result": "OK"})
		case "/JSON/context/action/newContext/":
			writeJSON(map[string]string{"contextId": "1"})
		case "/JSON/context/action/includeInContext/":
			writeJSON(map[string]string{"Result": "OK"})
		case "/JSON/context/action/removeContext/":
			writeJSON(map[string]string{"Result": "OK"})
		case "/JSON/spider/action/setOptionMaxDuration/",
			"/JSON/spider/action/setOptionMaxDepth/",
			"/JSON/spider/action/setOptionThreadCount/",
			"/JSON/spider/action/stop/",
			"/JSON/ascan/action/addScanPolicy/",
			"/JSON/ascan/action/disableScanners/",
			"/JSON/ascan/action/removeScanPolicy/",
			"/JSON/ascan/action/setOptionThreadPerHost/",
			"/JSON/ascan/action/setOptionDelayInMs/",
			"/JSON/ascan/action/setOptionMaxRuleDurationInMins/",
			"/JSON/ascan/action/setOptionMaxScanDurationInMins/",
			"/JSON/ascan/action/setOptionHostPerScan/",
			"/JSON/ascan/action/stop/":
			writeJSON(map[string]string{"Result": "OK"})
		case "/JSON/spider/action/scan/":
			if f.failOrigin != "" && r.URL.Query().Get("url") == f.failOrigin {
				writeJSON(map[string]string{"code": "url_not_found", "message": "unreachable"})
				return
			}
			f.mu.Lock()
			f.spiderPolls = 0
			f.mu.Unlock()
			writeJSON(map[string]string{"scan": "10"})
		case "/JSON/spider/view/status/":
			f.mu.Lock()
			f.spiderPolls++
			pct := "50"
			if f.spiderPolls >= 2 {
				pct = "100"
			}
			f.mu.Unlock()
			writeJSON(map[string]string{"status": pct})
		case "/JSON/ascan/view/scanners/":
			writeJSON(map[string]any{"scanners": f.scanners})
		case "/JSON/ascan/action/scan/":
			f.mu.Lock()
			f.ascanPolls = 0
			f.mu.Unlock()
			writeJSON(map[string]string{"scan": "20"})
		case "/JSON/ascan/view/status/":
			if f.blockAscan != nil {
				select {
				case <-f.blockAscan:
				case <-r.Context().Done():
					return
				}
			}
			f.mu.Lock()
			f.ascanPolls++
			pct := "40"
			if f.ascanPolls >= 2 {
				pct = "100"
			}
			f.mu.Unlock()
			writeJSON(map[string]string{"status": pct})
		case "/JSON/pscan/view/recordsToScan/":
			f.mu.Lock()
			f.passivePolls++
			rem := "0"
			if f.passivePolls == 1 {
				rem = "2"
			}
			f.mu.Unlock()
			writeJSON(map[string]string{"recordsToScan": rem})
		case "/OTHER/core/other/xmlreport/":
			// Return the XML for the most recently scanned origin.
			f.mu.Lock()
			var lastOrigin string
			for i := len(f.calls) - 1; i >= 0; i-- {
				if f.calls[i].Path == "/JSON/ascan/action/scan/" {
					lastOrigin = f.calls[i].Query.Get("url")
					break
				}
			}
			xmlBody := f.xmlByOrigin[lastOrigin]
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(xmlBody))
		default:
			http.Error(w, "unexpected endpoint: "+r.URL.Path, http.StatusNotFound)
		}
	})
}

func TestExactAPICallSequence(t *testing.T) {
	const key = "test-zap-key-123"
	fake := &fakeZAP{
		scanners: []map[string]string{
			{"id": "0", "name": "Directory Browsing"},
			{"id": "6", "name": "Path Traversal"},
			{"id": "30001", "name": "Buffer Overflow"},
			{"id": "30002", "name": "Format String Error"},
			{"id": "40012", "name": "Cross Site Scripting (Reflected)"},
			{"id": "40031", "name": "Out of Band XSS"},
			{"id": "40043", "name": "Log4Shell"},
			{"id": "40044", "name": "Exponential Entity Expansion (Billion Laughs Attack)"},
			{"id": "90020", "name": "Remote OS Command Injection"},
			{"id": "99999", "name": "Custom Out-of-Band Probe"},
		},
		xmlByOrigin: map[string]string{
			"http://172.30.0.19": `<?xml version="1.0"?>
<OWASPZAPReport programName="ZAP" version="2.17.0" generated="Sat, 21 Nov 2026 20:00:00">
  <site name="http://172.30.0.19" host="172.30.0.19" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>10020</pluginid>
        <alert>Missing Anti-clickjacking Header</alert>
        <riskcode>2</riskcode>
        <desc>&lt;p&gt;Missing X-Frame-Options.&lt;/p&gt;</desc>
        <instances><instance><uri>http://172.30.0.19/admin</uri><method>GET</method></instance></instances>
        <solution>&lt;p&gt;Add CSP frame-ancestors.&lt;/p&gt;</solution>
        <cweid>1021</cweid>
      </alertitem>
    </alerts>
  </site>
  <site name="http://172.30.0.99" host="172.30.0.99" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>999</pluginid>
        <alert>Out of scope alert</alert>
        <riskcode>3</riskcode>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>`,
		},
	}
	srv := httptest.NewServer(fake.handler(key))
	defer srv.Close()

	ip := netip.MustParseAddr("172.30.0.19")
	sc := &Scanner{
		BaseURL:      srv.URL,
		APIKey:       key,
		PollInterval: time.Millisecond,
	}
	rep, err := sc.RunDetailed(context.Background(), scanner.Input{
		IPs:  []netip.Addr{ip},
		URLs: []string{"http://172.30.0.19:80"},
	}, scanner.Options{RateLimit: 20})
	if err != nil {
		t.Fatalf("RunDetailed: %v", err)
	}
	if rep.Errors != 0 || len(rep.Outcomes) != 1 || rep.Outcomes[0].Alerts != 1 {
		t.Fatalf("unexpected report: %+v", rep)
	}

	// Verify exact sequence of endpoints called.
	wantPaths := []string{
		"/JSON/core/action/newSession/",
		"/JSON/context/action/newContext/",
		"/JSON/context/action/includeInContext/",
		"/JSON/spider/action/setOptionMaxDuration/",
		"/JSON/spider/action/setOptionMaxDepth/",
		"/JSON/spider/action/setOptionThreadCount/",
		"/JSON/spider/action/scan/",
		"/JSON/spider/view/status/",
		"/JSON/spider/view/status/",
		"/JSON/ascan/action/addScanPolicy/",
		"/JSON/ascan/view/scanners/",
		"/JSON/ascan/action/disableScanners/",
		"/JSON/ascan/action/setOptionThreadPerHost/",
		"/JSON/ascan/action/setOptionDelayInMs/",
		"/JSON/ascan/action/setOptionMaxRuleDurationInMins/",
		"/JSON/ascan/action/setOptionMaxScanDurationInMins/",
		"/JSON/ascan/action/setOptionHostPerScan/",
		"/JSON/ascan/action/scan/",
		"/JSON/ascan/view/status/",
		"/JSON/ascan/view/status/",
		"/JSON/pscan/view/recordsToScan/",
		"/JSON/pscan/view/recordsToScan/",
		"/OTHER/core/other/xmlreport/",
		"/JSON/ascan/action/removeScanPolicy/",
		"/JSON/context/action/removeContext/",
		"/JSON/core/action/newSession/",
	}
	gotPaths := make([]string, len(fake.calls))
	for i, c := range fake.calls {
		gotPaths[i] = c.Path
	}
	if !slices.Equal(gotPaths, wantPaths) {
		t.Fatalf("API call sequence mismatch:\ngot:  %v\nwant: %v", gotPaths, wantPaths)
	}

	// Verify critical safety parameters on key calls.
	callByPath := func(path string) apiCall {
		for _, c := range fake.calls {
			if c.Path == path {
				return c
			}
		}
		t.Fatalf("missing call %s", path)
		return apiCall{}
	}

	inc := callByPath("/JSON/context/action/includeInContext/")
	if got := inc.Query.Get("regex"); got != `^http://172\.30\.0\.19(:80)?([/?#].*)?$` {
		t.Fatalf("includeInContext regex = %q", got)
	}
	spDur := callByPath("/JSON/spider/action/setOptionMaxDuration/")
	if spDur.Query.Get("Integer") != "2" {
		t.Fatalf("spider maxDuration = %q, want 2", spDur.Query.Get("Integer"))
	}
	spDepth := callByPath("/JSON/spider/action/setOptionMaxDepth/")
	if spDepth.Query.Get("Integer") != "3" {
		t.Fatalf("spider maxDepth = %q, want 3", spDepth.Query.Get("Integer"))
	}
	spScan := callByPath("/JSON/spider/action/scan/")
	if spScan.Query.Get("contextName") != contextName || spScan.Query.Get("subtreeOnly") != "true" {
		t.Fatalf("spider scan params = %v", spScan.Query)
	}
	dis := callByPath("/JSON/ascan/action/disableScanners/")
	if got, want := dis.Query.Get("ids"), "30001,30002,40031,40043,40044,90020,99999"; got != want {
		t.Fatalf("disableScanners ids = %q, want %q", got, want)
	}
	delay := callByPath("/JSON/ascan/action/setOptionDelayInMs/")
	if delay.Query.Get("Integer") != "100" {
		t.Fatalf("ascan delayInMs = %q, want 100 (2 threads / 20 rps)", delay.Query.Get("Integer"))
	}
	ascan := callByPath("/JSON/ascan/action/scan/")
	if ascan.Query.Get("inScopeOnly") != "true" || ascan.Query.Get("contextId") != "1" || ascan.Query.Get("scanPolicyName") != scanPolicyName {
		t.Fatalf("ascan scan params = %v", ascan.Query)
	}

	// Out-of-scope site 172.30.0.99 must have been filtered out of the report.
	if bytes.Contains(rep.Result.Raw, []byte("172.30.0.99")) {
		t.Fatalf("out-of-scope site leaked into report: %s", rep.Result.Raw)
	}
	if len(rep.Result.Observations) != 1 || rep.Result.Observations[0].Match.Name != "Missing Anti-clickjacking Header" {
		t.Fatalf("observations = %+v", rep.Result.Observations)
	}
	perIP := rep.Result.PerIP(ip)
	if !bytes.Contains(perIP, []byte("Missing Anti-clickjacking Header")) {
		t.Fatalf("PerIP missing alert: %s", perIP)
	}
	if rep.Result.PerIP(netip.MustParseAddr("172.30.0.99")) != nil {
		t.Fatal("PerIP returned data for out-of-scope IP")
	}
}

func TestPerURLErrorContinuesBatch(t *testing.T) {
	const key = "key"
	fake := &fakeZAP{
		scanners:   []map[string]string{{"id": "30001", "name": "Buffer Overflow"}},
		failOrigin: "http://172.30.0.19",
		xmlByOrigin: map[string]string{
			"http://172.30.0.20": `<?xml version="1.0"?><OWASPZAPReport version="2.17.0"></OWASPZAPReport>`,
		},
	}
	srv := httptest.NewServer(fake.handler(key))
	defer srv.Close()

	ip19 := netip.MustParseAddr("172.30.0.19")
	ip20 := netip.MustParseAddr("172.30.0.20")
	sc := &Scanner{BaseURL: srv.URL, APIKey: key, PollInterval: time.Millisecond}
	rep, err := sc.RunDetailed(context.Background(), scanner.Input{
		IPs:  []netip.Addr{ip19, ip20},
		URLs: []string{"http://172.30.0.19:80", "http://172.30.0.20:80"},
	}, scanner.Options{RateLimit: 10})
	if err != nil {
		t.Fatalf("RunDetailed returned fatal error: %v", err)
	}
	if rep.Errors != 1 || len(rep.Outcomes) != 2 {
		t.Fatalf("expected 1 error across 2 URLs, got %+v", rep)
	}
	if rep.Outcomes[0].Err == nil || rep.Outcomes[1].Err != nil {
		t.Fatalf("unexpected outcomes: %+v", rep.Outcomes)
	}
	// Failed IP must NOT appear in PerIP (preserves existing Dojo findings).
	if rep.Result.PerIP(ip19) != nil {
		t.Fatalf("failed IP got PerIP output: %s", rep.Result.PerIP(ip19))
	}
	// Succeeded IP with 0 alerts MUST still emit an empty <site> report to close old findings.
	per20 := rep.Result.PerIP(ip20)
	if !bytes.Contains(per20, []byte(`host="172.30.0.20"`)) || !bytes.Contains(per20, []byte(`<alerts></alerts>`)) {
		t.Fatalf("succeeded IP with 0 alerts PerIP = %s", per20)
	}
}

func TestCancelStopsActiveScanAndCleansUp(t *testing.T) {
	const key = "key"
	block := make(chan struct{})
	fake := &fakeZAP{
		scanners:   []map[string]string{{"id": "0", "name": "Directory Browsing"}},
		blockAscan: block,
	}
	srv := httptest.NewServer(fake.handler(key))
	defer func() {
		close(block)
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	ip := netip.MustParseAddr("172.30.0.19")
	sc := &Scanner{BaseURL: srv.URL, APIKey: key, PollInterval: time.Millisecond}
	_, err := sc.Run(ctx, scanner.Input{
		IPs:  []netip.Addr{ip},
		URLs: []string{"http://172.30.0.19:80"},
	}, scanner.Options{RateLimit: 10})
	if err == nil {
		t.Fatal("expected context deadline error")
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	var sawStop, sawRemovePolicy, sawRemoveContext bool
	for _, c := range fake.calls {
		switch c.Path {
		case "/JSON/ascan/action/stop/":
			sawStop = true
		case "/JSON/ascan/action/removeScanPolicy/":
			sawRemovePolicy = true
		case "/JSON/context/action/removeContext/":
			sawRemoveContext = true
		}
	}
	if !sawStop || !sawRemovePolicy || !sawRemoveContext {
		t.Fatalf("cleanup incomplete: stop=%v removePolicy=%v removeContext=%v", sawStop, sawRemovePolicy, sawRemoveContext)
	}
}

func TestOriginIncludeRegex(t *testing.T) {
	tests := []struct {
		origin    string
		matches   []string
		noMatches []string
	}{
		{
			origin:    "http://172.30.0.19:80",
			matches:   []string{"http://172.30.0.19", "http://172.30.0.19/", "http://172.30.0.19/admin", "http://172.30.0.19:80/admin?x=1"},
			noMatches: []string{"http://172.30.0.190/", "https://172.30.0.19/", "http://172.30.0.19:8080/", "http://172.30.0.20/"},
		},
		{
			origin:    "http://172.30.0.21:8080",
			matches:   []string{"http://172.30.0.21:8080", "http://172.30.0.21:8080/manager/html"},
			noMatches: []string{"http://172.30.0.21/", "http://172.30.0.21:80800/", "https://172.30.0.21:8080/"},
		},
		{
			origin:    "https://172.30.0.23:443",
			matches:   []string{"https://172.30.0.23", "https://172.30.0.23:443/login"},
			noMatches: []string{"http://172.30.0.23/", "https://172.30.0.23:8443/"},
		},
	}
	for _, tc := range tests {
		u, port, ok := rootURL(tc.origin)
		if !ok {
			t.Fatalf("rootURL(%q) failed", tc.origin)
		}
		re := regexp.MustCompile(OriginIncludeRegex(u, port))
		for _, m := range tc.matches {
			if !re.MatchString(m) {
				t.Errorf("regex %q should match %q", re.String(), m)
			}
		}
		for _, nm := range tc.noMatches {
			if re.MatchString(nm) {
				t.Errorf("regex %q must NOT match %q", re.String(), nm)
			}
		}
	}
}

func TestDelayInMs(t *testing.T) {
	for _, tc := range []struct {
		rate, threads, want int
	}{
		{20, 2, 100},
		{50, 2, 40},
		{1000, 2, MinDelayInMs},
		{1, 2, 2000},
		{0, 2, MaxDelayInMs},
	} {
		if got := DelayInMs(tc.rate, tc.threads); got != tc.want {
			t.Errorf("DelayInMs(%d, %d) = %d, want %d", tc.rate, tc.threads, got, tc.want)
		}
	}
}

func TestBuildInput(t *testing.T) {
	ip19 := netip.MustParseAddr("172.30.0.19")
	ip20 := netip.MustParseAddr("172.30.0.20")
	other := netip.MustParseAddr("172.30.0.99")
	in := BuildInput([]netip.Addr{ip19, ip20}, []scanner.Observation{
		{Kind: scanner.ObsHTTP, IP: ip19, Port: 80, URL: "http://172.30.0.19:80", HTTP: &scanner.HTTPInfo{Status: 200}},
		{Kind: scanner.ObsHTTP, IP: ip19, Port: 80, URL: "http://vhost.lab:80", HTTP: &scanner.HTTPInfo{Status: 200}},
		{Kind: scanner.ObsHTTP, IP: other, Port: 80, URL: "http://172.30.0.99:80", HTTP: &scanner.HTTPInfo{Status: 200}},
		{Kind: scanner.ObsHTTP, IP: ip20, Port: 80, URL: "http://172.30.0.20:80", HTTP: &scanner.HTTPInfo{Status: 0}},
		{Kind: scanner.ObsHTTP, IP: ip20, Port: 80, URL: "http://172.30.0.20:80", HTTP: &scanner.HTTPInfo{Status: 200}},
		{Kind: scanner.ObsHTTP, IP: ip20, Port: 80, URL: "http://172.30.0.20:80", HTTP: &scanner.HTTPInfo{Status: 200}},
	})
	if !slices.Equal(in.URLs, []string{"http://172.30.0.19:80", "http://172.30.0.20:80"}) {
		t.Fatalf("URLs = %v", in.URLs)
	}
	if !slices.Equal(in.IPs, []netip.Addr{ip19, ip20}) {
		t.Fatalf("IPs = %v", in.IPs)
	}
}

func TestValidationRejectsUnsafeInput(t *testing.T) {
	sc := &Scanner{BaseURL: "http://127.0.0.1:8080", APIKey: "k"}
	ip := netip.MustParseAddr("172.30.0.19")
	for name, fn := range map[string]func() error{
		"zero rate limit": func() error {
			_, err := sc.Run(context.Background(), scanner.Input{IPs: []netip.Addr{ip}, URLs: []string{"http://172.30.0.19:80"}}, scanner.Options{RateLimit: 0})
			return err
		},
		"out of batch IP": func() error {
			_, err := sc.Run(context.Background(), scanner.Input{IPs: []netip.Addr{ip}, URLs: []string{"http://172.30.0.20:80"}}, scanner.Options{RateLimit: 10})
			return err
		},
		"hostname instead of literal IP": func() error {
			_, err := sc.Run(context.Background(), scanner.Input{IPs: []netip.Addr{ip}, URLs: []string{"http://example.com:80"}}, scanner.Options{RateLimit: 10})
			return err
		},
		"missing API key": func() error {
			noKey := &Scanner{BaseURL: "http://127.0.0.1:8080"}
			_, err := noKey.Run(context.Background(), scanner.Input{IPs: []netip.Addr{ip}, URLs: []string{"http://172.30.0.19:80"}}, scanner.Options{RateLimit: 10})
			return err
		},
	} {
		if err := fn(); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: error leaked key: %v", name, err)
		}
	}
	_ = fmt.Sprint(DisabledRuleIDs)
}

func TestParseLabFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(testdata/lab.xml): %v", err)
	}
	if len(res.Observations) != 10 {
		t.Fatalf("got %d observations, want 10 (6 on .19 + 4 on .20)", len(res.Observations))
	}

	ip19 := netip.MustParseAddr("172.30.0.19")
	ip20 := netip.MustParseAddr("172.30.0.20")
	other := netip.MustParseAddr("172.30.0.99")

	per19 := res.PerIP(ip19)
	if !bytes.Contains(per19, []byte(`host="172.30.0.19"`)) || bytes.Contains(per19, []byte(`host="172.30.0.20"`)) {
		t.Fatalf("PerIP(.19) did not isolate .19")
	}
	if !bytes.Contains(per19, []byte("HTTP Only Site")) || !bytes.Contains(per19, []byte("Missing Anti-clickjacking Header")) {
		t.Fatalf("PerIP(.19) missing expected alerts")
	}
	parsed19, err := Parse(per19)
	if err != nil || len(parsed19.Observations) != 6 {
		t.Fatalf("re-parse PerIP(.19): obs=%d err=%v, want 6", len(parsed19.Observations), err)
	}

	per20 := res.PerIP(ip20)
	if !bytes.Contains(per20, []byte(`host="172.30.0.20"`)) || bytes.Contains(per20, []byte(`host="172.30.0.19"`)) {
		t.Fatalf("PerIP(.20) did not isolate .20")
	}
	parsed20, err := Parse(per20)
	if err != nil || len(parsed20.Observations) != 4 {
		t.Fatalf("re-parse PerIP(.20): obs=%d err=%v, want 4", len(parsed20.Observations), err)
	}

	if res.PerIP(other) != nil {
		t.Fatalf("PerIP(.99) = %q, want nil", res.PerIP(other))
	}
}
