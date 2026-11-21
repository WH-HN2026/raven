// Package zap drives an OWASP ZAP daemon over its HTTP API for the opt-in
// Aggressive workflow stage (architecture §3.11, §9).
package zap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

const (
	// Hard safety caps (architecture §9).
	DefaultSpiderMaxDurationMins = 2
	DefaultSpiderMaxDepth        = 3
	DefaultSpiderMaxChildren     = 20
	DefaultSpiderThreads         = 2

	DefaultThreadsPerHost      = 2
	DefaultMaxRuleDurationMins = 1
	DefaultMaxScanDurationMins = 3

	DefaultPollInterval        = 2 * time.Second
	DefaultPassiveDrainTimeout = 15 * time.Second
	DefaultPerURLTimeout       = 6 * time.Minute

	MinDelayInMs = 20
	MaxDelayInMs = 5000

	apiKeyHeader   = "X-ZAP-API-Key"
	contextName    = "raven-scope"
	scanPolicyName = "raven-policy"

	maxAPIResponseBytes = 32 << 20 // 32 MiB cap for XML reports
)

// DisabledRuleIDs is the explicit list of DoS-like, exploitation-heavy,
// time-based, fuzzing, and OAST-based ZAP active scan rule IDs disabled in our
// scan policy (architecture §9).
var DisabledRuleIDs = []string{
	"7",     // Remote File Inclusion
	"10048", // Remote Code Execution - Shell Shock
	"10104", // User Agent Fuzzer
	"20015", // Heartbleed OpenSSL Vulnerability
	"20018", // Remote Code Execution - CVE-2012-1823
	"30001", // Buffer Overflow
	"30002", // Format String Error
	"40019", // SQL Injection - MySQL (Time Based)
	"40020", // SQL Injection - Hypersonic SQL (Time Based)
	"40021", // SQL Injection - Oracle (Time Based)
	"40022", // SQL Injection - PostgreSQL (Time Based)
	"40026", // Cross Site Scripting (DOM Based)
	"40027", // SQL Injection - MsSQL (Time Based)
	"40031", // Out of Band XSS
	"40043", // Log4Shell (OAST / RCE)
	"40044", // Exponential Entity Expansion (Billion Laughs Attack / DoS)
	"40045", // Spring4Shell (RCE)
	"40046", // Server Side Request Forgery (OAST)
	"40047", // Text4Shell (OAST / RCE)
	"40048", // Remote Code Execution (React2Shell)
	"50000", // Script Active Scan Rules
	"90017", // XSLT Injection
	"90019", // Server Side Code Injection
	"90020", // Remote OS Command Injection
	"90023", // XML External Entity Attack (OAST)
	"90035", // Server Side Template Injection
	"90036", // Server Side Template Injection (Blind)
	"90037", // Remote OS Command Injection (Time Based)
}

var disabledRuleIDSet = func() map[string]bool {
	m := make(map[string]bool, len(DisabledRuleIDs))
	for _, id := range DisabledRuleIDs {
		m[id] = true
	}
	return m
}()

var disabledRuleNameSubstrings = []string{
	"buffer overflow",
	"format string",
	"command injection",
	"remote code execution",
	"log4shell",
	"text4shell",
	"spring4shell",
	"out of band",
	"out-of-band",
	"oast",
	"billion laughs",
	"denial of service",
	"fuzzer",
	"time based",
	"time-based",
	"external entity",
	"xxe",
	"ssrf",
	"remote file inclusion",
	"heartbleed",
	"script active",
}

// ShouldDisableRule reports whether a ZAP active scan rule must be disabled by
// our safe active-scan policy.
func ShouldDisableRule(id, name string) bool {
	if disabledRuleIDSet[strings.TrimSpace(id)] {
		return true
	}
	lower := strings.ToLower(name)
	for _, sub := range disabledRuleNameSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// URLOutcome records the outcome of scanning one URL with ZAP.
type URLOutcome struct {
	URL      string
	IP       netip.Addr
	Duration time.Duration
	Alerts   int
	Err      error
}

// RunReport is the detailed result of running ZAP over a batch of URLs.
type RunReport struct {
	Result   *scanner.Result
	Outcomes []URLOutcome
	Errors   int
}

// DetailedRunner is implemented by Scanner so the pipeline stage can log
// per-URL durations/alerts and record per-URL errors in run stats.
type DetailedRunner interface {
	scanner.Scanner
	RunDetailed(ctx context.Context, in scanner.Input, opt scanner.Options) (*RunReport, error)
}

// Scanner drives a ZAP daemon over its HTTP API.
type Scanner struct {
	BaseURL string
	APIKey  string

	HTTPClient *http.Client

	PollInterval        time.Duration
	PassiveDrainTimeout time.Duration
	PerURLTimeout       time.Duration

	SpiderMaxDurationMins int
	SpiderMaxDepth        int
	SpiderMaxChildren     int
	SpiderThreads         int

	ThreadsPerHost      int
	MaxRuleDurationMins int
	MaxScanDurationMins int

	semOnce sync.Once
	sem     chan struct{}
}

var (
	_ scanner.Scanner = (*Scanner)(nil)
	_ DetailedRunner  = (*Scanner)(nil)
)

func (*Scanner) Name() string         { return "zap" }
func (*Scanner) DojoScanType() string { return "ZAP Scan" }

// DelayInMs computes ZAP's per-request active scan delay from the profile's
// web rate limit (requests/second) and active scan threads per host.
func DelayInMs(rateLimit, threadsPerHost int) int {
	if threadsPerHost < 1 {
		threadsPerHost = DefaultThreadsPerHost
	}
	if rateLimit < 1 {
		return MaxDelayInMs
	}
	d := (threadsPerHost * 1000) / rateLimit
	if d < MinDelayInMs {
		return MinDelayInMs
	}
	if d > MaxDelayInMs {
		return MaxDelayInMs
	}
	return d
}

// OriginIncludeRegex returns an anchored regular expression matching only the
// given URL's exact origin (scheme, literal IP host, port). Default ports
// (:80 for http, :443 for https) are matched optionally because ZAP normalizes
// default ports out of URLs in its Sites tree.
func OriginIncludeRegex(u *url.URL, port uint16) string {
	host := u.Hostname()
	hostPart := regexp.QuoteMeta(host)
	if strings.Contains(host, ":") {
		hostPart = `\[` + hostPart + `\]`
	}
	var portPart string
	switch {
	case u.Scheme == "http" && port == 80:
		portPart = `(:80)?`
	case u.Scheme == "https" && port == 443:
		portPart = `(:443)?`
	default:
		portPart = fmt.Sprintf(`:%d`, port)
	}
	return fmt.Sprintf(`^%s://%s%s([/?#].*)?$`, u.Scheme, hostPart, portPart)
}

// BuildInput selects the live, literal-IP HTTP(S) origins confirmed by httpx
// for this batch. Literal IP origins guarantee ZAP never resolves arbitrary
// hostnames outside the batch's in-scope targets.
func BuildInput(ips []netip.Addr, web []scanner.Observation) scanner.Input {
	batch := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		batch[ip.Unmap()] = true
	}
	var in scanner.Input
	seenIPs, seenURLs := map[netip.Addr]bool{}, map[string]bool{}
	for _, o := range web {
		if o.Kind != scanner.ObsHTTP || o.HTTP == nil || o.HTTP.Status < 100 || o.HTTP.Status > 599 || !batch[o.IP.Unmap()] {
			continue
		}
		origin, port, ok := rootURL(o.URL)
		if !ok || port != o.Port || !literalAddress(origin.Hostname(), o.IP) || seenURLs[origin.String()] {
			continue
		}
		in.URLs = append(in.URLs, origin.String())
		seenURLs[origin.String()] = true
		if ip := o.IP.Unmap(); !seenIPs[ip] {
			in.IPs = append(in.IPs, ip)
			seenIPs[ip] = true
		}
	}
	return in
}

// Run executes ZAP against every URL in in.URLs and returns the combined XML
// report and parsed observations.
func (s *Scanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	rep, err := s.RunDetailed(ctx, in, opt)
	if err != nil {
		return nil, err
	}
	return rep.Result, nil
}

// RunDetailed executes ZAP per URL, isolating per-URL failures so a failure on
// one URL does not abort the rest of the batch (unless ctx is cancelled).
func (s *Scanner) RunDetailed(ctx context.Context, in scanner.Input, opt scanner.Options) (*RunReport, error) {
	if strings.TrimSpace(s.BaseURL) == "" {
		return nil, errors.New("zap: BaseURL is not configured")
	}
	if s.APIKey == "" {
		return nil, errors.New("zap: APIKey is required")
	}
	if opt.RateLimit < 1 {
		return nil, errors.New("zap: rate limit must be positive")
	}

	type target struct {
		url    *url.URL
		ip     netip.Addr
		port   uint16
		origin string
	}
	var targets []target
	seen := make(map[string]bool, len(in.URLs))
	for _, raw := range in.URLs {
		u, port, ok := rootURL(raw)
		if !ok || !slices.ContainsFunc(in.IPs, func(ip netip.Addr) bool { return literalAddress(u.Hostname(), ip) }) {
			return nil, errors.New("zap: expected an HTTP(S) origin on a batch IP")
		}
		if seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		ip, _ := netip.ParseAddr(u.Hostname())
		targets = append(targets, target{
			url:    u,
			ip:     ip.Unmap(),
			port:   port,
			origin: zapOriginURL(u, port),
		})
	}
	if len(targets) == 0 {
		res, err := Parse(nil)
		return &RunReport{Result: res}, err
	}

	var (
		allSites  []SiteXML
		version   = defaultReportVersion
		generated string
		rep       = &RunReport{Outcomes: make([]URLOutcome, 0, len(targets))}
	)
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		started := time.Now()
		ver, gen, sites, alerts, err := s.scanURL(ctx, t.url, t.ip, t.port, t.origin, opt.RateLimit)
		dur := time.Since(started)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			rep.Errors++
			rep.Outcomes = append(rep.Outcomes, URLOutcome{
				URL: t.origin, IP: t.ip, Duration: dur, Err: err,
			})
			continue
		}
		if ver != "" {
			version = ver
		}
		if gen != "" {
			generated = gen
		}
		allSites = append(allSites, sites...)
		rep.Outcomes = append(rep.Outcomes, URLOutcome{
			URL: t.origin, IP: t.ip, Duration: dur, Alerts: alerts,
		})
	}

	if len(allSites) == 0 {
		res, err := Parse(nil)
		rep.Result = res
		return rep, err
	}
	merged, err := marshalReport("ZAP", version, generated, allSites)
	if err != nil {
		return nil, err
	}
	res, err := Parse(merged)
	if err != nil {
		return nil, err
	}
	rep.Result = res
	return rep, nil
}

func (s *Scanner) acquire(ctx context.Context) (func(), error) {
	s.semOnce.Do(func() { s.sem = make(chan struct{}, 1) })
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Scanner) scanURL(ctx context.Context, u *url.URL, ip netip.Addr, port uint16, origin string, rateLimit int) (version, generated string, sites []SiteXML, alerts int, err error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return "", "", nil, 0, err
	}
	defer release()

	urlTimeout := s.perURLTimeout()
	urlCtx, cancel := context.WithTimeout(ctx, urlTimeout)
	defer cancel()

	var (
		ctxCreated    bool
		policyCreated bool
		spiderID      string
		spiderRunning bool
		ascanID       string
		ascanRunning  bool
	)
	defer func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cleanCancel()
		if spiderRunning && spiderID != "" {
			_ = s.callJSON(cleanCtx, "/JSON/spider/action/stop/", url.Values{"scanId": {spiderID}}, nil)
		}
		if ascanRunning && ascanID != "" {
			_ = s.callJSON(cleanCtx, "/JSON/ascan/action/stop/", url.Values{"scanId": {ascanID}}, nil)
		}
		if policyCreated {
			_ = s.callJSON(cleanCtx, "/JSON/ascan/action/removeScanPolicy/", url.Values{"scanPolicyName": {scanPolicyName}}, nil)
		}
		if ctxCreated {
			_ = s.callJSON(cleanCtx, "/JSON/context/action/removeContext/", url.Values{"contextName": {contextName}}, nil)
		}
		_ = s.callJSON(cleanCtx, "/JSON/core/action/newSession/", url.Values{"overwrite": {"true"}}, nil)
	}()

	// 1. Start from a clean ZAP session so no alerts leak across URLs.
	if err := s.callJSON(urlCtx, "/JSON/core/action/newSession/", url.Values{"overwrite": {"true"}}, nil); err != nil {
		return "", "", nil, 0, fmt.Errorf("newSession: %w", err)
	}

	// 2. Create a context strictly scoped to this URL's origin (no auth, no users).
	var newCtxResp struct {
		ContextID string `json:"contextId"`
	}
	if err := s.callJSON(urlCtx, "/JSON/context/action/newContext/", url.Values{"contextName": {contextName}}, &newCtxResp); err != nil {
		return "", "", nil, 0, fmt.Errorf("newContext: %w", err)
	}
	if newCtxResp.ContextID == "" {
		return "", "", nil, 0, errors.New("newContext: empty contextId")
	}
	ctxCreated = true

	if err := s.callJSON(urlCtx, "/JSON/context/action/includeInContext/", url.Values{
		"contextName": {contextName},
		"regex":       {OriginIncludeRegex(u, port)},
	}, nil); err != nil {
		return "", "", nil, 0, fmt.Errorf("includeInContext: %w", err)
	}

	// 3. Configure and run a capped traditional spider inside the origin context.
	if err := s.callJSON(urlCtx, "/JSON/spider/action/setOptionMaxDuration/", url.Values{
		"Integer": {strconv.Itoa(s.spiderMaxDurationMins())},
	}, nil); err != nil {
		return "", "", nil, 0, fmt.Errorf("spider setOptionMaxDuration: %w", err)
	}
	if err := s.callJSON(urlCtx, "/JSON/spider/action/setOptionMaxDepth/", url.Values{
		"Integer": {strconv.Itoa(s.spiderMaxDepth())},
	}, nil); err != nil {
		return "", "", nil, 0, fmt.Errorf("spider setOptionMaxDepth: %w", err)
	}
	if err := s.callJSON(urlCtx, "/JSON/spider/action/setOptionThreadCount/", url.Values{
		"Integer": {strconv.Itoa(s.spiderThreads())},
	}, nil); err != nil {
		return "", "", nil, 0, fmt.Errorf("spider setOptionThreadCount: %w", err)
	}

	var spiderResp struct {
		Scan string `json:"scan"`
	}
	if err := s.callJSON(urlCtx, "/JSON/spider/action/scan/", url.Values{
		"url":         {origin},
		"contextName": {contextName},
		"maxChildren": {strconv.Itoa(s.spiderMaxChildren())},
		"recurse":     {"true"},
		"subtreeOnly": {"true"},
	}, &spiderResp); err != nil {
		return "", "", nil, 0, fmt.Errorf("spider scan: %w", err)
	}
	if spiderResp.Scan == "" {
		return "", "", nil, 0, errors.New("spider scan: empty scan id")
	}
	spiderID, spiderRunning = spiderResp.Scan, true
	if err := s.pollStatus(urlCtx, "/JSON/spider/view/status/", spiderID); err != nil {
		return "", "", nil, 0, fmt.Errorf("spider status: %w", err)
	}
	spiderRunning = false

	// 4. Create our active scan policy and disable DoS / RCE / OAST / fuzzing rules.
	if err := s.callJSON(urlCtx, "/JSON/ascan/action/addScanPolicy/", url.Values{
		"scanPolicyName": {scanPolicyName},
		"alertThreshold": {"MEDIUM"},
		"attackStrength": {"LOW"},
	}, nil); err != nil {
		return "", "", nil, 0, fmt.Errorf("addScanPolicy: %w", err)
	}
	policyCreated = true

	var scannersResp struct {
		Scanners []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"scanners"`
	}
	if err := s.callJSON(urlCtx, "/JSON/ascan/view/scanners/", url.Values{
		"scanPolicyName": {scanPolicyName},
	}, &scannersResp); err != nil {
		return "", "", nil, 0, fmt.Errorf("ascan list scanners: %w", err)
	}
	var disableIDs []string
	for _, sc := range scannersResp.Scanners {
		if ShouldDisableRule(sc.ID, sc.Name) {
			disableIDs = append(disableIDs, sc.ID)
		}
	}
	slices.SortFunc(disableIDs, func(a, b string) int {
		ai, _ := strconv.Atoi(a)
		bi, _ := strconv.Atoi(b)
		if ai != bi {
			return ai - bi
		}
		return strings.Compare(a, b)
	})
	if len(disableIDs) > 0 {
		if err := s.callJSON(urlCtx, "/JSON/ascan/action/disableScanners/", url.Values{
			"ids":            {strings.Join(disableIDs, ",")},
			"scanPolicyName": {scanPolicyName},
		}, nil); err != nil {
			return "", "", nil, 0, fmt.Errorf("disableScanners: %w", err)
		}
	}

	// 5. Set active scan concurrency, delay from web rate, and rule/scan caps.
	threads := s.threadsPerHost()
	delayMs := DelayInMs(rateLimit, threads)
	for _, optCall := range []struct {
		path string
		val  int
	}{
		{"/JSON/ascan/action/setOptionThreadPerHost/", threads},
		{"/JSON/ascan/action/setOptionDelayInMs/", delayMs},
		{"/JSON/ascan/action/setOptionMaxRuleDurationInMins/", s.maxRuleDurationMins()},
		{"/JSON/ascan/action/setOptionMaxScanDurationInMins/", s.maxScanDurationMins()},
		{"/JSON/ascan/action/setOptionHostPerScan/", 1},
	} {
		if err := s.callJSON(urlCtx, optCall.path, url.Values{"Integer": {strconv.Itoa(optCall.val)}}, nil); err != nil {
			return "", "", nil, 0, fmt.Errorf("%s: %w", optCall.path, err)
		}
	}

	// 6. Run capped active scan strictly in-scope of the context.
	var ascanResp struct {
		Scan string `json:"scan"`
	}
	if err := s.callJSON(urlCtx, "/JSON/ascan/action/scan/", url.Values{
		"url":            {origin},
		"contextId":      {newCtxResp.ContextID},
		"scanPolicyName": {scanPolicyName},
		"inScopeOnly":    {"true"},
		"recurse":        {"true"},
	}, &ascanResp); err != nil {
		return "", "", nil, 0, fmt.Errorf("ascan scan: %w", err)
	}
	if ascanResp.Scan == "" {
		return "", "", nil, 0, errors.New("ascan scan: empty scan id")
	}
	ascanID, ascanRunning = ascanResp.Scan, true
	if err := s.pollStatus(urlCtx, "/JSON/ascan/view/status/", ascanID); err != nil {
		return "", "", nil, 0, fmt.Errorf("ascan status: %w", err)
	}
	ascanRunning = false

	// 7. Wait briefly for passive scanner queue to finish processing responses.
	s.drainPassive(urlCtx)

	// 8. Fetch XML report and scope it strictly to this origin.
	xmlBytes, err := s.callBytes(urlCtx, "/OTHER/core/other/xmlreport/", nil)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("xmlreport: %w", err)
	}
	return filterSitesToOrigin(xmlBytes, u.Scheme, ip, port, origin)
}

func (s *Scanner) pollStatus(ctx context.Context, path, scanID string) error {
	interval := s.pollInterval()
	for {
		var resp struct {
			Status string `json:"status"`
		}
		if err := s.callJSON(ctx, path, url.Values{"scanId": {scanID}}, &resp); err != nil {
			return err
		}
		pct, err := strconv.Atoi(strings.TrimSpace(resp.Status))
		if err == nil && pct >= 100 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (s *Scanner) drainPassive(ctx context.Context) {
	drainCtx, cancel := context.WithTimeout(ctx, s.passiveDrainTimeout())
	defer cancel()
	interval := s.pollInterval()
	for {
		var resp struct {
			RecordsToScan string `json:"recordsToScan"`
		}
		if err := s.callJSON(drainCtx, "/JSON/pscan/view/recordsToScan/", nil, &resp); err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(resp.RecordsToScan))
		if err != nil || n <= 0 {
			return
		}
		select {
		case <-drainCtx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (s *Scanner) callJSON(ctx context.Context, path string, params url.Values, out any) error {
	body, err := s.callBytes(ctx, path, params)
	if err != nil {
		return err
	}
	var apiErr struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Code != "" {
		return fmt.Errorf("zap api %s: %s (%s)", path, apiErr.Code, apiErr.Message)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("zap api %s: decode json: %w", path, err)
		}
	}
	return nil
}

func (s *Scanner) callBytes(ctx context.Context, path string, params url.Values) ([]byte, error) {
	base := strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
	endpoint := base + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", path, err)
	}
	// Pass the API key only via header so it never appears in URLs or logs.
	req.Header.Set(apiKeyHeader, s.APIKey)

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(body) > maxAPIResponseBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", path, maxAPIResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zap %s: HTTP %d", path, resp.StatusCode)
	}
	return body, nil
}

func (s *Scanner) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s *Scanner) pollInterval() time.Duration {
	if s.PollInterval > 0 {
		return s.PollInterval
	}
	return DefaultPollInterval
}

func (s *Scanner) passiveDrainTimeout() time.Duration {
	if s.PassiveDrainTimeout > 0 {
		return s.PassiveDrainTimeout
	}
	return DefaultPassiveDrainTimeout
}

func (s *Scanner) perURLTimeout() time.Duration {
	if s.PerURLTimeout > 0 {
		return s.PerURLTimeout
	}
	return DefaultPerURLTimeout
}

func (s *Scanner) spiderMaxDurationMins() int {
	if s.SpiderMaxDurationMins > 0 {
		return s.SpiderMaxDurationMins
	}
	return DefaultSpiderMaxDurationMins
}

func (s *Scanner) spiderMaxDepth() int {
	if s.SpiderMaxDepth > 0 {
		return s.SpiderMaxDepth
	}
	return DefaultSpiderMaxDepth
}

func (s *Scanner) spiderMaxChildren() int {
	if s.SpiderMaxChildren > 0 {
		return s.SpiderMaxChildren
	}
	return DefaultSpiderMaxChildren
}

func (s *Scanner) spiderThreads() int {
	if s.SpiderThreads > 0 {
		return s.SpiderThreads
	}
	return DefaultSpiderThreads
}

func (s *Scanner) threadsPerHost() int {
	if s.ThreadsPerHost > 0 {
		return s.ThreadsPerHost
	}
	return DefaultThreadsPerHost
}

func (s *Scanner) maxRuleDurationMins() int {
	if s.MaxRuleDurationMins > 0 {
		return s.MaxRuleDurationMins
	}
	return DefaultMaxRuleDurationMins
}

func (s *Scanner) maxScanDurationMins() int {
	if s.MaxScanDurationMins > 0 {
		return s.MaxScanDurationMins
	}
	return DefaultMaxScanDurationMins
}

func literalAddress(host string, expected netip.Addr) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && ip.Unmap() == expected.Unmap()
}

func zapOriginURL(u *url.URL, port uint16) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if (u.Scheme == "http" && port == 80) || (u.Scheme == "https" && port == 443) {
		return u.Scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%d", u.Scheme, host, port)
}

func rootURL(raw string) (*url.URL, uint16, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, 0, false
	}
	if (u.Path != "" && u.EscapedPath() != "/") || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return nil, 0, false
	}
	port := u.Port()
	switch u.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	default:
		return nil, 0, false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, 0, false
	}
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		host = ip.Unmap().String()
	}
	u.Host = net.JoinHostPort(host, strconv.FormatUint(p, 10))
	u.Path, u.RawPath = "", ""
	return u, uint16(p), true
}
