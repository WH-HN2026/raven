// Package wpscan runs WPScan against WordPress URLs discovered by httpx/nuclei
// inside opt-in aggressive profiles (architecture §3.11, §9).
package wpscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

const (
	// DefaultDBDir is the XDG_CACHE_HOME containing the baked wpscan/db files.
	DefaultDBDir = "/opt/wpscan-db"

	// EnumerateList enumerates installed plugins and themes (passively detected
	// with version checks), config backups, DB exports, and users 1-5 (passive
	// only — no login attempts). vp/vt are omitted because WPScan 4.x requires
	// an external API token for them (forbidden by architecture §9).
	EnumerateList = "p,t,cb,dbe,u1-5"

	DefaultRequestTimeoutSec  = 15
	DefaultConnectTimeoutSec  = 10
	DefaultMaxThreads         = 2
	DefaultMaxScanDurationSec = 120
	DefaultPerURLTimeout      = 3 * time.Minute

	// wpscanExitVulnerable is WPScan::ExitCode::VULNERABLE (scan succeeded and
	// reported at least one vulnerability or an unconfigured install).
	wpscanExitVulnerable = 5
)

// Scanner runs WPScan from PATH (or Binary) with its baked offline metadata DB.
type Scanner struct {
	Binary           string        // executable name or absolute path (default "wpscan")
	DBDir            string        // XDG_CACHE_HOME containing wpscan/db (default DefaultDBDir)
	PerURLTimeout    time.Duration // hard wall-clock cap per URL (default DefaultPerURLTimeout)
	DisableTLSChecks bool          // pass --disable-tls-checks for HTTPS URLs when enabled
}

var _ scanner.Scanner = (*Scanner)(nil)

func (*Scanner) Name() string         { return "wpscan" }
func (*Scanner) DojoScanType() string { return "Wpscan" }

// BuildArgs returns the complete fixed flag allowlist for one WPScan URL scan.
// Password attacks, login attempts, API tokens, random user agents, and runtime
// DB updates are never emitted (architecture §9).
func BuildArgs(rawURL, outputFile, cacheDir, cookieJar string, opt scanner.Options, disableTLS bool) ([]string, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("wpscan: rate limit must be positive")
	}
	u, _, ok := rootURL(rawURL)
	if !ok {
		return nil, errors.New("wpscan: expected a canonical root HTTP(S) URL")
	}
	if strings.TrimSpace(outputFile) == "" || strings.TrimSpace(cacheDir) == "" || strings.TrimSpace(cookieJar) == "" {
		return nil, errors.New("wpscan: output, cache-dir and cookie-jar paths are required")
	}
	throttleMs := max(1, 1000/opt.RateLimit)
	args := []string{
		"--url", u.String(),
		"--no-update",
		"--no-banner",
		"--format", "json",
		"--output", outputFile,
		"--cache-dir", cacheDir,
		"--cookie-jar", cookieJar,
		"--enumerate", EnumerateList,
		"--detection-mode", "mixed",
		"--plugins-detection", "passive",
		"--themes-detection", "passive",
		"--users-detection", "passive",
		"--throttle", strconv.Itoa(throttleMs),
		"--request-timeout", strconv.Itoa(DefaultRequestTimeoutSec),
		"--connect-timeout", strconv.Itoa(DefaultConnectTimeoutSec),
		"--max-threads", strconv.Itoa(DefaultMaxThreads),
		"--max-scan-duration", strconv.Itoa(DefaultMaxScanDurationSec),
	}
	if disableTLS && u.Scheme == "https" {
		args = append(args, "--disable-tls-checks")
	}
	return args, nil
}

// BuildInput selects only live literal-IP HTTP(S) origins in this batch where
// httpx technologies or nuclei tech detection identified WordPress.
func BuildInput(ips []netip.Addr, webObs, nucleiObs []scanner.Observation) scanner.Input {
	batch := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		batch[ip.Unmap()] = true
	}

	type endpointKey struct {
		ip   netip.Addr
		port uint16
	}
	// Collect confirmed live literal-IP HTTP origins of this batch in stable order.
	type candidate struct {
		ip     netip.Addr
		port   uint16
		origin string
	}
	var candidates []candidate
	seenOrigin := map[string]bool{}
	wpOrigins := map[string]bool{}
	wpEndpoints := map[endpointKey]bool{}

	for _, o := range webObs {
		ip := o.IP.Unmap()
		if !batch[ip] {
			continue
		}
		if o.Kind == scanner.ObsHTTP && o.HTTP != nil && o.HTTP.Status >= 100 && o.HTTP.Status <= 599 {
			u, port, ok := rootURL(o.URL)
			if !ok || port != o.Port || !literalAddress(u.Hostname(), ip) {
				continue
			}
			origin := u.String()
			if !seenOrigin[origin] {
				seenOrigin[origin] = true
				candidates = append(candidates, candidate{ip: ip, port: port, origin: origin})
			}
			for _, tech := range o.HTTP.Technologies {
				if isWordPressTech(tech) {
					wpOrigins[origin] = true
					wpEndpoints[endpointKey{ip, port}] = true
					break
				}
			}
		} else if o.Kind == scanner.ObsTech {
			if isWordPressTech(o.Tech) || isWordPressCPE(o.CPE) {
				if u, port, ok := rootURL(o.URL); ok && port == o.Port && literalAddress(u.Hostname(), ip) {
					wpOrigins[u.String()] = true
				}
				wpEndpoints[endpointKey{ip, o.Port}] = true
			}
		}
	}

	for _, o := range nucleiObs {
		ip := o.IP.Unmap()
		if !batch[ip] || !isWordPressNuclei(o) {
			continue
		}
		if o.Match != nil && o.Match.SourceURL != "" {
			if u, port, ok := rootURL(o.Match.SourceURL); ok && literalAddress(u.Hostname(), ip) {
				wpOrigins[u.String()] = true
				wpEndpoints[endpointKey{ip, port}] = true
				continue
			}
		}
		wpEndpoints[endpointKey{ip, o.Port}] = true
	}

	var in scanner.Input
	seenIPs := map[netip.Addr]bool{}
	for _, c := range candidates {
		if !wpOrigins[c.origin] && !wpEndpoints[endpointKey{c.ip, c.port}] {
			continue
		}
		in.URLs = append(in.URLs, c.origin)
		if !seenIPs[c.ip] {
			seenIPs[c.ip] = true
			in.IPs = append(in.IPs, c.ip)
		}
	}
	return in
}

func isWordPressTech(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if i := strings.IndexAny(s, ":/"); i > 0 {
		s = s[:i]
	}
	return strings.EqualFold(strings.TrimSpace(s), "wordpress")
}

func isWordPressCPE(cpe string) bool {
	cpe = strings.ToLower(strings.TrimSpace(cpe))
	return cpe == "wordpress:wordpress" || strings.HasPrefix(cpe, "wordpress:wordpress:")
}

func isWordPressNuclei(o scanner.Observation) bool {
	if isWordPressTech(o.Tech) || isWordPressCPE(o.CPE) || strings.EqualFold(strings.TrimSpace(o.Product), "wordpress") {
		return true
	}
	if o.Match == nil {
		return false
	}
	if o.Kind == scanner.ObsTech && slices.ContainsFunc(o.Match.Tags, func(t string) bool {
		return strings.EqualFold(t, "wordpress")
	}) {
		return true
	}
	return strings.EqualFold(o.Match.TemplateID, "wordpress-detect")
}

// Run executes WPScan for each in-scope WordPress URL in in.URLs.
func (s *Scanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("wpscan: rate limit must be positive")
	}
	urls := make([]string, 0, len(in.URLs))
	seen := make(map[string]bool, len(in.URLs))
	for _, raw := range in.URLs {
		u, _, ok := rootURL(raw)
		if !ok || !slices.ContainsFunc(in.IPs, func(ip netip.Addr) bool { return literalAddress(u.Hostname(), ip) }) {
			return nil, errors.New("wpscan: expected an HTTP(S) origin on a batch IP")
		}
		canon := u.String()
		if !seen[canon] {
			seen[canon] = true
			urls = append(urls, canon)
		}
	}
	if len(urls) == 0 {
		return Parse(nil)
	}

	var lines [][]byte
	for _, u := range urls {
		raw, err := s.runOne(ctx, u, opt)
		if err != nil {
			return nil, err
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return nil, fmt.Errorf("wpscan: invalid JSON output for %s: %w", u, err)
		}
		lines = append(lines, compact.Bytes())
	}
	combined := bytes.Join(lines, []byte("\n"))
	if len(combined) > 0 {
		combined = append(combined, '\n')
	}
	return Parse(combined)
}

func (s *Scanner) runOne(ctx context.Context, rawURL string, opt scanner.Options) ([]byte, error) {
	dir, err := os.MkdirTemp("", "raven-wpscan-")
	if err != nil {
		return nil, fmt.Errorf("wpscan: create workspace: %w", err)
	}
	defer os.RemoveAll(dir)

	outFile := filepath.Join(dir, "report.json")
	cacheDir := filepath.Join(dir, "cache")
	cookieJar := filepath.Join(dir, "cookies.txt")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("wpscan: create cache dir: %w", err)
	}

	args, err := BuildArgs(rawURL, outFile, cacheDir, cookieJar, opt, s.DisableTLSChecks)
	if err != nil {
		return nil, err
	}

	timeout := s.PerURLTimeout
	if timeout <= 0 {
		timeout = DefaultPerURLTimeout
	}
	urlCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	binary := s.Binary
	if binary == "" {
		binary = "wpscan"
	}
	cmd := exec.CommandContext(urlCtx, binary, args...)
	if cmd.Err == nil {
		if path, err := filepath.Abs(cmd.Path); err == nil {
			cmd.Path = path
		}
	}
	dbDir := s.DBDir
	if dbDir == "" {
		dbDir = DefaultDBDir
	}
	cmd.Dir = dir
	// Controlled environment: never inherit os.Environ() so WPSCAN_API_TOKEN
	// and WPSCAN_ENTERPRISE_DB_TOKEN can never reach the subprocess.
	cmd.Env = []string{
		"PATH=" + safePath(),
		"HOME=" + dir,
		"XDG_CACHE_HOME=" + dbDir,
		"TMPDIR=" + dir,
		"LANG=C.UTF-8",
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if urlCtx.Err() != nil {
		return nil, fmt.Errorf("wpscan %s: %w", rawURL, urlCtx.Err())
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != wpscanExitVulnerable {
			return nil, fmt.Errorf("wpscan %s: %w%s", rawURL, err, formatStderr(stderr.Bytes()))
		}
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("wpscan %s: read output: %w", rawURL, err)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("wpscan %s: empty JSON output", rawURL)
	}
	return raw, nil
}

func safePath() string {
	if p := os.Getenv("PATH"); p != "" {
		return p
	}
	return "/usr/local/bin:/usr/bin:/bin"
}

func formatStderr(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if len(last) > 200 {
		last = last[:200]
	}
	return " (" + last + ")"
}

func literalAddress(host string, expected netip.Addr) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && ip.Unmap() == expected.Unmap()
}

func rootURL(raw string) (*url.URL, uint16, bool) {
	u, port, ok := webURL(raw)
	if !ok || (u.Path != "" && u.EscapedPath() != "/") || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return nil, 0, false
	}
	u.Path, u.RawPath = "", ""
	return u, port, true
}

func webURL(raw string) (*url.URL, uint16, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil {
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
	return u, uint16(p), true
}
