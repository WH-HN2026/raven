// Package nikto runs Nikto against httpx-confirmed web origins in aggressive
// scan profiles (architecture §3.11, §9).
//
// Safety guarantees:
//   - Flags come strictly from BuildArgs's fixed allowlist.
//   - Tuning is locked to "123be" (interesting files, misconfiguration,
//     information disclosure, software identification, admin console):
//     no XSS/injection (4), file retrieval (5/7), DoS (6), RCE (8), SQLi (9),
//     file upload (0), auth bypass (a), RFI (c), or WebService (d).
//   - No credentials (-id), no evasion (-evasion), no mutation (-mutate),
//     no custom plugins (-Plugins), and no phone-home/updates (-nocheck, -ask no).
//   - Rate limit (-Pause) and per-URL time cap (-maxtime) are always set.
//   - Literal-IP origins only with -nolookup, preventing out-of-scope DNS resolution.
package nikto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

const (
	// DefaultTuning restricts Nikto to non-exploitative information,
	// misconfiguration, software-ID, and admin-console checks.
	DefaultTuning = "123be"

	// DefaultMaxTime caps each per-URL Nikto process.
	DefaultMaxTime = 300 * time.Second

	// DefaultTimeout bounds individual HTTP requests inside Nikto.
	DefaultTimeout = 10 * time.Second

	// DefaultConcurrency bounds concurrent Nikto processes per Run call.
	DefaultConcurrency = 2

	// MaxConcurrency is the hard upper bound on concurrent Nikto processes.
	MaxConcurrency = 2

	// MinPause prevents a zero pause even when a high rate limit is configured.
	MinPause = 10 * time.Millisecond
)

// Scanner runs Nikto. Its zero value uses "nikto" from PATH with safe defaults.
type Scanner struct {
	Binary      string        // executable name or absolute path (default "nikto")
	MaxTime     time.Duration // per-URL cap (default DefaultMaxTime)
	Timeout     time.Duration // per-request timeout (default DefaultTimeout)
	Concurrency int           // concurrent per-URL processes, clamped to [1, MaxConcurrency]
}

var _ scanner.Scanner = (*Scanner)(nil)

func (*Scanner) Name() string         { return "nikto" }
func (*Scanner) DojoScanType() string { return "Nikto Scan" }

// BuildInput selects the live, literal-IP origins confirmed by httpx.
// Literal-IP origins combined with -nolookup keep Nikto strictly on the
// confirmed batch endpoints.
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
		origin, port, ip, ok := parseOrigin(o.URL)
		if !ok || port != o.Port || ip != o.IP.Unmap() || seenURLs[origin.String()] {
			continue
		}
		in.URLs = append(in.URLs, origin.String())
		seenURLs[origin.String()] = true
		if !seenIPs[ip] {
			in.IPs = append(in.IPs, ip)
			seenIPs[ip] = true
		}
	}
	return in
}

// BuildArgs constructs the complete, allowlisted Nikto argument vector for one
// canonical literal-IP HTTP(S) origin.
func BuildArgs(rawURL, outputPath string, opt scanner.Options, maxTime, timeout time.Duration) ([]string, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("nikto: rate limit must be positive")
	}
	origin, _, ip, ok := parseOrigin(rawURL)
	if !ok {
		return nil, errors.New("nikto: expected a canonical literal-IP HTTP(S) origin with explicit port")
	}
	if outputPath == "" || strings.HasPrefix(outputPath, "-") || strings.ContainsAny(outputPath, "\r\n\x00") {
		return nil, errors.New("nikto: invalid output path")
	}
	if maxTime < 0 {
		return nil, errors.New("nikto: max time must not be negative")
	}
	if maxTime == 0 {
		maxTime = DefaultMaxTime
	}
	maxSecs := int(math.Ceil(maxTime.Seconds()))
	if maxSecs < 1 {
		maxSecs = 1
	}
	if timeout < 0 {
		return nil, errors.New("nikto: timeout must not be negative")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	timeoutSecs := int(math.Ceil(timeout.Seconds()))
	if timeoutSecs < 1 {
		timeoutSecs = 1
	}

	schemeFlag := "-nossl"
	if origin.Scheme == "https" {
		schemeFlag = "-ssl"
	}

	args := []string{
		"-h", origin.String(),
		schemeFlag,
		"-Tuning", DefaultTuning,
		"-Pause", formatPause(opt.RateLimit),
		"-maxtime", strconv.Itoa(maxSecs) + "s",
		"-timeout", strconv.Itoa(timeoutSecs),
		"-Format", "json",
		"-output", outputPath,
		"-nointeractive",
		"-nocheck",
		"-ask", "no",
		"-nolookup",
	}
	if ip.Is6() {
		args = append(args, "-ipv6")
	}
	return args, nil
}

// formatPause converts a requests-per-second rate limit into Nikto's -Pause
// duration in seconds, floored at MinPause so rate limiting is always active.
func formatPause(rateLimit int) string {
	pause := 1.0 / float64(rateLimit)
	if minSec := MinPause.Seconds(); pause < minSec {
		pause = minSec
	}
	s := strconv.FormatFloat(pause, 'f', 3, 64)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

func (s *Scanner) concurrency() int {
	c := s.Concurrency
	if c <= 0 {
		c = DefaultConcurrency
	}
	if c > MaxConcurrency {
		c = MaxConcurrency
	}
	return c
}

// Run executes one Nikto process per in-scope HTTP(S) origin with bounded
// concurrency, merges their JSON reports, and returns the parsed result.
func (s *Scanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("nikto: rate limit must be positive")
	}
	allowedIPs := make(map[netip.Addr]bool, len(in.IPs))
	for _, ip := range in.IPs {
		if ip.IsValid() && ip.Zone() == "" {
			allowedIPs[ip.Unmap()] = true
		}
	}
	urls := make([]string, 0, len(in.URLs))
	seen := make(map[string]bool, len(in.URLs))
	for _, raw := range in.URLs {
		origin, _, ip, ok := parseOrigin(raw)
		if !ok || !allowedIPs[ip] {
			return nil, errors.New("nikto: expected a literal-IP HTTP(S) origin on a batch IP")
		}
		if seen[origin.String()] {
			continue
		}
		seen[origin.String()] = true
		urls = append(urls, origin.String())
	}
	if len(urls) == 0 {
		return Parse(nil)
	}

	dir, err := os.MkdirTemp("", "raven-nikto-")
	if err != nil {
		return nil, fmt.Errorf("nikto: create workspace: %w", err)
	}
	defer os.RemoveAll(dir)

	conc := min(s.concurrency(), len(urls))
	perProcOpt := opt
	perProcOpt.RateLimit = max(1, opt.RateLimit/conc)

	type urlOut struct {
		raw []byte
		err error
	}
	results := make([]urlOut, len(urls))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, target := range urls {
		wg.Add(1)
		go func(idx int, rawURL string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx].err = ctx.Err()
				return
			}
			outPath := filepath.Join(dir, fmt.Sprintf("nikto-%d.json", idx))
			data, runErr := s.runOne(ctx, dir, rawURL, outPath, perProcOpt)
			results[idx] = urlOut{raw: data, err: runErr}
		}(i, target)
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var chunks [][]byte
	var errs []error
	for i, r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("url %s: %w", urls[i], r.err))
			continue
		}
		chunks = append(chunks, r.raw)
	}
	if len(chunks) == 0 {
		return nil, errors.Join(errs...)
	}
	combined, err := CombineRaw(chunks)
	if err != nil {
		return nil, err
	}
	return Parse(combined)
}

func (s *Scanner) runOne(ctx context.Context, dir, rawURL, outPath string, opt scanner.Options) ([]byte, error) {
	args, err := BuildArgs(rawURL, outPath, opt, s.MaxTime, s.Timeout)
	if err != nil {
		return nil, err
	}
	binary := s.Binary
	if binary == "" {
		binary = "nikto"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	if cmd.Err == nil {
		path, err := filepath.Abs(cmd.Path)
		if err != nil {
			return nil, fmt.Errorf("nikto: resolve executable: %w", err)
		}
		cmd.Path = path
	}
	cmd.Dir = dir
	// Controlled environment: no proxy variables, no credentials, explicit PATH for perl.
	cmd.Env = []string{
		"HOME=" + dir,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	// Run in its own process group so ctx cancellation kills nikto and any child processes immediately.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if line := lastLine(stderr.String()); line != "" {
			return nil, fmt.Errorf("nikto: %w: %s", err, line)
		}
		return nil, fmt.Errorf("nikto: %w", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("nikto: read output: %w", err)
	}
	if _, err := Parse(data); err != nil {
		return nil, err
	}
	return data, nil
}

func parseOrigin(raw string) (*url.URL, uint16, netip.Addr, bool) {
	if raw == "" || strings.ContainsAny(raw, ", \t\r\n") {
		return nil, 0, netip.Addr{}, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" {
		return nil, 0, netip.Addr{}, false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, 0, netip.Addr{}, false
	}
	if (u.Path != "" && u.EscapedPath() != "/") || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return nil, 0, netip.Addr{}, false
	}
	portStr := u.Port()
	if portStr == "" {
		return nil, 0, netip.Addr{}, false
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return nil, 0, netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.Zone() != "" {
		return nil, 0, netip.Addr{}, false
	}
	ip = ip.Unmap()
	canonical := &url.URL{
		Scheme: u.Scheme,
		Host:   net.JoinHostPort(ip.String(), strconv.FormatUint(portNum, 10)),
	}
	return canonical, uint16(portNum), ip, true
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// AllowedFlags returns the exact set of CLI flags that BuildArgs may emit.
// Exported for policy/allowlist auditing in tests.
func AllowedFlags() []string {
	return slices.Clone([]string{
		"-h", "-ssl", "-nossl", "-Tuning", "-Pause", "-maxtime", "-timeout",
		"-Format", "-output", "-nointeractive", "-nocheck", "-ask", "-nolookup", "-ipv6",
	})
}
