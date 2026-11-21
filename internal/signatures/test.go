package signatures

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/audit"
	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/targets"
)

const (
	defaultTestRateLimit = 10
	defaultTestTimeout   = 30 * time.Second
)

var (
	ErrInvalidURL         = errors.New("invalid target URL")
	ErrOutOfScope         = errors.New("target URL is out of scope")
	ErrScannerUnavailable = errors.New("nuclei scanner unavailable")
)

// TemplateRunner runs one nuclei template against one in-scope URL.
// *nuclei.Scanner satisfies it; tests inject a fake or stub runner.
type TemplateRunner interface {
	RunTemplate(ctx context.Context, templateYAML, rawURL string, targetIP netip.Addr, rateLimit int) (*scanner.Result, error)
}

// TestMatch is one matcher hit returned by POST /api/signatures/{id}/test.
type TestMatch struct {
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Matcher    string   `json:"matcher"`
	MatchedAt  string   `json:"matched_at"`
	Extracted  []string `json:"extracted"`
}

// TestResult is the response of POST /api/signatures/{id}/test.
type TestResult struct {
	Matched bool        `json:"matched"`
	URL     string      `json:"url"`
	Matches []TestMatch `json:"matches"`
}

// Test runs one stored signature against one in-scope URL and logs an audit
// entry. The URL's host must resolve to IPv4 address(es) inside configured
// targets/scope and not in the global blacklist.
func (s *Store) Test(ctx context.Context, u *auth.User, id int64, rawURL string, runner TemplateRunner, resolver targets.Resolver) (TestResult, error) {
	sig, err := s.Get(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	if !sig.Valid {
		return TestResult{}, &InvalidError{Msg: "invalid signature cannot be tested"}
	}
	normalizedURL, host, err := normalizeTestURL(rawURL)
	if err != nil {
		return TestResult{}, err
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, hostnames, err := resolveTestHost(ctx, host, resolver)
	if err != nil {
		return TestResult{}, err
	}
	if err := s.checkURLScope(ctx, ips, hostnames, resolver); err != nil {
		return TestResult{}, err
	}
	if runner == nil {
		return TestResult{}, ErrScannerUnavailable
	}

	runCtx, cancel := context.WithTimeout(ctx, defaultTestTimeout)
	defer cancel()
	res, err := runner.RunTemplate(runCtx, sig.TemplateYAML, normalizedURL, ips[0], defaultTestRateLimit)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return TestResult{}, fmt.Errorf("%w: nuclei binary not installed", ErrScannerUnavailable)
		}
		return TestResult{}, err
	}

	out := TestResult{
		URL:     normalizedURL,
		Matches: []TestMatch{},
	}
	if res != nil {
		for _, o := range res.Observations {
			if o.Match == nil || (o.Kind != scanner.ObsMatch && o.Kind != scanner.ObsTech) {
				continue
			}
			extracted := o.Match.Extracted
			if extracted == nil {
				extracted = []string{}
			}
			out.Matches = append(out.Matches, TestMatch{
				TemplateID: o.Match.TemplateID,
				Name:       o.Match.Name,
				Severity:   o.Match.Severity,
				Matcher:    o.Match.Matcher,
				MatchedAt:  o.URL,
				Extracted:  extracted,
			})
		}
	}
	out.Matched = len(out.Matches) > 0

	if err := audit.Log(ctx, gen.New(s.Pool), userID(u), "signatures.test", "signature", ids(sig.ID), map[string]any{
		"name": sig.Name, "url": normalizedURL, "matched": out.Matched, "matches": len(out.Matches),
	}); err != nil {
		return TestResult{}, fmt.Errorf("audit signature test: %w", err)
	}
	return out, nil
}

func normalizeTestURL(raw string) (normalized, host string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("%w: url is required", ErrInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", "", fmt.Errorf("%w: url must be a valid http or https URL without credentials", ErrInvalidURL)
	}
	port := u.Port()
	if port != "" {
		p, perr := strconv.ParseUint(port, 10, 16)
		if perr != nil || p == 0 {
			return "", "", fmt.Errorf("%w: invalid port %q", ErrInvalidURL, port)
		}
	} else if u.Scheme == "http" {
		port = "80"
	} else {
		port = "443"
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip, perr := netip.ParseAddr(h); perr == nil && ip.Zone() == "" {
		h = ip.Unmap().String()
	}
	u.Host = net.JoinHostPort(h, port)
	if u.Path == "/" && !u.ForceQuery && u.RawQuery == "" && u.Fragment == "" {
		u.Path, u.RawPath = "", ""
	}
	return u.String(), h, nil
}

func resolveTestHost(ctx context.Context, host string, resolver targets.Resolver) ([]netip.Addr, []string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, nil, fmt.Errorf("%w: zoned IP addresses are not supported", ErrInvalidURL)
		}
		ip = ip.Unmap()
		if err := checkTestAddr(ip); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrOutOfScope, err)
		}
		return []netip.Addr{ip}, nil, nil
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, fmt.Errorf("%w: cannot resolve %q: %v", ErrInvalidURL, host, err)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("%w: %q has no IPv4 address", ErrInvalidURL, host)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	for _, a := range out {
		if err := checkTestAddr(a); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrOutOfScope, err)
		}
	}
	return out, []string{host}, nil
}

func checkTestAddr(a netip.Addr) error {
	switch {
	case !a.Is4():
		return fmt.Errorf("%s: IPv6 addresses are not supported", a)
	case a.IsUnspecified(), a.IsLoopback(), a.IsMulticast(), a.IsLinkLocalUnicast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%s: loopback, link-local, multicast and unspecified addresses are not scannable", a)
	}
	return nil
}

type scopeSet struct {
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
	domains  []string
}

func buildScopeSet(ctx context.Context, values []string, resolver targets.Resolver) (*scopeSet, error) {
	ss := &scopeSet{addrs: map[netip.Addr]struct{}{}}
	for _, raw := range values {
		k, v, err := targets.Classify(raw)
		if err != nil {
			continue
		}
		switch k {
		case targets.KindIP:
			ss.addrs[netip.MustParseAddr(v).Unmap()] = struct{}{}
		case targets.KindCIDR:
			ss.prefixes = append(ss.prefixes, netip.MustParsePrefix(v).Masked())
		case targets.KindDomain:
			ss.domains = append(ss.domains, v)
			if resolver != nil {
				if addrs, err := resolver.LookupNetIP(ctx, "ip4", v); err == nil {
					for _, a := range addrs {
						if a = a.Unmap(); a.Is4() {
							ss.addrs[a] = struct{}{}
						}
					}
				} else if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
		}
	}
	return ss, nil
}

func (ss *scopeSet) empty() bool {
	return len(ss.addrs) == 0 && len(ss.prefixes) == 0 && len(ss.domains) == 0
}

func (ss *scopeSet) match(ip netip.Addr, hostnames []string) bool {
	if _, ok := ss.addrs[ip]; ok {
		return true
	}
	for _, p := range ss.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	for _, d := range ss.domains {
		for _, h := range hostnames {
			if h == d || strings.HasSuffix(h, "."+d) {
				return true
			}
		}
	}
	return false
}

func (s *Store) checkURLScope(ctx context.Context, ips []netip.Addr, hostnames []string, resolver targets.Resolver) error {
	q := gen.New(s.Pool)
	ts, err := q.ListAllTargets(ctx)
	if err != nil {
		return fmt.Errorf("load targets: %w", err)
	}
	rules, err := q.ListEffectiveScope(ctx, nil)
	if err != nil {
		return fmt.Errorf("load global scope: %w", err)
	}

	targetVals := make([]string, 0, len(ts))
	for _, t := range ts {
		targetVals = append(targetVals, t.Value)
	}
	var incVals, excVals []string
	for _, r := range rules {
		if r.List == "include" {
			incVals = append(incVals, r.Value)
		} else {
			excVals = append(excVals, r.Value)
		}
	}

	targetSet, err := buildScopeSet(ctx, targetVals, resolver)
	if err != nil {
		return err
	}
	incSet, err := buildScopeSet(ctx, incVals, resolver)
	if err != nil {
		return err
	}
	excSet, err := buildScopeSet(ctx, excVals, resolver)
	if err != nil {
		return err
	}

	if targetSet.empty() && incSet.empty() {
		return fmt.Errorf("%w: no targets or include rules are configured", ErrOutOfScope)
	}
	for _, ip := range ips {
		if excSet.match(ip, hostnames) {
			return fmt.Errorf("%w: %s is excluded by the blacklist", ErrOutOfScope, ip)
		}
		if !targetSet.empty() && !targetSet.match(ip, hostnames) {
			return fmt.Errorf("%w: %s is not in configured targets", ErrOutOfScope, ip)
		}
		if !incSet.empty() && !incSet.match(ip, hostnames) {
			return fmt.Errorf("%w: %s is not in the include scope", ErrOutOfScope, ip)
		}
	}
	return nil
}
