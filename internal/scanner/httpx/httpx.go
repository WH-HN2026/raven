// Package httpx collects HTTP response metadata from discovered services.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// Scanner runs ProjectDiscovery httpx. Its zero value uses httpx from PATH.
type Scanner struct {
	Binary string // executable name or absolute path
}

var _ scanner.Scanner = (*Scanner)(nil)

func (*Scanner) Name() string         { return "httpx" }
func (*Scanner) DojoScanType() string { return "httpx Scan" }

// BuildArgs is the complete flag allowlist. Targets go over stdin. Restrict
// redirects to the original hostname and every dial to the eligible batch IPs,
// including dials for favicons linked in response bodies.
func BuildArgs(ips, resolvers []netip.Addr, opt scanner.Options) ([]string, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("httpx: rate limit must be positive")
	}
	if len(ips) == 0 {
		return nil, errors.New("httpx: no eligible addresses")
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() || ip.Zone() != "" {
			return nil, errors.New("httpx: invalid address")
		}
		addresses = append(addresses, ip.Unmap().String())
	}
	var nameservers []string
	for _, ip := range resolvers {
		if !ip.IsValid() {
			return nil, errors.New("httpx: invalid resolver address")
		}
		nameservers = append(nameservers, net.JoinHostPort(ip.String(), "53"))
	}
	if len(nameservers) == 0 {
		return nil, errors.New("httpx: no system resolvers configured")
	}
	return []string{
		"-silent", "-json", "-title", "-sc", "-irh", "-tls-grab", "-favicon", "-td",
		"-fhr", "-include-chain", "-nfs", "-disable-update-check", "-auth=false", "-cdn=false",
		"-rl", strconv.Itoa(opt.RateLimit), "-allow", strings.Join(addresses, ","),
		"-r", strings.Join(nameservers, ","),
	}, nil
}

func (s *Scanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	resolvers, err := systemResolvers()
	if err != nil {
		return nil, err
	}
	args, err := BuildArgs(in.IPs, resolvers, opt)
	if err != nil {
		return nil, err
	}

	scoped := make(map[string]bool, len(in.URLs))
	for _, raw := range in.URLs {
		u, _, ok := parseURL(raw)
		if !ok || u.String() != raw || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, errors.New("httpx: expected a canonical root HTTP(S) URL with an explicit port")
		}
		scoped[raw] = true
	}
	if len(scoped) == 0 {
		return nil, errors.New("httpx: no URLs")
	}

	binary := s.Binary
	if binary == "" {
		binary = "httpx"
	}
	dir, err := os.MkdirTemp("", "asi-httpx-")
	if err != nil {
		return nil, fmt.Errorf("httpx: create config directory: %w", err)
	}
	defer os.RemoveAll(dir)

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = strings.NewReader(strings.Join(in.URLs, "\n") + "\n")
	// Keep httpx independent of user configuration, proxy variables and cloud credentials.
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir}
	raw, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("httpx: %w", err)
	}

	return parse(raw, func(u *url.URL, ip netip.Addr) bool {
		if !scoped[u.String()] {
			return false
		}
		if hostIP, err := netip.ParseAddr(u.Hostname()); err == nil {
			return hostIP.Unmap() == ip
		}
		ipURL := *u
		ipURL.Host = net.JoinHostPort(ip.String(), u.Port())
		for _, host := range in.Hostnames[ip] {
			if strings.EqualFold(strings.TrimSuffix(host, "."), u.Hostname()) {
				return scoped[ipURL.String()]
			}
		}
		return false
	})
}

// httpx adds public fallback resolvers unless its resolver list is explicit.
// Use the local resolver configuration already used to expand the targets.
func systemResolvers() ([]netip.Addr, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("httpx: read system resolvers: %w", err)
	}
	var resolvers []netip.Addr
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip, err := netip.ParseAddr(fields[1]); err == nil {
			resolvers = append(resolvers, ip)
		}
	}
	return resolvers, nil
}
