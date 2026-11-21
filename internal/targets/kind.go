// Package targets turns user input (manual text, CSV, JSON) into target
// entries and expands targets + scope rules into the IP list a run scans
// (architecture §3.1, §9 "Scope").
package targets

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Kind of a target or scope value.
type Kind string

const (
	KindIP     Kind = "ip"
	KindCIDR   Kind = "cidr"
	KindDomain Kind = "domain"
)

// DefaultMaxHostBits caps how large a target CIDR may be: at most 2^16
// addresses (a /16 for IPv4). Scope rules are filters and have no cap.
const DefaultMaxHostBits = 16

// Classify auto-detects the kind of value and returns its canonical form:
// IPs in netip notation, CIDRs masked to their network address, domains
// lower-cased without a trailing dot.
func Classify(value string) (Kind, string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", "", errors.New("empty value")
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", "", fmt.Errorf("invalid CIDR %q", v)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		return KindCIDR, p.String(), nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return KindIP, a.Unmap().String(), nil
	}
	d, err := normalizeDomain(v)
	if err != nil {
		return "", "", err
	}
	return KindDomain, d, nil
}

func normalizeDomain(v string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(v), ".")
	if len(d) > 253 {
		return "", fmt.Errorf("domain %q is too long", v)
	}
	allDigits := true
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid domain %q", v)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", v)
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c == '-', c == '_':
				allDigits = false
			case c >= '0' && c <= '9':
			default:
				return "", fmt.Errorf("invalid value %q: not an IP, CIDR or domain", v)
			}
		}
	}
	if allDigits { // e.g. 10.0.0.256: a broken IP, not a host name
		return "", fmt.Errorf("invalid IP %q", v)
	}
	return d, nil
}

// checkTarget applies the target-only rules on top of Classify: IPv4 only
// (the scanner runs IPv4 nmap) and CIDRs within the size cap. No address
// range is special: which networks may be scanned is an operating rule
// (architecture §9), enforced through profile scope and the global blacklist.
func checkTarget(kind Kind, value string, maxHostBits int) error {
	var a netip.Addr
	switch kind {
	case KindIP:
		a = netip.MustParseAddr(value)
	case KindCIDR:
		p := netip.MustParsePrefix(value)
		a = p.Addr()
		if hb := a.BitLen() - p.Bits(); hb > maxHostBits {
			return fmt.Errorf("CIDR %s has 2^%d addresses; the limit is 2^%d (a /%d)", value, hb, maxHostBits, 32-maxHostBits)
		}
	default:
		return nil
	}
	return checkAddr(a)
}

func checkAddr(a netip.Addr) error {
	if !a.Is4() {
		return fmt.Errorf("%s: IPv6 targets are not supported", a)
	}
	return nil
}
