package targets

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Resolver resolves host names. *net.Resolver (e.g. net.DefaultResolver)
// satisfies it; tests inject a fake so they never touch DNS.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Rule is one scope entry (architecture §5 scope_entries).
type Rule struct {
	Kind  Kind
	Value string
}

// Scope holds the rules one run applies: the global entries plus the
// profile's own, already merged by list.
type Scope struct {
	Include []Rule
	Exclude []Rule // global blacklist + profile excludes
}

// Limits bound the expansion; zero fields take the defaults.
type Limits struct {
	MaxHostBits int // largest target CIDR, in host bits (default 24 = a /8)
	MaxIPs      int // most addresses from all targets, overlaps counted, before de-dup and filtering (default 1<<25)
}

func (l Limits) withDefaults() Limits {
	if l.MaxHostBits == 0 {
		l.MaxHostBits = DefaultMaxHostBits
	}
	if l.MaxIPs == 0 {
		l.MaxIPs = 1 << 25
	}
	return l
}

// ScanList is what a run scans.
type ScanList struct {
	IPs       []netip.Addr            // sorted, unique, in scope
	Hostnames map[netip.Addr][]string // known host names per scanned IP (for vhost probes)
	Domains   map[string][]netip.Addr // every resolved target domain → its IPv4 addresses
	Warnings  []string                // unresolvable domains, dropped addresses
	Stats     struct {
		Candidates  int // unique IPs from the targets
		NotIncluded int // dropped: matched no include rule
		Excluded    int // dropped: matched an exclude rule
		Rejected    int // dropped: IPv6 (see checkAddr)
	}
}

// Expand turns targets into the scan list:
//
//  1. CIDRs are expanded (each must fit Limits.MaxHostBits) and domains are
//     resolved to IPv4 addresses; the domain → IP map is kept, and each IP
//     remembers its host names.
//  2. Include: an IP is kept only if it matches an include rule (IP equal,
//     inside an include CIDR, one of an include domain's resolved IPs, or one
//     of its host names equals or is a subdomain of an include domain).
//     If the scope has no include rules at all, the targets themselves are
//     the include set: everything from step 1 is kept.
//  3. Exclude, always last: an IP matching any exclude rule (same matching
//     as include) is dropped, whatever includes say. Exclusions always win.
//  4. IPs are de-duplicated and sorted.
//
// A domain that does not resolve is reported in Warnings, not as an error.
// An exclude domain that does not resolve still excludes by host name.
func Expand(ctx context.Context, targets []Entry, scope Scope, r Resolver, lim Limits) (*ScanList, error) {
	lim = lim.withDefaults()
	sl := &ScanList{Hostnames: map[netip.Addr][]string{}, Domains: map[string][]netip.Addr{}}
	// A slice, sorted and de-duplicated below, not a map: a /8 is 2^24
	// addresses and a map of that size costs several times the memory.
	// Sized up front so a /8 is allocated once (domains may still grow it).
	size := 0
	for _, t := range targets {
		if p, err := netip.ParsePrefix(t.Value); t.Kind == KindCIDR && err == nil {
			if hb := p.Addr().BitLen() - p.Bits(); hb <= lim.MaxHostBits {
				size += 1 << hb
			}
		} else if t.Kind == KindIP {
			size++
		}
	}
	cand := make([]netip.Addr, 0, min(size, lim.MaxIPs))
	grow := func(n int) error {
		if len(cand)+n > lim.MaxIPs {
			return fmt.Errorf("expand targets: more than %d IPs", lim.MaxIPs)
		}
		cand = slices.Grow(cand, n)
		return nil
	}
	add := func(a netip.Addr) error {
		if err := grow(1); err != nil {
			return err
		}
		cand = append(cand, a)
		return nil
	}

	for _, t := range targets {
		switch t.Kind {
		case KindIP:
			a, err := netip.ParseAddr(t.Value)
			if err != nil {
				return nil, fmt.Errorf("expand target %q: %w", t.Value, err)
			}
			if err := add(a.Unmap()); err != nil {
				return nil, err
			}
		case KindCIDR:
			p, err := netip.ParsePrefix(t.Value)
			if err != nil {
				return nil, fmt.Errorf("expand target %q: %w", t.Value, err)
			}
			p = p.Masked()
			hb := p.Addr().BitLen() - p.Bits()
			if hb > lim.MaxHostBits {
				return nil, fmt.Errorf("expand target %s: 2^%d addresses exceeds the limit of 2^%d", p, hb, lim.MaxHostBits)
			}
			if err := grow(1 << hb); err != nil {
				return nil, err
			}
			for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
				cand = append(cand, a)
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		case KindDomain:
			addrs, err := resolve(ctx, r, t.Value)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				sl.Warnings = append(sl.Warnings, fmt.Sprintf("resolve %s: %v", t.Value, err))
				continue
			}
			sl.Domains[t.Value] = addrs
			for _, a := range addrs {
				if err := add(a); err != nil {
					return nil, err
				}
				if !slices.Contains(sl.Hostnames[a], t.Value) {
					sl.Hostnames[a] = append(sl.Hostnames[a], t.Value)
				}
			}
		default:
			return nil, fmt.Errorf("expand target %q: unknown kind %q", t.Value, t.Kind)
		}
	}
	slices.SortFunc(cand, netip.Addr.Compare)
	cand = slices.Compact(cand)
	sl.Stats.Candidates = len(cand)

	inc, err := newMatcher(ctx, scope.Include, r, sl)
	if err != nil {
		return nil, err
	}
	exc, err := newMatcher(ctx, scope.Exclude, r, sl)
	if err != nil {
		return nil, err
	}
	sl.IPs = cand[:0] // filtered in place: cand is not used after this
	for _, a := range cand {
		names := sl.Hostnames[a]
		switch {
		case !inc.empty() && !inc.match(a, names):
			sl.Stats.NotIncluded++
		case exc.match(a, names): // exclusions last: they always win
			sl.Stats.Excluded++
		case checkAddr(a) != nil:
			sl.Stats.Rejected++
		default:
			sl.IPs = append(sl.IPs, a)
			continue
		}
		delete(sl.Hostnames, a)
	}
	sl.IPs = slices.Clip(sl.IPs)
	if sl.Stats.Rejected > 0 {
		sl.Warnings = append(sl.Warnings, fmt.Sprintf("dropped %d IPv6 addresses", sl.Stats.Rejected))
	}
	return sl, nil
}

// resolve returns the IPv4 addresses of host (sorted, unique).
func resolve(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	if r == nil {
		return nil, fmt.Errorf("no resolver")
	}
	addrs, err := r.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 address")
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out, nil
}

type matcher struct {
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
	domains  []string
}

func newMatcher(ctx context.Context, rules []Rule, r Resolver, sl *ScanList) (*matcher, error) {
	m := &matcher{addrs: map[netip.Addr]struct{}{}}
	for _, rule := range rules {
		k, v, err := Classify(rule.Value)
		if err != nil {
			return nil, fmt.Errorf("scope rule %q: %w", rule.Value, err)
		}
		switch k {
		case KindIP:
			m.addrs[netip.MustParseAddr(v)] = struct{}{}
		case KindCIDR:
			m.prefixes = append(m.prefixes, netip.MustParsePrefix(v))
		case KindDomain:
			m.domains = append(m.domains, v)
			addrs, err := resolve(ctx, r, v)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				sl.Warnings = append(sl.Warnings, fmt.Sprintf("resolve scope rule %s: %v (matching by host name only)", v, err))
				continue
			}
			for _, a := range addrs {
				m.addrs[a] = struct{}{}
			}
		}
	}
	return m, nil
}

func (m *matcher) empty() bool {
	return len(m.addrs) == 0 && len(m.prefixes) == 0 && len(m.domains) == 0
}

func (m *matcher) match(a netip.Addr, hostnames []string) bool {
	if _, ok := m.addrs[a]; ok {
		return true
	}
	for _, p := range m.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	for _, d := range m.domains {
		for _, h := range hostnames {
			if h == d || strings.HasSuffix(h, "."+d) {
				return true
			}
		}
	}
	return false
}
