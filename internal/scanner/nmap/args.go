package nmap

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// AllowedScripts are the only NSE scripts we ever run (architecture §9).
// All four are in nmap's "safe" category and only read what a normal client
// sees: the HTTP title and headers of "/", the TLS certificate, and the banner.
var AllowedScripts = []string{"http-title", "http-headers", "ssl-cert", "banner"}

// valueKind says how an allowlisted flag takes its value.
type valueKind int

const (
	noValue  valueKind = iota // -sS
	separate                  // -p 80, --max-rate 100 (or --max-rate=100 for long flags)
	attached                  // -PS22,80 (value glued to the flag)
)

type flagRule struct {
	kind  valueKind
	check func(string) error // nil for noValue
}

// allowedFlags is the complete list of nmap flags this package may emit.
// Anything else (-A, -sC, -O, -sU, -Pn, -iL, --script-args, -oN, --datadir,
// --script outside AllowedScripts, ...) is rejected by validateArgs.
var allowedFlags = map[string]flagRule{
	// scan types: TCP SYN scan + service/version detection
	"-sS": {kind: noValue},
	"-sV": {kind: noValue},
	// host discovery probes (no -Pn: we need nmap to tell us which hosts are down)
	"-PE": {kind: noValue},
	"-PP": {kind: noValue},
	"-PS": {kind: attached, check: checkPortList},
	"-PA": {kind: attached, check: checkPortList},
	// what to scan and how fast
	"-p":                  {kind: separate, check: CheckPorts},
	"--max-rate":          {kind: separate, check: checkPositiveInt(1_000_000)},
	"--max-retries":       {kind: separate, check: checkIntRange(0, 10)},
	"--host-timeout":      {kind: separate, check: checkDuration},
	"--script-timeout":    {kind: separate, check: checkDuration},
	"--version-intensity": {kind: separate, check: checkIntRange(0, 9)},
	"-T0":                 {kind: noValue},
	"-T1":                 {kind: noValue},
	"-T2":                 {kind: noValue},
	"-T3":                 {kind: noValue},
	"-T4":                 {kind: noValue},
	// scripts: allowlisted ones only
	"--script": {kind: separate, check: checkScripts},
	// output
	"-n":       {kind: noValue},
	"-v":       {kind: noValue},
	"--reason": {kind: noValue},
	"-oX":      {kind: separate, check: checkOutput},
}

// baseFlags are always present, in this order, before any extra flags.
//
// Why each one:
//   - no -Pn and -v: nmap does host discovery first (the "-sn phase" of
//     architecture §3.3) and, with -v, writes down hosts to the XML too, so
//     one invocation yields both up and down hosts;
//   - -PE -PP -PS... -PA...: ICMP echo/timestamp plus TCP SYN/ACK pings on
//     common ports, so hosts that drop ICMP are still found (on a local L2
//     segment nmap uses ARP instead, which is even gentler);
//   - -sS -sV on the profile's ports: the "-sS -sV phase";
//   - -n: no reverse DNS. Scans must not generate DNS traffic to resolvers
//     outside the scanned range, rDNS on a /16 is slow, and Dojo keys the
//     Location on the PTR name when there is one, while our Assets are keyed
//     by IP. Hostnames come from domain targets (S1) instead;
//   - -T3 --max-retries 2 --host-timeout 15m --script-timeout 30s: default
//     timing, bounded retries, and one slow host or script can't stall a batch;
//   - --reason: why a host/port has its state (useful when debugging misses).
var discoveryProbes = []string{"-PE", "-PP", "-PS21,22,23,25,80,443,445,3389,8080", "-PA80,443"}

// BuildArgs returns the full nmap argument vector for one batch. It is pure:
// same input, same output. Every flag, including extra ones, passes
// validateArgs, which also rejects a second copy of a flag we already set
// (e.g. another -p or --max-rate). Targets are formatted from netip.Addr
// values, so nothing user-supplied can become a flag.
func BuildArgs(ips []netip.Addr, opt scanner.Options, extra []string) ([]string, error) {
	if opt.MaxRate <= 0 {
		return nil, fmt.Errorf("nmap: --max-rate must be > 0, got %d", opt.MaxRate)
	}
	if opt.Ports == "" {
		return nil, errors.New("nmap: port list is empty")
	}
	targets, err := targetArgs(ips)
	if err != nil {
		return nil, err
	}

	args := []string{"-sS", "-sV"}
	args = append(args, discoveryProbes...)
	args = append(args,
		"-p", opt.Ports,
		"--script", strings.Join(AllowedScripts, ","),
		"--max-rate", strconv.Itoa(opt.MaxRate),
		"-T3", "--max-retries", "2", "--host-timeout", "15m", "--script-timeout", "30s",
		"-n", "-v", "--reason",
		"-oX", "-",
	)
	args = append(args, extra...)
	if err := validateArgs(args); err != nil {
		return nil, err
	}
	return append(args, targets...), nil
}

func targetArgs(ips []netip.Addr) ([]string, error) {
	if len(ips) == 0 {
		return nil, errors.New("nmap: no targets")
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() {
			return nil, errors.New("nmap: invalid target address")
		}
		// IPv4 only: nmap needs -6 for IPv6 and can't mix families in one run,
		// and Dojo's Nmap parser only reads ipv4 addresses.
		if !ip.Is4() {
			return nil, fmt.Errorf("nmap: IPv6 target %s not supported", ip)
		}
		out = append(out, ip.String())
	}
	return out, nil
}

// validateArgs checks that every token is an allowlisted flag with a valid
// value and that no flag appears twice.
func validateArgs(args []string) error {
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasEq := a, "", false
		if strings.HasPrefix(a, "--") {
			name, val, hasEq = strings.Cut(a, "=")
		}
		rule, ok := allowedFlags[name]
		if !ok && !hasEq {
			// attached form: -PS22,80
			for _, p := range []string{"-PS", "-PA"} {
				if strings.HasPrefix(a, p) {
					name, val, rule, ok = p, a[len(p):], allowedFlags[p], true
				}
			}
		}
		if !ok {
			return fmt.Errorf("nmap: flag %q is not allowed", a)
		}
		key := name
		if strings.HasPrefix(name, "-T") {
			key = "-T" // -T0..-T4 are one setting
		}
		if seen[key] {
			return fmt.Errorf("nmap: flag %q given twice", key)
		}
		seen[key] = true

		switch rule.kind {
		case noValue:
			if hasEq {
				return fmt.Errorf("nmap: flag %q takes no value", name)
			}
			continue
		case attached:
			if a == name {
				return fmt.Errorf("nmap: flag %q needs a port list", name)
			}
		case separate:
			if !hasEq {
				if i+1 >= len(args) {
					return fmt.Errorf("nmap: flag %q needs a value", name)
				}
				i++
				val = args[i]
			}
		}
		if err := rule.check(val); err != nil {
			return fmt.Errorf("nmap: %s %q: %w", name, val, err)
		}
	}
	return nil
}

var (
	portSpecRE = regexp.MustCompile(`^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`)
	durationRE = regexp.MustCompile(`^[0-9]{1,6}(ms|s|m|h)?$`)
)

// CheckPorts validates an nmap port spec: digits, commas and ranges only
// (no "T:", "U:", names, "-" alone or open-ended ranges), ports 1–65535.
func CheckPorts(spec string) error {
	if !portSpecRE.MatchString(spec) {
		return errors.New("port spec may contain only digits, commas and ranges like 1-1024")
	}
	for part := range strings.SplitSeq(spec, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		l, err := parsePort(lo)
		if err != nil {
			return err
		}
		if isRange {
			h, err := parsePort(hi)
			if err != nil {
				return err
			}
			if l > h {
				return fmt.Errorf("range %s is reversed", part)
			}
		}
	}
	return nil
}

// checkPortList is for ping probes: a plain comma list of ports.
func checkPortList(s string) error {
	for p := range strings.SplitSeq(s, ",") {
		if _, err := parsePort(p); err != nil {
			return err
		}
	}
	return nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q out of range 1-65535", s)
	}
	return n, nil
}

func checkPositiveInt(maxV int) func(string) error {
	return checkIntRange(1, maxV)
}

func checkIntRange(lo, hi int) func(string) error {
	return func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < lo || n > hi || strconv.Itoa(n) != s {
			return fmt.Errorf("must be an integer in [%d, %d]", lo, hi)
		}
		return nil
	}
}

func checkDuration(s string) error {
	if !durationRE.MatchString(s) {
		return errors.New("must be a duration like 30s, 15m, 1h")
	}
	return nil
}

func checkScripts(s string) error {
	for name := range strings.SplitSeq(s, ",") {
		if !slices.Contains(AllowedScripts, name) {
			return fmt.Errorf("script %q is not allowed", name)
		}
	}
	return nil
}

func checkOutput(s string) error {
	if s != "-" {
		return errors.New("XML output goes to stdout only")
	}
	return nil
}
