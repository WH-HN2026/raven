package httpx

import (
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/targets"
)

// BuildInput builds root URLs only for HTTP(S) services discovered in this batch.
func BuildInput(in scanner.Input, obs []scanner.Observation) scanner.Input {
	up := make(map[netip.Addr]bool)
	for _, o := range obs {
		if o.Kind == scanner.ObsHost && o.Up {
			up[o.IP.Unmap()] = true
		}
	}
	batch := make(map[netip.Addr]bool, len(in.IPs))
	for _, ip := range in.IPs {
		batch[ip.Unmap()] = true
	}
	var out scanner.Input
	out.Hostnames = in.Hostnames
	addresses := make(map[netip.Addr]bool)
	seen := make(map[string]bool)
	for _, o := range obs {
		ip := o.IP.Unmap()
		if o.Kind != scanner.ObsService || !batch[ip] || !up[ip] || o.Port == 0 || o.Proto != "tcp" {
			continue
		}
		scheme := serviceScheme(o.Service)
		if scheme == "" {
			continue
		}
		addresses[ip] = true
		port := strconv.Itoa(int(o.Port))
		for _, host := range append([]string{ip.String()}, in.Hostnames[ip]...) {
			kind, host, err := targets.Classify(host)
			if err != nil || (kind != targets.KindDomain && host != ip.String()) {
				continue
			}
			u := scheme + "://" + net.JoinHostPort(host, port)
			if !seen[u] {
				seen[u] = true
				out.URLs = append(out.URLs, u)
			}
		}
	}
	for ip := range addresses {
		out.IPs = append(out.IPs, ip)
	}
	slices.SortFunc(out.IPs, netip.Addr.Compare)
	slices.Sort(out.URLs)
	return out
}

func serviceScheme(service string) string {
	switch {
	case service == "https", strings.HasPrefix(service, "https-"), strings.HasPrefix(service, "ssl/http"):
		return "https"
	case service == "http", strings.HasPrefix(service, "http-"):
		return "http"
	default:
		return ""
	}
}

// parseURL puts default ports back when httpx elides them.
func parseURL(raw string) (*url.URL, uint16, bool) {
	u, err := url.Parse(raw)
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
	u.Host = net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	if u.Path == "/" && u.RawPath == "" {
		u.Path = ""
	}
	return u, uint16(p), true
}
