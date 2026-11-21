package httpx

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/scanner"
)

type record struct {
	At      time.Time         `json:"timestamp"`
	Input   string            `json:"input"`
	URL     string            `json:"url"`
	IP      string            `json:"host_ip"`
	Failed  bool              `json:"failed"`
	Status  int               `json:"status_code"`
	Title   string            `json:"title"`
	Headers map[string]string `json:"header"`
	TLS     json.RawMessage   `json:"tls"`
	Chain   []struct {
		URL      string `json:"request-url"`
		Location string `json:"location"`
	} `json:"chain"`
	Location    string   `json:"location"`
	FaviconHash string   `json:"favicon"`
	Tech        []string `json:"tech"`
}

// Parse normalizes httpx JSON lines and indexes the original records by IP.
func Parse(raw []byte) (*scanner.Result, error) { return parse(raw, nil) }

func parse(raw []byte, accept func(*url.URL, netip.Addr) bool) (*scanner.Result, error) {
	res := &scanner.Result{Raw: raw}
	lines := make(map[netip.Addr][][]byte)
	for i, line := range bytes.SplitAfter(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("httpx: invalid JSON record on line %d", i+1)
		}
		if r.Failed || r.Status < 100 || r.Status > 599 {
			continue
		}
		u, port, ok := parseURL(cmp.Or(r.Input, r.URL))
		if !ok {
			continue
		}
		ip, err := netip.ParseAddr(cmp.Or(r.IP, u.Hostname()))
		ip = ip.Unmap()
		if err != nil || (accept != nil && !accept(u, ip)) {
			continue
		}

		lines[ip] = append(lines[ip], line)
		obs := scanner.Observation{
			Kind: scanner.ObsHTTP, IP: ip, At: r.At, Port: port, Proto: "tcp", URL: u.String(),
			HTTP: r.httpInfo(u),
		}
		if _, err := netip.ParseAddr(u.Hostname()); err != nil {
			obs.Hostname = u.Hostname()
		}
		res.Observations = append(res.Observations, obs)
		for _, technology := range obs.HTTP.Technologies {
			to := scanner.Observation{
				Kind: scanner.ObsTech, IP: ip, Hostname: obs.Hostname, At: r.At,
				Port: port, Proto: "tcp", URL: obs.URL, Tech: technology,
			}
			if c, v, ok := cve.CPEForTech(technology); ok {
				to.CPE = cve.FormatCPE(c, v)
				to.Version = v
			}
			res.Observations = append(res.Observations, to)
		}
	}
	res.PerIP = func(ip netip.Addr) []byte { return bytes.Join(lines[ip.Unmap()], nil) }
	return res, nil
}

func (r record) httpInfo(u *url.URL) *scanner.HTTPInfo {
	info := &scanner.HTTPInfo{
		Status: r.Status, Title: r.Title, FaviconHash: r.FaviconHash,
		Headers: make(map[string]string, len(r.Headers)),
	}
	for k, v := range r.Headers {
		info.Headers[http.CanonicalHeaderKey(strings.ReplaceAll(k, "_", "-"))] = v
	}
	if v := info.Headers["Set-Cookie"]; v != "" {
		info.Cookies = splitCookies(v)
	}
	if len(r.TLS) > 0 && string(r.TLS) != "null" {
		info.TLSCert = string(r.TLS)
	}
	for _, hop := range r.Chain {
		base, err := url.Parse(hop.URL)
		if err == nil {
			info.Redirects = appendRedirect(info.Redirects, base, hop.Location)
		}
	}
	if len(r.Chain) == 0 {
		info.Redirects = appendRedirect(info.Redirects, u, r.Location)
	}
	slices.Sort(r.Tech)
	info.Technologies = slices.Compact(r.Tech)
	return info
}

func appendRedirect(chain []string, base *url.URL, location string) []string {
	if location == "" {
		return chain
	}
	to, err := base.Parse(location)
	if err != nil || (to.Scheme != "http" && to.Scheme != "https") {
		return chain
	}
	to.User = nil
	return append(chain, to.String())
}

// httpx joins repeated header fields with ", ". A cookie's Expires date may
// also contain a comma, so split only when another cookie pair starts.
var cookieStart = regexp.MustCompile(",[ \t]*[!#$%&'*+.\\^_`|~0-9A-Za-z-]+=")

func splitCookies(header string) []string {
	var cookies []string
	start := 0
	for _, match := range cookieStart.FindAllStringIndex(header, -1) {
		cookies = append(cookies, strings.TrimSpace(header[start:match[0]]))
		start = match[0] + 1
	}
	return append(cookies, strings.TrimSpace(header[start:]))
}
