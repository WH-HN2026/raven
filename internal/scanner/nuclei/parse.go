package nuclei

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/scanner"
)

type record struct {
	TemplateID string    `json:"template-id"`
	Type       string    `json:"type"`
	URL        string    `json:"url"`
	MatchedAt  string    `json:"matched-at"`
	IP         string    `json:"ip"`
	At         time.Time `json:"timestamp"`
	Matcher    string    `json:"matcher-name"`
	Extractor  string    `json:"extractor-name"`
	Extracted  []string  `json:"extracted-results"`
	Info       struct {
		Name     string         `json:"name"`
		Severity string         `json:"severity"`
		Tags     []string       `json:"tags"`
		Metadata map[string]any `json:"metadata"`
	} `json:"info"`
}

// Parse reads nuclei JSONL and indexes the original records for per-IP export.
func Parse(raw []byte) (*scanner.Result, error) { return parse(raw, nil) }

func parse(raw []byte, scope map[string]netip.Addr) (*scanner.Result, error) {
	res := &scanner.Result{Raw: raw}
	lines := make(map[netip.Addr][][]byte)
	for i, line := range bytes.SplitAfter(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("nuclei: invalid JSON record on line %d", i+1)
		}
		o, ok := r.observation()
		if !ok || (scope != nil && scope[o.Match.SourceURL] != o.IP) {
			continue
		}
		lines[o.IP] = append(lines[o.IP], line)
		res.Observations = append(res.Observations, o)
	}
	res.PerIP = func(ip netip.Addr) []byte { return bytes.Join(lines[ip.Unmap()], nil) }
	return res, nil
}

var (
	cpeComponent = regexp.MustCompile(`^(?:[a-z0-9_.-]|\\[!+])+$`)
	versionValue = regexp.MustCompile(`^[0-9][0-9a-zA-Z._+~-]{0,63}$`)
)

func (r record) observation() (scanner.Observation, bool) {
	if r.TemplateID == "" || r.Info.Name == "" {
		return scanner.Observation{}, false
	}
	matched := r.MatchedAt
	switch r.Type {
	case "http":
		if matched == "" {
			matched = r.URL
		}
	case "ssl":
		matched = "https://" + matched
	default:
		return scanner.Observation{}, false
	}
	matchedURL, port, ok := webURL(matched)
	if !ok && r.Type == "http" && r.URL != "" {
		// Active/fuzzing templates can echo unescaped payload characters in matched-at.
		// Fall back to the clean input URL so valid matches are not dropped from PerIP.
		matchedURL, port, ok = webURL(r.URL)
	}
	if !ok {
		return scanner.Observation{}, false
	}
	origin := originOf(matchedURL)
	if r.URL != "" {
		inputURL, _, ok := webURL(r.URL)
		if !ok || originOf(inputURL) != origin {
			return scanner.Observation{}, false
		}
	}
	ipText := r.IP
	if ipText == "" {
		ipText = matchedURL.Hostname()
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil || ip.Zone() != "" {
		return scanner.Observation{}, false
	}
	ip = ip.Unmap()
	var hostname string
	if _, err := netip.ParseAddr(matchedURL.Hostname()); err != nil {
		hostname = matchedURL.Hostname()
	} else if !literalAddress(matchedURL.Hostname(), ip) {
		return scanner.Observation{}, false
	}
	o := scanner.Observation{
		Kind: scanner.ObsMatch, IP: ip, Hostname: hostname, At: r.At,
		Port: port, Proto: "tcp", URL: matchedURL.String(),
		Match: &scanner.MatchInfo{
			TemplateID: r.TemplateID, Name: r.Info.Name, Severity: r.Info.Severity,
			Tags: r.Info.Tags, Matcher: r.Matcher, Extracted: r.Extracted, SourceURL: origin,
		},
	}
	vendor, _ := r.Info.Metadata["vendor"].(string)
	product, _ := r.Info.Metadata["product"].(string)
	vendor, product = cpePart(vendor), cpePart(product)
	if cpeComponent.MatchString(vendor) && cpeComponent.MatchString(product) {
		o.Product = product
		o.CPE = vendor + ":" + product
	}
	if len(r.Extracted) == 1 && strings.HasPrefix(r.Extractor, "version") && versionValue.MatchString(r.Extracted[0]) {
		o.Version = r.Extracted[0]
	}
	if slices.Contains(r.Info.Tags, "tech") {
		o.Kind, o.Tech = scanner.ObsTech, r.Info.Name
		if o.Product != "" {
			o.Tech = o.Product
		} else if r.Matcher != "" {
			o.Tech = r.Matcher
		}
	}
	if o.CPE == "" {
		for _, cand := range []string{o.Tech, r.TemplateID, r.Info.Name} {
			if c, v, ok := cve.CPEForTech(cand); ok {
				o.CPE = c
				if o.Version == "" && v != "" {
					o.Version = v
				}
				break
			}
		}
	}
	return o, true
}

func cpePart(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), `\\`, `\`)
}

func originOf(u *url.URL) string {
	return u.Scheme + "://" + u.Host
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
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		host = ip.Unmap().String()
	}
	u.Host = net.JoinHostPort(host, strconv.FormatUint(p, 10))
	return u, uint16(p), true
}
