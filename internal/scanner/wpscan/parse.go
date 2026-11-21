package wpscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/scanner"
)

type report struct {
	StartTime           int64                     `json:"start_time"`
	TargetURL           string                    `json:"target_url"`
	TargetIP            string                    `json:"target_ip"`
	EffectiveURL        string                    `json:"effective_url"`
	Version             *versionInfo              `json:"version"`
	MainTheme           *componentInfo            `json:"main_theme"`
	Plugins             map[string]*componentInfo `json:"plugins"`
	Themes              map[string]*componentInfo `json:"themes"`
	InterestingFindings []json.RawMessage         `json:"interesting_findings"`
}

type versionInfo struct {
	Number     string `json:"number"`
	Status     string `json:"status"`
	Confidence int    `json:"confidence"`
}

type componentInfo struct {
	Slug    string       `json:"slug"`
	Version *versionInfo `json:"version"`
}

// Parse reads one WPScan JSON report or a stream of newline-delimited WPScan
// JSON reports (one per scanned URL) and indexes them by target IP for
// per-Asset DefectDojo reimport.
func Parse(raw []byte) (*scanner.Result, error) {
	res := &scanner.Result{Raw: raw}
	byIP := make(map[netip.Addr][][]byte)

	dec := json.NewDecoder(bytes.NewReader(raw))
	for i := 0; ; i++ {
		var rawObj json.RawMessage
		err := dec.Decode(&rawObj)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("wpscan: invalid JSON report #%d: %w", i+1, err)
		}
		trimmed := bytes.TrimSpace(rawObj)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("wpscan: report #%d is not a JSON object", i+1)
		}
		var rep report
		if err := json.Unmarshal(trimmed, &rep); err != nil {
			return nil, fmt.Errorf("wpscan: decode report #%d: %w", i+1, err)
		}
		ip, port, origin, ok := rep.targetIdentity()
		if !ok {
			continue
		}
		byIP[ip] = append(byIP[ip], trimmed)
		res.Observations = append(res.Observations, rep.observations(ip, port, origin)...)
	}

	res.PerIP = func(ip netip.Addr) []byte {
		docs := byIP[ip.Unmap()]
		switch len(docs) {
		case 0:
			return nil
		case 1:
			return docs[0]
		default:
			merged, err := mergeReports(docs)
			if err != nil {
				return docs[0]
			}
			return merged
		}
	}
	return res, nil
}

func (r *report) targetIdentity() (netip.Addr, uint16, string, bool) {
	target := r.TargetURL
	if target == "" {
		target = r.EffectiveURL
	}
	u, port, ok := webURL(target)
	if !ok {
		return netip.Addr{}, 0, "", false
	}
	ipText := strings.TrimSpace(r.TargetIP)
	if ipText == "" {
		ipText = u.Hostname()
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, 0, "", false
	}
	ip = ip.Unmap()
	origin := u.Scheme + "://" + u.Host
	return ip, port, origin, true
}

func (r *report) observations(ip netip.Addr, port uint16, origin string) []scanner.Observation {
	var at time.Time
	if r.StartTime > 0 {
		at = time.Unix(r.StartTime, 0).UTC()
	}
	var out []scanner.Observation
	seen := map[string]bool{}
	add := func(product, ver string) {
		product = strings.TrimSpace(product)
		ver = strings.TrimSpace(ver)
		if product == "" {
			return
		}
		key := strings.ToLower(product) + "|" + ver
		if seen[key] {
			return
		}
		seen[key] = true
		tech := product
		if ver != "" {
			tech = product + ":" + ver
		}
		obs := scanner.Observation{
			Kind:    scanner.ObsTech,
			IP:      ip,
			At:      at,
			Port:    port,
			Proto:   "tcp",
			URL:     origin,
			Product: product,
			Version: ver,
			Tech:    tech,
		}
		if c, _, ok := cve.CPEForTech(product); ok {
			obs.CPE = cve.FormatCPE(c, ver)
		}
		out = append(out, obs)
	}

	if r.Version != nil && strings.TrimSpace(r.Version.Number) != "" {
		add("WordPress", r.Version.Number)
	} else {
		add("WordPress", "")
	}

	if r.MainTheme != nil && strings.TrimSpace(r.MainTheme.Slug) != "" {
		var ver string
		if r.MainTheme.Version != nil {
			ver = r.MainTheme.Version.Number
		}
		add(r.MainTheme.Slug, ver)
	}

	addMap := func(m map[string]*componentInfo) {
		if len(m) == 0 {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			c := m[k]
			if c == nil {
				continue
			}
			slug := strings.TrimSpace(c.Slug)
			if slug == "" {
				slug = k
			}
			var ver string
			if c.Version != nil {
				ver = c.Version.Number
			}
			add(slug, ver)
		}
	}
	addMap(r.Plugins)
	addMap(r.Themes)

	return out
}

// mergeReports merges multiple WPScan JSON reports for the same IP (e.g.,
// WordPress on two ports) into one valid WPScan JSON object for DefectDojo's
// WpscanParser, which expects a single top-level JSON object.
func mergeReports(docs [][]byte) ([]byte, error) {
	var base map[string]any
	if err := json.Unmarshal(docs[0], &base); err != nil {
		return nil, err
	}
	for _, doc := range docs[1:] {
		var next map[string]any
		if err := json.Unmarshal(doc, &next); err != nil {
			return nil, err
		}
		if items, ok := next["interesting_findings"].([]any); ok && len(items) > 0 {
			existing, _ := base["interesting_findings"].([]any)
			base["interesting_findings"] = append(existing, items...)
		}
		for _, field := range []string{"plugins", "themes"} {
			if m, ok := next[field].(map[string]any); ok && len(m) > 0 {
				dst, _ := base[field].(map[string]any)
				if dst == nil {
					dst = make(map[string]any, len(m))
				}
				maps.Copy(dst, m)
				base[field] = dst
			}
		}
		if base["version"] == nil && next["version"] != nil {
			base["version"] = next["version"]
		}
	}
	return json.Marshal(base)
}
