package cve

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
)

// WPScanReport is the subset of WPScan's JSON output used for offline CVE
// matching (architecture §11): WordPress core version plus detected plugins
// and themes.
type WPScanReport struct {
	Version   *WPScanVersion             `json:"version"`
	MainTheme *WPScanComponent           `json:"main_theme"`
	Plugins   map[string]WPScanComponent `json:"plugins"`
	Themes    map[string]WPScanComponent `json:"themes"`
}

// WPScanVersion holds the detected version number of WordPress core or a component.
type WPScanVersion struct {
	Number string `json:"number"`
}

// WPScanComponent holds the detected slug and version of a WordPress plugin or theme.
type WPScanComponent struct {
	Slug    string         `json:"slug"`
	Version *WPScanVersion `json:"version"`
}

// InstancesFromWPScan builds offline CVE matcher instances from WordPress core,
// plugin and theme versions reported by wpscan. Only products tracked in our
// committed dataset (via CPEForTech, WordPress core at minimum) emit instances;
// untracked plugins and themes are skipped.
func InstancesFromWPScan(ip netip.Addr, port int32, proto string, coreVersion string, plugins, themes map[string]string) []Instance {
	var out []Instance
	add := func(product, ver string) {
		product = strings.TrimSpace(product)
		ver = strings.TrimSpace(ver)
		if product == "" || ver == "" {
			return
		}
		if c, _, ok := CPEForTech(product); ok {
			out = append(out, Instance{
				IP: ip, Port: port, Proto: proto,
				CPE: FormatCPE(c, ver), Product: product, Version: ver,
			})
		}
	}
	add("WordPress", coreVersion)
	addSorted := func(m map[string]string) {
		if len(m) == 0 {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			add(k, m[k])
		}
	}
	addSorted(plugins)
	addSorted(themes)
	return out
}

// InstancesFromWPScanJSON parses one WPScan JSON report and extracts offline
// CVE matcher instances for tracked products.
func InstancesFromWPScanJSON(ip netip.Addr, port int32, proto string, raw []byte) []Instance {
	if len(raw) == 0 {
		return nil
	}
	var rep WPScanReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil
	}
	var coreVer string
	if rep.Version != nil {
		coreVer = rep.Version.Number
	}
	plugins := make(map[string]string, len(rep.Plugins))
	for slug, comp := range rep.Plugins {
		if comp.Version == nil || strings.TrimSpace(comp.Version.Number) == "" {
			continue
		}
		name := strings.TrimSpace(comp.Slug)
		if name == "" {
			name = slug
		}
		plugins[name] = comp.Version.Number
	}
	themes := make(map[string]string, len(rep.Themes)+1)
	if rep.MainTheme != nil && rep.MainTheme.Version != nil && strings.TrimSpace(rep.MainTheme.Version.Number) != "" {
		if slug := strings.TrimSpace(rep.MainTheme.Slug); slug != "" {
			themes[slug] = rep.MainTheme.Version.Number
		}
	}
	for slug, comp := range rep.Themes {
		if comp.Version == nil || strings.TrimSpace(comp.Version.Number) == "" {
			continue
		}
		name := strings.TrimSpace(comp.Slug)
		if name == "" {
			name = slug
		}
		themes[name] = comp.Version.Number
	}
	return InstancesFromWPScan(ip, port, proto, coreVer, plugins, themes)
}
