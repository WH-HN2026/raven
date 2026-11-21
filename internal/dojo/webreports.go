package dojo

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nuclei"
)

// webReports collects the web scanners' reports and Asset tags for responding IPs.
func webReports(ips []netip.Addr, httpx, detection *scanner.Result) (map[netip.Addr][]scannerReport, map[netip.Addr][]string) {
	reports := make(map[netip.Addr][]scannerReport)
	tags := make(map[netip.Addr][]string)
	if httpx == nil {
		return reports, tags
	}
	for _, ip := range ips {
		// httpx emits one record per responding URL. An empty report would
		// close all its previous findings without a successful HTTP probe.
		if raw := bytes.TrimSpace(httpx.PerIP(ip)); len(raw) > 0 {
			reports[ip] = []scannerReport{{"httpx", "httpx Scan", "jsonl", raw}}
		}
	}
	for _, o := range httpx.Observations {
		if len(reports[o.IP]) > 0 {
			tags[o.IP] = append(tags[o.IP], observationTags(o)...)
		}
	}
	if detection != nil {
		// Ingest stores an artifact, even an empty one, after a successful
		// nuclei pass. Coverage is the same set of HTTP origins it was given.
		covered := make(map[netip.Addr]bool)
		for _, ip := range nuclei.BuildInput(ips, httpx.Observations).IPs {
			covered[ip] = true
			raw := bytes.TrimSpace(detection.PerIP(ip))
			if len(raw) == 0 {
				// This is a valid empty report for Dojo and closes old matches.
				raw = []byte("[]")
			}
			reports[ip] = append(reports[ip], scannerReport{"nuclei", "Nuclei Scan", "jsonl", raw})
		}
		for _, o := range detection.Observations {
			if covered[o.IP] {
				tags[o.IP] = append(tags[o.IP], observationTags(o)...)
			}
		}
	}
	return reports, tags
}

func observationTags(o scanner.Observation) []string {
	var tags []string
	add := func(prefix, value string) {
		value = strings.Join(strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_')
		}), "-")
		if value != "" && len(prefix)+len(value) <= 100 {
			tags = append(tags, prefix+value)
		}
	}
	if o.Hostname != "" {
		add("host:", strings.TrimSuffix(o.Hostname, "."))
	}
	if o.HTTP != nil {
		for _, technology := range o.HTTP.Technologies {
			name, _, _ := strings.Cut(technology, ":") // httpx emits Name:Version
			add("tech:", name)
		}
		if env := environmentTag(o.HTTP.Headers["X-Environment"]); env != "" {
			add("env:", env)
		} else if hasStagingMarker(o.Hostname) || hasStagingMarker(o.HTTP.Title) {
			add("env:", "staging")
		}
	}
	if o.Match != nil {
		if o.Kind == scanner.ObsTech {
			add("tech:", o.Tech)
		}
		if slices.Contains(o.Match.Tags, "panel") {
			panel := o.Product
			if panel == "" {
				panel = o.Match.TemplateID
			}
			add("panel:", panel)
		}
	}
	return tags
}

func environmentTag(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "staging", "stage", "stg":
		return "staging"
	case "prod", "production":
		return "production"
	case "dev", "development":
		return "development"
	case "qa", "test", "testing", "uat", "sandbox", "preprod":
		return value
	default:
		return ""
	}
}

func hasStagingMarker(value string) bool {
	return slices.Contains(strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return r < 'a' || r > 'z'
	}), "staging")
}
