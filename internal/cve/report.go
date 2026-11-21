package cve

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TestTitle is the per-IP Dojo test the CVE findings live in (§11).
const TestTitle = "ASI CVE match"

// descriptionCVEs caps the CVE table in a finding's description; the full
// list is always in vulnerability_ids.
const descriptionCVEs = 40

type genericFinding struct {
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	Severity          string   `json:"severity"`
	Date              string   `json:"date"`
	UniqueIDFromTool  string   `json:"unique_id_from_tool"`
	VulnerabilityIDs  []string `json:"vulnerability_ids"`
	ComponentName     string   `json:"component_name"`
	ComponentVersion  string   `json:"component_version"`
	CVSSv3Score       float64  `json:"cvssv3_score,omitempty"`
	EPSSScore         float64  `json:"epss_score,omitempty"`
	KnownExploited    bool     `json:"known_exploited"`
	ScannerConfidence int      `json:"scanner_confidence"`
	Tags              []string `json:"tags"`
	Active            bool     `json:"active"`
	Verified          bool     `json:"verified"`
	StaticFinding     bool     `json:"static_finding"`
	DynamicFinding    bool     `json:"dynamic_finding"`
}

// FindingTags are the per-finding tags; "asi" is what D3's sync pulls by.
func (m *Match) FindingTags() []string {
	tags := []string{"asi", "cve-match"}
	if m.Distro {
		tags = append(tags, TagDistroBuild)
	}
	return tags
}

// Description lists the CVEs with CVSS, EPSS and KEV.
func (m *Match) Description() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s on %s:%d/%s matches %d known CVEs from the offline NVD dataset (%d in CISA KEV).\n\n",
		m.Name, m.Version, m.IP, m.Port, m.Proto, len(m.Hits), m.KEV)
	fmt.Fprintf(&b, "**CPE:** %s  \n**Confidence:** %s", m.CPE, m.Confidence)
	if m.Distro {
		b.WriteString(" (distribution build: fixes may be backported, severity capped at Low)")
	}
	b.WriteString("\n\n| CVE | CVSS | EPSS | KEV |\n|---|---|---|---|\n")
	for i, h := range m.Hits {
		if i == descriptionCVEs {
			fmt.Fprintf(&b, "\n… and %d more (all listed in the vulnerability IDs).\n", len(m.Hits)-i)
			break
		}
		kev := ""
		if h.KEV {
			kev = "yes"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", h.ID, strconv.FormatFloat(h.CVSS, 'f', 1, 64),
			strconv.FormatFloat(h.EPSS, 'f', 3, 64), kev)
	}
	return b.String()
}

// Report is the Generic Findings Import JSON for one IP: one finding per
// product instance. Findings carry no "service": Dojo's close_old_findings
// only closes findings with the reimport's service value (none). An empty list is valid and, reimported with
// close_old_findings, closes the IP's previous CVE findings.
func Report(ms []Match, date time.Time) ([]byte, error) {
	out := make([]genericFinding, 0, len(ms))
	for i := range ms {
		m := &ms[i]
		ids := make([]string, len(m.Hits))
		var epss float64
		for j, h := range m.Hits {
			ids[j] = h.ID
			epss = max(epss, h.EPSS)
		}
		conf := 1 // Dojo: 1 = certain …
		if m.Confidence == ConfidenceLow {
			conf = 6
		}
		out = append(out, genericFinding{
			Title: m.Title(), Description: m.Description(), Severity: m.Severity,
			Date: date.UTC().Format(time.DateOnly), UniqueIDFromTool: m.UID(), VulnerabilityIDs: ids,
			ComponentName: m.Name, ComponentVersion: m.Version, CVSSv3Score: m.MaxCVSS, EPSSScore: epss,
			KnownExploited: m.KEV > 0, ScannerConfidence: conf,
			Tags: m.FindingTags(), Active: true, StaticFinding: true,
		})
	}
	return json.Marshal(map[string]any{"findings": out})
}
