package cve

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// TestTitle is the per-IP Dojo test the CVE findings live in (§11).
const TestTitle = "RAVEN CVE match"

type genericFinding struct {
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	Severity          string   `json:"severity"`
	Date              string   `json:"date"`
	UniqueIDFromTool  string   `json:"unique_id_from_tool"`
	VulnerabilityIDs  []string `json:"vulnerability_ids"`
	ComponentName     string   `json:"component_name"`
	ComponentVersion  string   `json:"component_version"`
	CVSSv3Score       float64  `json:"cvssv3_score"`
	EPSSScore         float64  `json:"epss_score"`
	KnownExploited    bool     `json:"known_exploited"`
	ScannerConfidence int      `json:"scanner_confidence"`
	Tags              []string `json:"tags"`
	Active            bool     `json:"active"`
	Verified          bool     `json:"verified"`
	StaticFinding     bool     `json:"static_finding"`
	DynamicFinding    bool     `json:"dynamic_finding"`
}

// FindingTags are the per-finding tags; "raven" is what D3's sync pulls by.
func (m *Match) FindingTags() []string {
	tags := []string{"raven", "cve-match"}
	if m.Distro {
		tags = append(tags, TagDistroBuild)
	}
	return tags
}

func (m *Match) findingDescription(h Hit, instance string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**CVE:** %s  \n**Instance:** %s  \n**CVSS:** %.1f  \n**EPSS:** %g  \n**KEV:** %t  \n**CPE:** %s  \n**Confidence:** %s",
		h.ID, instance, h.CVSS, h.EPSS, h.KEV, m.CPE, m.Confidence)
	if m.Distro {
		b.WriteString(" (distribution build: fixes may be backported, severity capped at Low)")
	}
	return b.String()
}

// Report produces one Generic Findings Import finding per matched CVE on an IP.
// Findings omit "service" so Dojo's reimport can close absent findings in the
// same test. An empty report closes all previous CVE findings in that test.
func Report(ms []Match, date time.Time) ([]byte, error) {
	out := []genericFinding{}
	for i := range ms {
		m := &ms[i]
		conf := 1 // Dojo: 1 = certain …
		if m.Confidence == ConfidenceLow {
			conf = 6
		}
		instance := fmt.Sprintf("%s %s (%s/%s)", m.Name, m.Version,
			net.JoinHostPort(m.IP.String(), strconv.Itoa(int(m.Port))), m.Proto)
		for _, h := range m.Hits {
			out = append(out, genericFinding{
				Title: h.ID + " in " + instance, Description: m.findingDescription(h, instance),
				Severity: Severity(h.CVSS, h.KEV, m.Distro),
				Date:     date.UTC().Format(time.DateOnly), UniqueIDFromTool: m.FindingUID(h.ID), VulnerabilityIDs: []string{h.ID},
				ComponentName: m.Name, ComponentVersion: m.Version, CVSSv3Score: h.CVSS, EPSSScore: h.EPSS,
				KnownExploited: h.KEV, ScannerConfidence: conf,
				Tags: m.FindingTags(), Active: true, StaticFinding: true,
			})
		}
	}
	return json.Marshal(map[string]any{"findings": out})
}
