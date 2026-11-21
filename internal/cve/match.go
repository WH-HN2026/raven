package cve

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Instance is one detected product on one service (architecture §11: one
// finding per IP + port + product + version).
type Instance struct {
	IP      netip.Addr
	Port    int32
	Proto   string
	CPE     string // normalized "vendor:product[:version]" (S8), may be ""
	Product string // scanner product name, e.g. "Apache httpd"
	Version string // scanner version string, e.g. "7.4p1 Debian 10+deb9u7"
	Banner  string // raw banner, only used for distro detection
}

// Hit is one CVE that applies to a matched instance.
type Hit struct {
	ID   string  `json:"id"`
	CVSS float64 `json:"cvss"`
	KEV  bool    `json:"kev"`
	EPSS float64 `json:"epss"`
}

// Confidence levels (§11).
const (
	ConfidenceHigh = "high" // exact upstream version from a banner/header
	ConfidenceLow  = "low"  // distro build: fixes may be backported

	TagDistroBuild = "cve:distro-build"
)

// Match is one product instance with at least one CVE: the matcher's
// result, the cve_matches row, and the API shape.
type Match struct {
	IP         netip.Addr `json:"ip"`
	Port       int32      `json:"port"`
	Proto      string     `json:"proto"`
	Name       string     `json:"product"`    // products.txt display name, e.g. "Apache httpd"
	CPE        string     `json:"cpe"`        // matched vendor:product
	Version    string     `json:"version"`    // upstream version that was matched, e.g. "2.4.49"
	Hits       []Hit      `json:"cves"`       // by CVSS desc, then id
	MaxCVSS    float64    `json:"max_cvss"`   //
	KEV        int        `json:"kev"`        // hits in CISA KEV
	Distro     bool       `json:"distro"`     // distro build detected
	Confidence string     `json:"confidence"` // high | low
	Severity   string     `json:"severity"`   // Dojo severity
	MatchedAt  time.Time  `json:"matched_at"` // first matched with this cpe+version
}

// UID is the stable Dojo unique_id_from_tool: ip:port:cpe:version. A version
// change gives a new id, so reimport closes the old finding.
func (m *Match) UID() string {
	return m.IP.String() + ":" + strconv.Itoa(int(m.Port)) + ":" + m.CPE + ":" + m.Version
}

// Title is e.g. "Apache httpd 2.4.49: 12 known CVEs (2 KEV)".
func (m *Match) Title() string {
	noun := "CVEs"
	if len(m.Hits) == 1 {
		noun = "CVE"
	}
	return m.Name + " " + m.Version + ": " + strconv.Itoa(len(m.Hits)) + " known " + noun + " (" + strconv.Itoa(m.KEV) + " KEV)"
}

// Matcher matches instances against a dataset.
type Matcher struct {
	db    *DB
	byCPE map[string]Product // detected or NVD vendor:product → product
}

// NewMatcher indexes db by the products of products.txt.
func NewMatcher(db *DB, products []Product) *Matcher {
	m := &Matcher{db: db, byCPE: map[string]Product{}}
	for _, p := range products {
		for _, c := range append(append([]string{}, p.NVD...), p.Aliases...) {
			m.byCPE[strings.ToLower(c)] = p
		}
	}
	return m
}

// Default is a Matcher over the embedded dataset and products.txt.
func Default() (*Matcher, error) {
	db, err := Load()
	if err != nil {
		return nil, err
	}
	return NewMatcher(db, Products()), nil
}

// splitCPE: "vendor:product[:version]" → "vendor:product", version.
func splitCPE(c string) (vp, version string) {
	parts := strings.SplitN(strings.ToLower(strings.TrimSpace(c)), ":", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	vp = parts[0] + ":" + parts[1]
	if len(parts) == 3 {
		version = parts[2]
	}
	return vp, version
}

// Match returns the CVEs of one instance, or nil if the product isn't
// tracked, the version is unknown, or no CVE applies.
func (m *Matcher) Match(in Instance) *Match {
	vp, cpeVer := splitCPE(in.CPE)
	p, ok := m.byCPE[vp]
	if !ok {
		c, techVer, tok := CPEForTech(in.Product)
		if !tok {
			return nil
		}
		vp, p = c, m.byCPE[strings.ToLower(c)]
		if cpeVer == "" {
			cpeVer = techVer
		}
	}
	// Canonicalize alias CPEs (e.g. nmap's igor_sysoev:nginx → f5:nginx,
	// apache:httpd → apache:http_server) so nmap, httpx and nuclei produce the
	// same product key and unique_id_from_tool on the same port.
	if len(p.NVD) > 0 {
		vp = strings.ToLower(p.NVD[0])
	}
	ver := Upstream(ExtractVersion(in.Version))
	if ver == "" {
		ver = Upstream(ExtractVersion(cpeVer))
	}
	if ver == "" {
		return nil
	}
	seen := map[string]bool{}
	var hits []Hit
	for _, nvd := range p.NVD {
		for _, a := range m.db.Products[nvd] {
			if seen[a.ID] || !slices.ContainsFunc(a.Ranges, func(r Range) bool { return InRange(ver, r) }) {
				continue
			}
			seen[a.ID] = true
			r := m.db.CVEs[a.ID]
			hits = append(hits, Hit{ID: a.ID, CVSS: r.CVSS, KEV: r.KEV, EPSS: r.EPSS})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	slices.SortFunc(hits, func(a, b Hit) int {
		if c := cmp.Compare(b.CVSS, a.CVSS); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	proto := in.Proto
	if proto == "" {
		proto = "tcp"
	}
	out := &Match{IP: in.IP, Port: in.Port, Proto: proto, Name: p.Name, CPE: vp, Version: ver, Hits: hits,
		MaxCVSS: hits[0].CVSS, Distro: DistroBuild(in.Version, in.Banner)}
	for _, h := range hits {
		if h.KEV {
			out.KEV++
		}
	}
	out.Confidence = ConfidenceHigh
	if out.Distro {
		out.Confidence = ConfidenceLow
	}
	out.Severity = Severity(out.MaxCVSS, out.KEV > 0, out.Distro)
	return out
}

// MatchAll matches all instances and deduplicates by (ip, port, proto,
// canonical CPE). When multiple scanners (e.g. nmap and httpx) report the
// same product on the same port, one finding is returned; a distro-build
// detection wins over a non-distro match so the distro severity cap is kept.
func (m *Matcher) MatchAll(instances []Instance) []Match {
	type key struct {
		ip    netip.Addr
		port  int32
		proto string
		cpe   string
	}
	idx := make(map[key]int, len(instances))
	out := make([]Match, 0, len(instances))
	for _, in := range instances {
		mt := m.Match(in)
		if mt == nil {
			continue
		}
		k := key{mt.IP.Unmap(), mt.Port, mt.Proto, mt.CPE}
		if pos, exists := idx[k]; exists {
			if !out[pos].Distro && mt.Distro {
				out[pos] = *mt
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, *mt)
	}
	return out
}

// InstancesFromHTTPTech builds matcher instances from stored HTTP observation
// CPEs and raw httpx/nuclei technology strings (via CPEForTech).
func InstancesFromHTTPTech(ip netip.Addr, port int32, proto string, cpes, technologies []string) []Instance {
	out := make([]Instance, 0, len(cpes)+len(technologies))
	for _, c := range cpes {
		if strings.TrimSpace(c) == "" {
			continue
		}
		out = append(out, Instance{IP: ip, Port: port, Proto: proto, CPE: c})
	}
	for _, tech := range technologies {
		if c, v, ok := CPEForTech(tech); ok && v != "" {
			out = append(out, Instance{IP: ip, Port: port, Proto: proto, CPE: FormatCPE(c, v), Product: tech, Version: v})
		}
	}
	return out
}

// InstancesFromNucleiJSON extracts matcher instances from a run_observations
// nuclei_matches JSON array.
func InstancesFromNucleiJSON(ip netip.Addr, port int32, proto string, raw json.RawMessage) []Instance {
	if len(raw) == 0 {
		return nil
	}
	var items []struct {
		TemplateID string `json:"template_id"`
		Name       string `json:"name"`
		CPE        string `json:"cpe"`
		Version    string `json:"version"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	out := make([]Instance, 0, len(items))
	for _, it := range items {
		cpeStr, ver := strings.TrimSpace(it.CPE), strings.TrimSpace(it.Version)
		if cpeStr == "" {
			for _, cand := range []string{it.TemplateID, it.Name} {
				if c, v, ok := CPEForTech(cand); ok {
					cpeStr = c
					if ver == "" {
						ver = v
					}
					break
				}
			}
		}
		if cpeStr == "" && it.Name == "" {
			continue
		}
		out = append(out, Instance{
			IP: ip, Port: port, Proto: proto,
			CPE: FormatCPE(cpeStr, ver), Product: it.Name, Version: ver,
		})
	}
	return out
}

// Severities in Dojo's spelling, lowest first.
var severities = []string{"Info", "Low", "Medium", "High", "Critical"}

// Severity is the finding severity (§11): from the highest CVSS score,
// raised one level if any CVE is in KEV, capped at Low for distro builds.
func Severity(maxCVSS float64, kev, distro bool) string {
	lvl := 0
	switch {
	case maxCVSS >= 9:
		lvl = 4
	case maxCVSS >= 7:
		lvl = 3
	case maxCVSS >= 4:
		lvl = 2
	case maxCVSS > 0:
		lvl = 1
	}
	if kev && lvl < 4 {
		lvl++
	}
	if distro && lvl > 1 {
		lvl = 1
	}
	return severities[lvl]
}
