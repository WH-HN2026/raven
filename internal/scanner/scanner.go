// Package scanner defines the Scanner interface (architecture §7, D6).
// Implementations live in subpackages (nmap, nuclei) and build their command
// lines only from their own flag allowlists (architecture §9).
package scanner

import (
	"context"
	"net/netip"
	"time"
)

type Scanner interface {
	Name() string                                                    // "nmap", "nuclei"
	DojoScanType() string                                            // "Nmap Scan", "Nuclei Scan"
	Run(ctx context.Context, in Input, opt Options) (*Result, error) // ctx cancel = kill process
}

// Input is what one scanner process works on (one batch).
type Input struct {
	IPs       []netip.Addr
	URLs      []string                // web scanners: scheme://host:port built from services + hostnames
	Hostnames map[netip.Addr][]string // known hostnames per IP (from domain targets / rDNS)
}

// Options come from the scan profile; implementations translate them into
// allowlisted flags only.
type Options struct {
	Ports      string   // nmap port spec from the profile's allowed list
	MaxRate    int      // nmap --max-rate (always set)
	RateLimit  int      // nuclei -rl (always set)
	Tags       []string // nuclei template tags (allowlisted)
	Signatures []string // paths of validated custom nuclei templates
}

type Result struct {
	Raw          []byte                     // tool output, stored encrypted, pushed to Dojo
	Observations []Observation              // normalized: host up/down, service, http, tech, match
	PerIP        func(ip netip.Addr) []byte // raw output filtered to one IP, for per-Asset reimport
}

type ObservationKind string

const (
	ObsHost    ObservationKind = "host"    // host up/down
	ObsService ObservationKind = "service" // open port + fingerprint
	ObsHTTP    ObservationKind = "http"    // HTTP response facts
	ObsTech    ObservationKind = "tech"    // detected technology
	ObsMatch   ObservationKind = "match"   // template / signature match
)

// Observation is one normalized fact. Fields not relevant to Kind stay zero.
type Observation struct {
	Kind     ObservationKind
	IP       netip.Addr
	Hostname string
	At       time.Time
	Up       bool   // ObsHost
	Port     uint16 // ObsService, ObsHTTP, ObsTech, ObsMatch
	Proto    string // "tcp" | "udp"
	Service  string // nmap service name, e.g. "http"
	Product  string
	Version  string
	CPE      string // normalized "vendor:product" or "vendor:product:version" (architecture §11)
	Banner   string
	URL      string // ObsHTTP, ObsTech, ObsMatch
	HTTP     *HTTPInfo
	Tech     string     // ObsTech: e.g. "wordpress"
	Match    *MatchInfo // ObsTech or ObsMatch from nuclei
}

type MatchInfo struct {
	TemplateID string
	Name       string
	Severity   string
	Tags       []string
	Matcher    string
	Extracted  []string
	SourceURL  string // httpx-confirmed origin, with an explicit port
}

type HTTPInfo struct {
	Status       int
	Title        string
	Headers      map[string]string
	Cookies      []string
	TLSCert      string // PEM or summary
	Redirects    []string
	FaviconHash  string
	Technologies []string
	ResponseMS   *int // httpx response time in ms; nil = unknown
}
