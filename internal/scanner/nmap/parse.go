package nmap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

type xmlHost struct {
	StartTime int64 `xml:"starttime,attr"`
	EndTime   int64 `xml:"endtime,attr"`
	Status    struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []xmlPort `xml:"ports>port"`
}

type xmlPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   uint16 `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		ServiceFP string   `xml:"servicefp,attr"`
		CPEs      []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []xmlScript `xml:"script"`
}

type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
	Elems  []struct {
		Key   string `xml:"key,attr"`
		Value string `xml:",chardata"`
	} `xml:"elem"`
}

func (s xmlScript) elem(key string) string {
	for _, e := range s.Elems {
		if e.Key == key {
			return e.Value
		}
	}
	return ""
}

// hostSpan is where one <host> or <hosthint> element sits in the raw XML.
type hostSpan struct {
	start, end int64
	ip         netip.Addr
	isHost     bool // false for <hosthint>
}

// Parse turns nmap XML (-oX) into a Result: one ObsHost per host (up or
// down), one ObsService per open port, and one ObsHTTP per HTTP(S) port
// where the http-* or ssl-cert scripts said something. PerIP filters Raw.
func Parse(raw []byte) (*scanner.Result, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	var (
		obs      []scanner.Observation
		spans    []hostSpan
		runStart int64
		depth    int
		sawRoot  bool
	)
	for {
		off := d.InputOffset()
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("nmap parse xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if t.Name.Local != "nmaprun" {
					return nil, fmt.Errorf("nmap parse xml: root is <%s>, want <nmaprun>", t.Name.Local)
				}
				sawRoot = true
				runStart = attrInt(t, "start")
				depth++
				continue
			}
			if depth == 1 && (t.Name.Local == "host" || t.Name.Local == "hosthint") {
				var h xmlHost
				if err := d.DecodeElement(&h, &t); err != nil {
					return nil, fmt.Errorf("nmap parse <%s>: %w", t.Name.Local, err)
				}
				ip, ok := h.ip()
				if !ok {
					// no ipv4/ipv6 address: nothing to key it on; PerIP drops it
					spans = append(spans, hostSpan{start: off, end: d.InputOffset()})
					continue
				}
				spans = append(spans, hostSpan{start: off, end: d.InputOffset(), ip: ip, isHost: t.Name.Local == "host"})
				if t.Name.Local == "host" {
					obs = append(obs, h.observations(ip, runStart)...)
				}
				continue
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
	if !sawRoot {
		return nil, errors.New("nmap parse xml: no <nmaprun> element")
	}
	return &scanner.Result{
		Raw:          raw,
		Observations: obs,
		PerIP:        newPerIPIndex(raw, spans).perIP,
	}, nil
}

func attrInt(t xml.StartElement, name string) int64 {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			n, _ := strconv.ParseInt(a.Value, 10, 64)
			return n
		}
	}
	return 0
}

func (h xmlHost) ip() (netip.Addr, bool) {
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			ip, err := netip.ParseAddr(a.Addr)
			if err == nil {
				return ip.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
}

func (h xmlHost) observations(ip netip.Addr, runStart int64) []scanner.Observation {
	at := time.Unix(firstNonZero(h.EndTime, h.StartTime, runStart), 0).UTC()
	hostname := ""
	if len(h.Hostnames) > 0 {
		hostname = h.Hostnames[0].Name
	}
	out := []scanner.Observation{{
		Kind: scanner.ObsHost, IP: ip, Hostname: hostname, At: at,
		Up: h.Status.State == "up",
	}}
	for _, p := range h.Ports {
		if p.State.State != "open" {
			continue
		}
		svc := scanner.Observation{
			Kind: scanner.ObsService, IP: ip, Hostname: hostname, At: at,
			Port: p.PortID, Proto: p.Protocol,
			Service: serviceName(p.Service.Name, p.Service.Tunnel),
			Product: p.Service.Product,
			Version: p.Service.Version,
			CPE:     selectCPE(p.Service.CPEs),
			Banner:  p.Service.ServiceFP,
		}
		info := &scanner.HTTPInfo{}
		for _, s := range p.Scripts {
			switch s.ID {
			case "banner":
				svc.Banner = s.Output
			case "http-title":
				info.Title = s.elem("title")
				if r := s.elem("redirect_url"); r != "" {
					info.Redirects = append(info.Redirects, r)
				}
			case "http-headers":
				info.Headers, info.Cookies = parseHeaders(s.Output)
			case "ssl-cert":
				info.TLSCert = s.elem("pem")
				if info.TLSCert == "" {
					info.TLSCert = s.Output
				}
			}
		}
		out = append(out, svc)
		empty := info.Title == "" && info.Headers == nil && info.TLSCert == "" && info.Redirects == nil
		switch {
		case strings.HasPrefix(svc.Service, "http"):
			if empty {
				continue
			}
			scheme := "http"
			if p.Service.Tunnel == "ssl" || svc.Service == "https" {
				scheme = "https"
			}
			out = append(out, scanner.Observation{
				Kind: scanner.ObsHTTP, IP: ip, Hostname: hostname, At: at,
				Port: p.PortID, Proto: p.Protocol, Service: svc.Service,
				URL:  scheme + "://" + netip.AddrPortFrom(ip, p.PortID).String(),
				HTTP: info,
			})
		case !empty:
			// e.g. a TLS certificate on a non-HTTP service (smtps, imaps)
			out[len(out)-1].HTTP = info
		}
	}
	return out
}

// serviceName folds nmap's tunnel="ssl" into the name: "http" over TLS
// becomes "https" (what URL builders want), anything else "ssl/<name>"
// like nmap's own normal output.
func serviceName(name, tunnel string) string {
	if tunnel != "ssl" || name == "" {
		return name
	}
	if name == "http" {
		return "https"
	}
	return "ssl/" + name
}

// selectCPE picks a single normalized CPE to store on a service when nmap
// emits zero, one, or multiple <cpe> elements (e.g. an application CPE plus
// an OS CPE like cpe:/o:linux:linux_kernel).
//
// Policy: keep the most specific application CPE:
//  1. Prefer part "a" (application) over "o" (OS) over "h" (hardware).
//  2. Within the same part, prefer a CPE that includes a version over one without.
//  3. Break ties by first appearance in nmap's XML output.
func selectCPE(raws []string) string {
	var (
		best     string
		bestPart int
		bestVer  bool
	)
	for _, raw := range raws {
		norm, part, hasVer := parseCPE(raw)
		if norm == "" {
			continue
		}
		if part > bestPart || (part == bestPart && hasVer && !bestVer) {
			best, bestPart, bestVer = norm, part, hasVer
		}
	}
	return best
}

// normalizeCPE converts an nmap CPE URI (CPE 2.2 "cpe:/a:vendor:product[:version...]"
// or CPE 2.3 "cpe:2.3:a:vendor:product[:version...]") into "vendor:product" or
// "vendor:product:version". Invalid or incomplete CPEs return "".
func normalizeCPE(raw string) string {
	norm, _, _ := parseCPE(raw)
	return norm
}

func parseCPE(raw string) (norm string, partRank int, hasVersion bool) {
	s := strings.TrimSpace(strings.ToLower(raw))
	var rest string
	switch {
	case strings.HasPrefix(s, "cpe:/"):
		rest = strings.TrimPrefix(s, "cpe:/")
	case strings.HasPrefix(s, "cpe:2.3:"):
		rest = strings.TrimPrefix(s, "cpe:2.3:")
	default:
		return "", 0, false
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 3 {
		return "", 0, false
	}
	switch parts[0] {
	case "a":
		partRank = 3
	case "o":
		partRank = 2
	case "h":
		partRank = 1
	default:
		return "", 0, false
	}
	vendor, product := cleanCPEPart(parts[1]), cleanCPEPart(parts[2])
	if vendor == "" || product == "" {
		return "", 0, false
	}
	if len(parts) >= 4 {
		if ver := cleanCPEPart(parts[3]); ver != "" {
			return vendor + ":" + product + ":" + ver, partRank, true
		}
	}
	return vendor + ":" + product, partRank, false
}

func cleanCPEPart(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" || p == "-" {
		return ""
	}
	return p
}

// parseHeaders reads http-headers output ("  Name: value" lines, then a
// blank line and "(Request type: HEAD)").
func parseHeaders(out string) (map[string]string, []string) {
	var (
		headers map[string]string
		cookies []string
	)
	for line := range strings.SplitSeq(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ": ")
		if !ok || k == "" || strings.HasPrefix(k, "(") {
			continue
		}
		if strings.EqualFold(k, "Set-Cookie") {
			cookies = append(cookies, v)
		}
		if headers == nil {
			headers = map[string]string{}
		}
		if prev, dup := headers[k]; dup {
			v = prev + ", " + v
		}
		headers[k] = v
	}
	return headers, cookies
}

func firstNonZero(vs ...int64) int64 {
	for _, v := range vs {
		if v != 0 {
			return v
		}
	}
	return 0
}

type xmlGap struct {
	afterSpan int // -1 = before spans[0], i = after spans[i]
	data      []byte
}

// perIPIndex precomputes the O(1) IP → span lookup and the non-host XML
// envelope slices once per batch, avoiding O(N²) span scans and O(len(raw))
// buffer allocations for every responding IP in large batches.
type perIPIndex struct {
	raw         []byte
	spans       []hostSpan
	byIP        map[netip.Addr]int
	gaps        []xmlGap
	totalGapLen int
}

func newPerIPIndex(raw []byte, spans []hostSpan) *perIPIndex {
	byIP := make(map[netip.Addr]int)
	var gaps []xmlGap
	totalGapLen := 0
	last := int64(0)
	for i, s := range spans {
		if s.isHost && s.ip.IsValid() {
			if _, exists := byIP[s.ip]; !exists {
				byIP[s.ip] = i
			}
		}
		if s.start > last {
			g := raw[last:s.start]
			gaps = append(gaps, xmlGap{afterSpan: i - 1, data: g})
			totalGapLen += len(g)
		}
		last = s.end
		if last < int64(len(raw)) && raw[last] == '\n' {
			last++
		}
	}
	if last < int64(len(raw)) {
		g := raw[last:]
		gaps = append(gaps, xmlGap{afterSpan: len(spans) - 1, data: g})
		totalGapLen += len(g)
	}
	return &perIPIndex{raw: raw, spans: spans, byIP: byIP, gaps: gaps, totalGapLen: totalGapLen}
}

// perIP returns raw with every <host>/<hosthint> removed except the <host>
// of ip, or nil if ip has no <host> in this output. The rest of the
// document (header, scaninfo, runstats) is kept byte for byte, so Dojo's
// Nmap parser reads it like any -oX file. A down host has no <hostnames>,
// which Dojo's parser iterates unconditionally, so an empty one is added.
func (idx *perIPIndex) perIP(ip netip.Addr) []byte {
	spanIdx, ok := idx.byIP[ip.Unmap()]
	if !ok {
		return nil
	}
	s := idx.spans[spanIdx]
	el := idx.raw[s.start:s.end]
	trailingNL := s.end < int64(len(idx.raw)) && idx.raw[s.end] == '\n'

	extra := 0
	insertHostnames := !bytes.Contains(el, []byte("<hostnames"))
	hostEnd := -1
	if insertHostnames {
		hostEnd = bytes.LastIndex(el, []byte("</host>"))
		if hostEnd >= 0 {
			extra = len("<hostnames>\n</hostnames>\n")
		}
	}
	if trailingNL {
		extra++
	}

	var b bytes.Buffer
	b.Grow(idx.totalGapLen + len(el) + extra)
	for _, g := range idx.gaps {
		if g.afterSpan < spanIdx {
			b.Write(g.data)
		}
	}
	if hostEnd >= 0 {
		b.Write(el[:hostEnd])
		b.WriteString("<hostnames>\n</hostnames>\n")
		b.Write(el[hostEnd:])
	} else {
		b.Write(el)
	}
	if trailingNL {
		b.WriteByte('\n')
	}
	for _, g := range idx.gaps {
		if g.afterSpan >= spanIdx {
			b.Write(g.data)
		}
	}
	return b.Bytes()
}
