package exchange

import (
	"bytes"
	"cmp"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

// ResultsFormatName and ResultsFormatVersion identify our native scan-results JSON schema.
const (
	ResultsFormatName    = "raven-results"
	ResultsFormatVersion = 1
)

// ResultsDocument is RAVEN's extensible JSON/CSV scan-results interchange format.
// See docs/development/exchange.md for the schema and examples.
type ResultsDocument struct {
	Format    string       `json:"format,omitempty"`
	Version   int          `json:"version,omitempty"`
	ScannedAt *time.Time   `json:"scanned_at,omitempty"`
	Hosts     []ResultHost `json:"hosts"`
}

// ResultHost describes one observed host and its open services.
type ResultHost struct {
	IP        string          `json:"ip"`
	Up        *bool           `json:"up,omitempty"` // nil defaults to true
	Hostnames []string        `json:"hostnames,omitempty"`
	Services  []ResultService `json:"services,omitempty"`
}

// IsUp reports whether the host responded (defaults to true when Up is nil).
func (h ResultHost) IsUp() bool {
	return h.Up == nil || *h.Up
}

// ResultService describes one open port on a host, plus optional HTTP
// observations and template/signature matches attached to it.
type ResultService struct {
	Port    uint16        `json:"port"`
	Proto   string        `json:"proto,omitempty"` // default "tcp"
	Name    string        `json:"name,omitempty"`
	Service string        `json:"service,omitempty"` // alias for Name accepted on import
	Product string        `json:"product,omitempty"`
	Version string        `json:"version,omitempty"`
	CPE     string        `json:"cpe,omitempty"`
	Banner  string        `json:"banner,omitempty"`
	HTTP    []ResultHTTP  `json:"http,omitempty"`
	Matches []ResultMatch `json:"matches,omitempty"`
}

// ResultHTTP describes one HTTP observation on a service.
type ResultHTTP struct {
	URL          string            `json:"url"`
	Status       int               `json:"status,omitempty"`
	Title        string            `json:"title,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Cookies      []string          `json:"cookies,omitempty"`
	TLSCert      string            `json:"tls_cert,omitempty"`
	Redirects    []string          `json:"redirects,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	FaviconHash  string            `json:"favicon_hash,omitempty"`
	ObservedAt   *time.Time        `json:"observed_at,omitempty"`
}

// ResultMatch describes one nuclei template or signature match on a service.
type ResultMatch struct {
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Matcher    string   `json:"matcher,omitempty"`
	URL        string   `json:"url,omitempty"`
	SourceURL  string   `json:"source_url,omitempty"`
	Tech       string   `json:"tech,omitempty"`
	CPE        string   `json:"cpe,omitempty"`
	Version    string   `json:"version,omitempty"`
	Extracted  []string `json:"extracted,omitempty"`
}

// EncodeResultsJSON serializes doc as indented JSON with format/version metadata.
func EncodeResultsJSON(doc *ResultsDocument) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("%w: nil results document", ErrInvalid)
	}
	out := *doc
	if out.Format == "" {
		out.Format = ResultsFormatName
	}
	if out.Version == 0 {
		out.Version = ResultsFormatVersion
	}
	if out.Hosts == nil {
		out.Hosts = []ResultHost{}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode results json: %w", err)
	}
	return append(b, '\n'), nil
}

// ParseResultsJSON parses RAVEN's results JSON document:
//   - standard envelope: {"format":"raven-results","version":1,"hosts":[...]}
//   - flat array of hosts or exported service rows: [{"ip":...}, ...]
func ParseResultsJSON(raw []byte) (*ResultsDocument, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\ufeff")))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty JSON input", ErrInvalid)
	}
	var doc ResultsDocument
	if trimmed[0] == '[' {
		// Accept a bare JSON array of hosts or flat exported services.
		if err := parseFlatJSONArray(trimmed, &doc); err != nil {
			return nil, err
		}
	} else {
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return nil, fmt.Errorf("%w: invalid results JSON: %v", ErrInvalid, err)
		}
		if doc.Version > ResultsFormatVersion {
			return nil, fmt.Errorf("%w: unsupported results version %d (max %d)", ErrInvalid, doc.Version, ResultsFormatVersion)
		}
	}
	if err := normalizeResultsDoc(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// flatJSONRow handles re-importing exported hosts or services JSON arrays.
type flatJSONRow struct {
	IP        string          `json:"ip"`
	Up        *bool           `json:"up"`
	State     string          `json:"state"`
	Hostnames []string        `json:"hostnames"`
	Services  []ResultService `json:"services"`
	// Service-export flat fields
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
	Name    string `json:"name"`
	Service string `json:"service"`
	Product string `json:"product"`
	Version string `json:"version"`
	CPE     string `json:"cpe"`
	Banner  string `json:"banner"`
}

func parseFlatJSONArray(raw []byte, doc *ResultsDocument) error {
	var rows []flatJSONRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return fmt.Errorf("%w: invalid results JSON array: %v", ErrInvalid, err)
	}
	byIP := make(map[string]int)
	for i, r := range rows {
		ip, err := parseIPv4OrAny(r.IP)
		if err != nil {
			return fmt.Errorf("%w: element %d: %v", ErrInvalid, i+1, err)
		}
		key := ip.String()
		idx, ok := byIP[key]
		if !ok {
			up := true
			if r.Up != nil {
				up = *r.Up
			} else if strings.EqualFold(r.State, "inactive") || strings.EqualFold(r.State, "down") {
				up = false
			}
			idx = len(doc.Hosts)
			byIP[key] = idx
			doc.Hosts = append(doc.Hosts, ResultHost{IP: key, Up: &up})
		}
		h := &doc.Hosts[idx]
		h.Hostnames = mergeUniqueStrings(h.Hostnames, r.Hostnames)
		if len(r.Services) > 0 {
			h.Services = append(h.Services, r.Services...)
		}
		if r.Port > 0 && !strings.EqualFold(r.State, "gone") {
			h.Services = append(h.Services, ResultService{
				Port: r.Port, Proto: r.Proto, Name: cmp.Or(r.Name, r.Service),
				Product: r.Product, Version: r.Version, CPE: r.CPE, Banner: r.Banner,
			})
		}
	}
	return nil
}

func normalizeResultsDoc(doc *ResultsDocument) error {
	if doc.Format == "" {
		doc.Format = ResultsFormatName
	}
	if doc.Version == 0 {
		doc.Version = ResultsFormatVersion
	}
	if len(doc.Hosts) == 0 {
		return fmt.Errorf("%w: results contain no hosts", ErrInvalid)
	}
	for i := range doc.Hosts {
		h := &doc.Hosts[i]
		ip, err := parseIPv4OrAny(h.IP)
		if err != nil {
			return fmt.Errorf("%w: host %d: %v", ErrInvalid, i+1, err)
		}
		h.IP = ip.String()
		h.Hostnames = cleanStrings(h.Hostnames)
		for j := range h.Services {
			sv := &h.Services[j]
			if sv.Port == 0 {
				return fmt.Errorf("%w: host %s service %d: port must be 1..65535", ErrInvalid, h.IP, j+1)
			}
			sv.Proto = strings.ToLower(strings.TrimSpace(sv.Proto))
			if sv.Proto == "" {
				sv.Proto = "tcp"
			}
			if sv.Proto != "tcp" && sv.Proto != "udp" {
				return fmt.Errorf("%w: host %s port %d: proto must be tcp or udp, got %q", ErrInvalid, h.IP, sv.Port, sv.Proto)
			}
			if sv.Name == "" && sv.Service != "" {
				sv.Name = sv.Service
			}
			sv.Service = ""
			for k := range sv.HTTP {
				ho := &sv.HTTP[k]
				if strings.TrimSpace(ho.URL) == "" {
					ho.URL = defaultServiceURL(ip, sv.Port, sv.Name)
				}
				ho.Technologies = cleanStrings(ho.Technologies)
			}
			for k := range sv.Matches {
				m := &sv.Matches[k]
				if strings.TrimSpace(m.TemplateID) == "" || strings.TrimSpace(m.Name) == "" {
					return fmt.Errorf("%w: host %s port %d match %d: template_id and name are required", ErrInvalid, h.IP, sv.Port, k+1)
				}
				if strings.TrimSpace(m.URL) == "" {
					m.URL = defaultServiceURL(ip, sv.Port, sv.Name)
				}
				if strings.TrimSpace(m.SourceURL) == "" {
					m.SourceURL = defaultServiceURL(ip, sv.Port, sv.Name)
				}
				if strings.TrimSpace(m.Severity) == "" {
					m.Severity = "info"
				}
				m.Tags = cleanStrings(m.Tags)
			}
		}
	}
	return nil
}

// resultsCSVHeader is the canonical header for our results-csv format.
var resultsCSVHeader = []string{
	"ip", "up", "hostnames",
	"port", "proto", "name", "product", "version", "cpe", "banner",
	"url", "http_status", "http_title", "technologies", "favicon_hash", "redirects",
	"match_template_id", "match_name", "match_severity", "match_tags", "match_matcher", "match_url", "match_tech", "match_extracted",
}

// EncodeResultsCSV writes doc in RAVEN's flat results-csv format.
// Each host/service/http/match combination is written as self-contained rows
// so ParseResultsCSV reconstructs the document without duplicates.
func EncodeResultsCSV(w io.Writer, doc *ResultsDocument) error {
	if doc == nil {
		return fmt.Errorf("%w: nil results document", ErrInvalid)
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(resultsCSVHeader); err != nil {
		return err
	}
	for _, h := range doc.Hosts {
		upStr := strconv.FormatBool(h.IsUp())
		hnames := strings.Join(h.Hostnames, ";")
		if len(h.Services) == 0 {
			row := make([]string, len(resultsCSVHeader))
			row[0], row[1], row[2] = h.IP, upStr, hnames
			if err := cw.Write(row); err != nil {
				return err
			}
			continue
		}
		for _, sv := range h.Services {
			proto := cmp.Or(sv.Proto, "tcp")
			name := cmp.Or(sv.Name, sv.Service)
			n := max(1, max(len(sv.HTTP), len(sv.Matches)))
			for i := range n {
				row := make([]string, len(resultsCSVHeader))
				row[0], row[1], row[2] = h.IP, upStr, hnames
				row[3] = strconv.Itoa(int(sv.Port))
				row[4], row[5], row[6], row[7], row[8], row[9] = proto, name, sv.Product, sv.Version, sv.CPE, sv.Banner
				if i < len(sv.HTTP) {
					ho := sv.HTTP[i]
					row[10] = ho.URL
					if ho.Status != 0 {
						row[11] = strconv.Itoa(ho.Status)
					}
					row[12] = ho.Title
					row[13] = strings.Join(ho.Technologies, ";")
					row[14] = ho.FaviconHash
					row[15] = strings.Join(ho.Redirects, ";")
				}
				if i < len(sv.Matches) {
					m := sv.Matches[i]
					row[16] = m.TemplateID
					row[17] = m.Name
					row[18] = m.Severity
					row[19] = strings.Join(m.Tags, ";")
					row[20] = m.Matcher
					row[21] = m.URL
					row[22] = m.Tech
					row[23] = strings.Join(m.Extracted, ";")
				}
				if err := cw.Write(row); err != nil {
					return err
				}
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// ParseResultsCSV parses RAVEN's header-driven results-csv format (and also
// accepts exported services/hosts CSV files because columns are matched by
// header name).
func ParseResultsCSV(r io.Reader) (*ResultsDocument, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.Comment = '#'

	hdr, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: empty CSV input", ErrInvalid)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read CSV header: %v", ErrInvalid, err)
	}
	col := make(map[string]int, len(hdr))
	for i, h := range hdr {
		name := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
		if name != "" {
			col[name] = i
		}
	}
	if _, ok := col["ip"]; !ok {
		return nil, fmt.Errorf("%w: CSV header must contain an \"ip\" column", ErrInvalid)
	}

	cell := func(rec []string, names ...string) string {
		for _, n := range names {
			if idx, ok := col[n]; ok && idx < len(rec) {
				if v := strings.TrimSpace(rec[idx]); v != "" {
					return v
				}
			}
		}
		return ""
	}

	type svcKey struct {
		ip    string
		port  uint16
		proto string
	}
	doc := &ResultsDocument{Format: ResultsFormatName, Version: ResultsFormatVersion}
	hostIdx := make(map[string]int)
	svcIdx := make(map[svcKey]int)
	httpSeen := make(map[string]bool)
	matchSeen := make(map[string]bool)

	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line, _ := cr.FieldPos(0)
		if err != nil {
			return nil, fmt.Errorf("%w: CSV line %d: %v", ErrInvalid, line, err)
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue
		}
		rawIP := cell(rec, "ip")
		if rawIP == "" {
			return nil, fmt.Errorf("%w: CSV line %d: empty ip", ErrInvalid, line)
		}
		ip, err := parseIPv4OrAny(rawIP)
		if err != nil {
			return nil, fmt.Errorf("%w: CSV line %d: %v", ErrInvalid, line, err)
		}
		ipStr := ip.String()

		up := true
		if u := cell(rec, "up"); u != "" {
			b, err := parseBoolFlexible(u)
			if err != nil {
				return nil, fmt.Errorf("%w: CSV line %d: invalid up %q", ErrInvalid, line, u)
			}
			up = b
		} else if st := strings.ToLower(cell(rec, "state")); st == "inactive" || st == "down" {
			up = false
		}

		hi, exists := hostIdx[ipStr]
		if !exists {
			hi = len(doc.Hosts)
			hostIdx[ipStr] = hi
			u := up
			doc.Hosts = append(doc.Hosts, ResultHost{IP: ipStr, Up: &u})
		} else if up {
			t := true
			doc.Hosts[hi].Up = &t
		}
		h := &doc.Hosts[hi]
		if hn := splitList(cell(rec, "hostnames", "hostname")); len(hn) > 0 {
			h.Hostnames = mergeUniqueStrings(h.Hostnames, hn)
		}

		portStr := cell(rec, "port")
		if portStr == "" || strings.EqualFold(cell(rec, "state"), "gone") {
			continue
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("%w: CSV line %d: invalid port %q", ErrInvalid, line, portStr)
		}
		proto := strings.ToLower(cmp.Or(cell(rec, "proto", "protocol"), "tcp"))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("%w: CSV line %d: invalid proto %q", ErrInvalid, line, proto)
		}
		sk := svcKey{ipStr, uint16(p), proto}
		si, ok := svcIdx[sk]
		if !ok {
			si = len(h.Services)
			svcIdx[sk] = si
			h.Services = append(h.Services, ResultService{
				Port:    uint16(p),
				Proto:   proto,
				Name:    cell(rec, "name", "service"),
				Product: cell(rec, "product"),
				Version: cell(rec, "version"),
				CPE:     cell(rec, "cpe"),
				Banner:  cell(rec, "banner"),
			})
		} else {
			sv := &h.Services[si]
			sv.Name = cmp.Or(sv.Name, cell(rec, "name", "service"))
			sv.Product = cmp.Or(sv.Product, cell(rec, "product"))
			sv.Version = cmp.Or(sv.Version, cell(rec, "version"))
			sv.CPE = cmp.Or(sv.CPE, cell(rec, "cpe"))
			sv.Banner = cmp.Or(sv.Banner, cell(rec, "banner"))
		}
		sv := &h.Services[si]

		httpURL := cell(rec, "url", "http_url")
		httpStatusStr := cell(rec, "http_status", "status")
		httpTitle := cell(rec, "http_title", "title")
		httpTech := splitList(cell(rec, "technologies", "tech"))
		httpFav := cell(rec, "favicon_hash")
		httpRedir := splitList(cell(rec, "redirects"))
		if httpURL != "" || httpStatusStr != "" || httpTitle != "" || len(httpTech) > 0 || httpFav != "" || len(httpRedir) > 0 {
			if httpURL == "" {
				httpURL = defaultServiceURL(ip, uint16(p), sv.Name)
			}
			var status int
			if httpStatusStr != "" {
				status, err = strconv.Atoi(httpStatusStr)
				if err != nil {
					return nil, fmt.Errorf("%w: CSV line %d: invalid http_status %q", ErrInvalid, line, httpStatusStr)
				}
			}
			hk := ipStr + "|" + strconv.Itoa(int(p)) + "|" + httpURL
			if !httpSeen[hk] {
				httpSeen[hk] = true
				sv.HTTP = append(sv.HTTP, ResultHTTP{
					URL: httpURL, Status: status, Title: httpTitle,
					Technologies: httpTech, FaviconHash: httpFav, Redirects: httpRedir,
				})
			}
		}

		tid := cell(rec, "match_template_id", "template_id")
		mname := cell(rec, "match_name")
		if tid != "" {
			if mname == "" {
				mname = tid
			}
			murl := cmp.Or(cell(rec, "match_url"), httpURL, defaultServiceURL(ip, uint16(p), sv.Name))
			mk := ipStr + "|" + strconv.Itoa(int(p)) + "|" + tid + "|" + murl
			if !matchSeen[mk] {
				matchSeen[mk] = true
				sv.Matches = append(sv.Matches, ResultMatch{
					TemplateID: tid,
					Name:       mname,
					Severity:   cmp.Or(cell(rec, "match_severity", "severity"), "info"),
					Tags:       splitList(cell(rec, "match_tags")),
					Matcher:    cell(rec, "match_matcher"),
					URL:        murl,
					SourceURL:  cmp.Or(httpURL, defaultServiceURL(ip, uint16(p), sv.Name)),
					Tech:       cell(rec, "match_tech"),
					Extracted:  splitList(cell(rec, "match_extracted")),
				})
			}
		}
	}

	if err := normalizeResultsDoc(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// BuildImportData turns a normalized ResultsDocument into pipeline-ready
// scanner.Results (with a synthesized nmap XML for Dojo push and C1 diffing),
// HTTP observations, nuclei matches, candidate IPs, and hostnames.
func (doc *ResultsDocument) BuildImportData() (primary, httpRes, nucleiRes *scanner.Result, ips []netip.Addr, hostnames map[netip.Addr][]string, err error) {
	seenAt := time.Now().UTC()
	if doc.ScannedAt != nil && !doc.ScannedAt.IsZero() {
		seenAt = doc.ScannedAt.UTC()
	}

	xmlBytes, err := SynthesizeNmapXML(doc, seenAt)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	nmapRes, err := nmap.Parse(xmlBytes)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parse synthesized nmap xml: %w", err)
	}

	var (
		baseObs   []scanner.Observation
		httpObs   []scanner.Observation
		nucleiObs []scanner.Observation
	)
	hostnames = make(map[netip.Addr][]string, len(doc.Hosts))
	ips = make([]netip.Addr, 0, len(doc.Hosts))

	for _, h := range doc.Hosts {
		ip, err := netip.ParseAddr(h.IP)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("%w: invalid IP %q", ErrInvalid, h.IP)
		}
		ip = ip.Unmap()
		ips = append(ips, ip)
		if len(h.Hostnames) > 0 {
			hostnames[ip] = mergeUniqueStrings(hostnames[ip], h.Hostnames)
		}
		primaryName := ""
		if len(h.Hostnames) > 0 {
			primaryName = h.Hostnames[0]
		}
		baseObs = append(baseObs, scanner.Observation{
			Kind: scanner.ObsHost, IP: ip, Hostname: primaryName, At: seenAt, Up: h.IsUp(),
		})
		if !h.IsUp() {
			continue
		}
		for _, sv := range h.Services {
			proto := cmp.Or(sv.Proto, "tcp")
			name := cmp.Or(sv.Name, sv.Service)
			baseObs = append(baseObs, scanner.Observation{
				Kind: scanner.ObsService, IP: ip, Hostname: primaryName, At: seenAt,
				Port: sv.Port, Proto: proto, Service: name,
				Product: sv.Product, Version: sv.Version, CPE: sv.CPE, Banner: sv.Banner,
			})
			for _, ho := range sv.HTTP {
				at := seenAt
				if ho.ObservedAt != nil && !ho.ObservedAt.IsZero() {
					at = ho.ObservedAt.UTC()
				}
				hdrs := ho.Headers
				if hdrs == nil {
					hdrs = map[string]string{}
				}
				httpObs = append(httpObs, scanner.Observation{
					Kind: scanner.ObsHTTP, IP: ip, Hostname: primaryName, At: at,
					Port: sv.Port, Proto: proto, Service: name, URL: ho.URL,
					HTTP: &scanner.HTTPInfo{
						Status:       ho.Status,
						Title:        ho.Title,
						Headers:      hdrs,
						Cookies:      ho.Cookies,
						TLSCert:      ho.TLSCert,
						Redirects:    ho.Redirects,
						FaviconHash:  ho.FaviconHash,
						Technologies: ho.Technologies,
					},
				})
			}
			for _, m := range sv.Matches {
				kind := scanner.ObsMatch
				tech := m.Tech
				if tech != "" || slices.Contains(m.Tags, "tech") {
					kind = scanner.ObsTech
					if tech == "" {
						tech = cmp.Or(m.Matcher, m.Name)
					}
				}
				nucleiObs = append(nucleiObs, scanner.Observation{
					Kind: kind, IP: ip, Hostname: primaryName, At: seenAt,
					Port: sv.Port, Proto: proto, URL: m.URL,
					Product: sv.Product, Version: cmp.Or(m.Version, sv.Version), CPE: cmp.Or(m.CPE, sv.CPE),
					Tech: tech,
					Match: &scanner.MatchInfo{
						TemplateID: m.TemplateID,
						Name:       m.Name,
						Severity:   m.Severity,
						Tags:       m.Tags,
						Matcher:    m.Matcher,
						Extracted:  m.Extracted,
						SourceURL:  m.SourceURL,
					},
				})
			}
		}
	}

	primary = &scanner.Result{
		Raw:          xmlBytes,
		Observations: baseObs,
		PerIP:        nmapRes.PerIP,
	}
	if len(httpObs) > 0 {
		httpRes = &scanner.Result{Observations: httpObs}
	}
	if len(nucleiObs) > 0 {
		nucleiRes = &scanner.Result{Observations: nucleiObs}
	}
	return primary, httpRes, nucleiRes, ips, hostnames, nil
}

// SynthesizeNmapXML builds a minimal valid nmap -oX XML document from doc so
// imported JSON/CSV results work identically with DefectDojo's "Nmap Scan"
// parser and C1's fingerprint diffing.
func SynthesizeNmapXML(doc *ResultsDocument, at time.Time) ([]byte, error) {
	type xmlElem struct {
		Key   string `xml:"key,attr"`
		Value string `xml:",chardata"`
	}
	type xmlScript struct {
		ID     string    `xml:"id,attr"`
		Output string    `xml:"output,attr"`
		Elems  []xmlElem `xml:"elem,omitempty"`
	}
	type xmlService struct {
		Name    string   `xml:"name,attr,omitempty"`
		Product string   `xml:"product,attr,omitempty"`
		Version string   `xml:"version,attr,omitempty"`
		CPEs    []string `xml:"cpe,omitempty"`
	}
	type xmlPortState struct {
		State string `xml:"state,attr"`
	}
	type xmlPort struct {
		Protocol string       `xml:"protocol,attr"`
		PortID   uint16       `xml:"portid,attr"`
		State    xmlPortState `xml:"state"`
		Service  xmlService   `xml:"service"`
		Scripts  []xmlScript  `xml:"script,omitempty"`
	}
	type xmlHostname struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	}
	type xmlHostnames struct {
		Items []xmlHostname `xml:"hostname"`
	}
	type xmlAddress struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	}
	type xmlStatus struct {
		State string `xml:"state,attr"`
	}
	type xmlPorts struct {
		Ports []xmlPort `xml:"port"`
	}
	type xmlHost struct {
		StartTime int64        `xml:"starttime,attr"`
		EndTime   int64        `xml:"endtime,attr"`
		Status    xmlStatus    `xml:"status"`
		Address   xmlAddress   `xml:"address"`
		Hostnames xmlHostnames `xml:"hostnames"`
		Ports     *xmlPorts    `xml:"ports,omitempty"`
	}
	type xmlNmapRun struct {
		XMLName xml.Name  `xml:"nmaprun"`
		Scanner string    `xml:"scanner,attr"`
		Start   int64     `xml:"start,attr"`
		Hosts   []xmlHost `xml:"host"`
	}

	ts := at.UTC().Unix()
	run := xmlNmapRun{Scanner: "nmap", Start: ts, Hosts: make([]xmlHost, 0, len(doc.Hosts))}
	for _, h := range doc.Hosts {
		ip, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		addrType := "ipv4"
		if ip.Is6() {
			addrType = "ipv6"
		}
		state := "down"
		if h.IsUp() {
			state = "up"
		}
		xh := xmlHost{
			StartTime: ts, EndTime: ts,
			Status:  xmlStatus{State: state},
			Address: xmlAddress{Addr: ip.String(), AddrType: addrType},
		}
		for _, hn := range h.Hostnames {
			xh.Hostnames.Items = append(xh.Hostnames.Items, xmlHostname{Name: hn, Type: "user"})
		}
		if h.IsUp() && len(h.Services) > 0 {
			ps := &xmlPorts{Ports: make([]xmlPort, 0, len(h.Services))}
			for _, sv := range h.Services {
				xp := xmlPort{
					Protocol: cmp.Or(sv.Proto, "tcp"),
					PortID:   sv.Port,
					State:    xmlPortState{State: "open"},
					Service: xmlService{
						Name:    cmp.Or(sv.Name, sv.Service),
						Product: sv.Product,
						Version: sv.Version,
					},
				}
				if sv.CPE != "" {
					cpe := sv.CPE
					if !strings.HasPrefix(cpe, "cpe:") {
						cpe = "cpe:/a:" + cpe
					}
					xp.Service.CPEs = []string{cpe}
				}
				if sv.Banner != "" {
					xp.Scripts = append(xp.Scripts, xmlScript{ID: "banner", Output: sv.Banner})
				}
				for _, ho := range sv.HTTP {
					if ho.Title != "" {
						xp.Scripts = append(xp.Scripts, xmlScript{
							ID: "http-title", Output: ho.Title,
							Elems: []xmlElem{{Key: "title", Value: ho.Title}},
						})
						break
					}
				}
				ps.Ports = append(ps.Ports, xp)
			}
			xh.Ports = ps
		}
		run.Hosts = append(run.Hosts, xh)
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return nil, fmt.Errorf("encode synthesized nmap xml: %w", err)
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func parseIPv4OrAny(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", s)
	}
	return ip.Unmap(), nil
}

func defaultServiceURL(ip netip.Addr, port uint16, name string) string {
	scheme := "http"
	if port == 443 || port == 8443 || strings.HasPrefix(strings.ToLower(name), "https") || strings.HasPrefix(strings.ToLower(name), "ssl/") {
		scheme = "https"
	}
	return scheme + "://" + netip.AddrPortFrom(ip, port).String()
}

func parseBoolFlexible(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "up", "active":
		return true, nil
	case "false", "0", "no", "down", "inactive":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool %q", s)
	}
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '|' })
	return cleanStrings(parts)
}

func cleanStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

func mergeUniqueStrings(a, b []string) []string {
	return cleanStrings(append(slices.Clone(a), b...))
}
