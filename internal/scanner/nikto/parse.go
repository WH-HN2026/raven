package nikto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

// flexString unmarshals a JSON string or number as a string (Nikto 2.6.x emits
// port as string or number depending on Perl scalar context) and always
// marshals as a JSON string for DefectDojo's NiktoJSONParser.
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*f = ""
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(trimmed, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

func (f flexString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(f))
}

// HostReport matches one target entry produced by Nikto's JSON reporter
// (nikto_report_json.plugin) and consumed by DefectDojo's NiktoJSONParser.
type HostReport struct {
	Host            string          `json:"host"`
	IP              string          `json:"ip"`
	Port            flexString      `json:"port"`
	Banner          string          `json:"banner,omitempty"`
	ServerBanner    string          `json:"server_banner,omitempty"`
	StartTime       string          `json:"start_time,omitempty"`
	EndTime         string          `json:"end_time,omitempty"`
	SSLInfo         json.RawMessage `json:"ssl_info,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability matches one entry inside HostReport.Vulnerabilities.
type Vulnerability struct {
	ID         flexString `json:"id"`
	OSVDB      flexString `json:"OSVDB,omitempty"`
	References string     `json:"references,omitempty"`
	Method     string     `json:"method"`
	URL        string     `json:"url"`
	Msg        string     `json:"msg"`
}

// Parse parses Nikto JSON output (either an array of HostReports as emitted by
// Nikto 2.6.1 or a single HostReport object) into normalized observations and
// a per-IP Dojo report extractor.
func Parse(raw []byte) (*scanner.Result, error) {
	res := &scanner.Result{Raw: raw}
	reports, err := decodeReports(raw)
	if err != nil {
		return nil, err
	}
	byIP := make(map[netip.Addr][]HostReport)
	for _, rep := range reports {
		ip, ok := reportIP(rep)
		if !ok {
			continue
		}
		if rep.Vulnerabilities == nil {
			rep.Vulnerabilities = []Vulnerability{}
		}
		byIP[ip] = append(byIP[ip], rep)

		port := reportPort(rep)
		scheme := reportScheme(rep, port)
		origin := scheme + "://" + net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		var hostname string
		if rep.Host != "" {
			if _, err := netip.ParseAddr(rep.Host); err != nil {
				hostname = strings.TrimSuffix(strings.ToLower(rep.Host), ".")
			}
		}
		at := parseNiktoTime(rep.EndTime, rep.StartTime)
		for _, v := range rep.Vulnerabilities {
			if strings.TrimSpace(v.Msg) == "" {
				continue
			}
			fullURL := origin
			if v.URL != "" {
				if strings.HasPrefix(v.URL, "/") {
					fullURL = origin + v.URL
				} else {
					fullURL = origin + "/" + v.URL
				}
			}
			sev := "info"
			if v.OSVDB != "" && v.OSVDB != "0" {
				sev = "medium"
			}
			res.Observations = append(res.Observations, scanner.Observation{
				Kind:     scanner.ObsMatch,
				IP:       ip,
				Hostname: hostname,
				At:       at,
				Port:     port,
				Proto:    "tcp",
				URL:      fullURL,
				Match: &scanner.MatchInfo{
					TemplateID: string(v.ID),
					Name:       v.Msg,
					Severity:   sev,
					Tags:       []string{"nikto"},
					Matcher:    v.Method,
					SourceURL:  origin,
				},
			})
		}
	}

	res.PerIP = func(ip netip.Addr) []byte {
		reps := byIP[ip.Unmap()]
		if len(reps) == 0 {
			return nil
		}
		// DefectDojo's NiktoJSONParser unwraps a 1-element JSON list or reads a
		// single JSON object, and fails on a list of 2+ objects. When one IP was
		// scanned on multiple ports/origins, merge them into one single-host
		// object so no findings are dropped.
		if len(reps) == 1 {
			out, err := json.Marshal([]HostReport{reps[0]})
			if err != nil {
				return nil
			}
			return out
		}
		merged := reps[0]
		merged.Vulnerabilities = make([]Vulnerability, 0)
		for _, r := range reps {
			for _, v := range r.Vulnerabilities {
				if r.Port != merged.Port && r.Port != "" {
					v.Msg = fmt.Sprintf("[port %s] %s", r.Port, v.Msg)
				}
				merged.Vulnerabilities = append(merged.Vulnerabilities, v)
			}
		}
		out, err := json.Marshal([]HostReport{merged})
		if err != nil {
			return nil
		}
		return out
	}
	return res, nil
}

// CombineRaw merges multiple per-URL Nikto JSON outputs into a single JSON
// array of HostReports for storage in artifacts.content_enc.
func CombineRaw(chunks [][]byte) ([]byte, error) {
	var all []HostReport
	for _, chunk := range chunks {
		reps, err := decodeReports(chunk)
		if err != nil {
			return nil, err
		}
		for i := range reps {
			if reps[i].Vulnerabilities == nil {
				reps[i].Vulnerabilities = []Vulnerability{}
			}
		}
		all = append(all, reps...)
	}
	if len(all) == 0 {
		return nil, nil
	}
	return json.Marshal(all)
}

func decodeReports(raw []byte) ([]HostReport, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	switch trimmed[0] {
	case '[':
		var reps []HostReport
		if err := json.Unmarshal(trimmed, &reps); err != nil {
			return nil, fmt.Errorf("nikto: invalid JSON report array: %w", err)
		}
		return reps, nil
	case '{':
		var rep HostReport
		if err := json.Unmarshal(trimmed, &rep); err != nil {
			return nil, fmt.Errorf("nikto: invalid JSON report object: %w", err)
		}
		return []HostReport{rep}, nil
	default:
		return nil, fmt.Errorf("nikto: unexpected JSON token %q", trimmed[0])
	}
}

func reportIP(r HostReport) (netip.Addr, bool) {
	for _, cand := range []string{r.IP, r.Host} {
		cand = strings.TrimSpace(cand)
		if cand == "" {
			continue
		}
		if ip, err := netip.ParseAddr(cand); err == nil && ip.Zone() == "" {
			return ip.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func reportPort(r HostReport) uint16 {
	p, err := strconv.ParseUint(strings.TrimSpace(string(r.Port)), 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

func reportScheme(r HostReport, port uint16) string {
	trimmed := bytes.TrimSpace(r.SSLInfo)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte("{}")) {
		return "https"
	}
	if port == 443 {
		return "https"
	}
	return "http"
}

func parseNiktoTime(candidates ...string) time.Time {
	layouts := []string{
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, c); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}
