package zap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/WH-HN2026/raven/internal/scanner"
)

const defaultReportVersion = "2.17.0"

// reportXML mirrors ZAP's /OTHER/core/other/xmlreport/ document while
// preserving each <site> inner XML verbatim for DefectDojo's "ZAP Scan" parser.
type reportXML struct {
	XMLName     xml.Name  `xml:"OWASPZAPReport"`
	ProgramName string    `xml:"programName,attr,omitempty"`
	Version     string    `xml:"version,attr,omitempty"`
	Generated   string    `xml:"generated,attr,omitempty"`
	Sites       []SiteXML `xml:"site"`
}

// SiteXML is one <site> block from a ZAP XML report.
type SiteXML struct {
	Name     string `xml:"name,attr"`
	Host     string `xml:"host,attr"`
	Port     string `xml:"port,attr"`
	SSL      string `xml:"ssl,attr"`
	InnerXML []byte `xml:",innerxml"`
}

type siteAlertsXML struct {
	Alerts []alertItemXML `xml:"alerts>alertitem"`
}

type alertItemXML struct {
	PluginID  string        `xml:"pluginid"`
	Alert     string        `xml:"alert"`
	Name      string        `xml:"name"`
	RiskCode  string        `xml:"riskcode"`
	CWEID     string        `xml:"cweid"`
	Instances []instanceXML `xml:"instances>instance"`
}

type instanceXML struct {
	URI      string `xml:"uri"`
	Method   string `xml:"method"`
	Evidence string `xml:"evidence"`
}

// Parse reads a ZAP XML report and indexes its <site> blocks for per-IP export
// to DefectDojo's "ZAP Scan" parser.
func Parse(raw []byte) (*scanner.Result, error) {
	res := &scanner.Result{
		Raw:   raw,
		PerIP: func(netip.Addr) []byte { return nil },
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return res, nil
	}
	var doc reportXML
	if err := xml.Unmarshal(trimmed, &doc); err != nil {
		return nil, fmt.Errorf("zap: invalid XML report: %w", err)
	}
	byIP := make(map[netip.Addr][]SiteXML)
	for _, site := range doc.Sites {
		ip, ok := parseSiteIP(site.Host)
		if !ok {
			continue
		}
		port := parseSitePort(site.Port, site.SSL)
		byIP[ip] = append(byIP[ip], site)

		alerts, err := parseSiteAlerts(site.InnerXML)
		if err != nil {
			return nil, fmt.Errorf("zap: parse alerts for %s: %w", site.Name, err)
		}
		for _, a := range alerts {
			title := strings.TrimSpace(a.Alert)
			if title == "" {
				title = strings.TrimSpace(a.Name)
			}
			if title == "" {
				continue
			}
			uri := site.Name
			if len(a.Instances) > 0 && strings.TrimSpace(a.Instances[0].URI) != "" {
				uri = strings.TrimSpace(a.Instances[0].URI)
			}
			res.Observations = append(res.Observations, scanner.Observation{
				Kind:  scanner.ObsMatch,
				IP:    ip,
				Port:  port,
				Proto: "tcp",
				URL:   uri,
				Match: &scanner.MatchInfo{
					TemplateID: strings.TrimSpace(a.PluginID),
					Name:       title,
					Severity:   mapRiskCode(a.RiskCode),
					SourceURL:  site.Name,
				},
			})
		}
	}
	program := doc.ProgramName
	if program == "" {
		program = "ZAP"
	}
	version := doc.Version
	if version == "" {
		version = defaultReportVersion
	}
	generated := doc.Generated
	res.PerIP = func(ip netip.Addr) []byte {
		sites := byIP[ip.Unmap()]
		if len(sites) == 0 {
			return nil
		}
		b, err := marshalReport(program, version, generated, sites)
		if err != nil {
			return nil
		}
		return b
	}
	return res, nil
}

// filterSitesToOrigin keeps only <site> entries from raw that match the exact
// scanned origin (scheme, literal IP, port). If ZAP emitted no <site> node
// (e.g. a reachable target with zero alerts), it returns one empty <site> node
// for that origin so PerIP still produces a valid empty report for Dojo.
func filterSitesToOrigin(raw []byte, expectedScheme string, expectedIP netip.Addr, expectedPort uint16, originName string) (version, generated string, sites []SiteXML, alertCount int, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return defaultReportVersion, "", []SiteXML{emptySite(expectedScheme, expectedIP, expectedPort, originName)}, 0, nil
	}
	var doc reportXML
	if err := xml.Unmarshal(trimmed, &doc); err != nil {
		return "", "", nil, 0, fmt.Errorf("zap: invalid XML report: %w", err)
	}
	version = doc.Version
	if version == "" {
		version = defaultReportVersion
	}
	generated = doc.Generated
	wantSSL := expectedScheme == "https"
	for _, s := range doc.Sites {
		ip, ok := parseSiteIP(s.Host)
		if !ok || ip != expectedIP.Unmap() {
			continue
		}
		port := parseSitePort(s.Port, s.SSL)
		ssl := strings.EqualFold(strings.TrimSpace(s.SSL), "true")
		if port != expectedPort || ssl != wantSSL {
			continue
		}
		alerts, err := parseSiteAlerts(s.InnerXML)
		if err != nil {
			return "", "", nil, 0, fmt.Errorf("zap: parse site alerts: %w", err)
		}
		alertCount += len(alerts)
		sites = append(sites, s)
	}
	if len(sites) == 0 {
		sites = []SiteXML{emptySite(expectedScheme, expectedIP, expectedPort, originName)}
	}
	return version, generated, sites, alertCount, nil
}

func emptySite(scheme string, ip netip.Addr, port uint16, originName string) SiteXML {
	ssl := "false"
	if scheme == "https" {
		ssl = "true"
	}
	return SiteXML{
		Name:     originName,
		Host:     ip.Unmap().String(),
		Port:     strconv.Itoa(int(port)),
		SSL:      ssl,
		InnerXML: []byte("<alerts></alerts>"),
	}
}

func marshalReport(program, version, generated string, sites []SiteXML) ([]byte, error) {
	if program == "" {
		program = "ZAP"
	}
	if version == "" {
		version = defaultReportVersion
	}
	doc := reportXML{
		ProgramName: program,
		Version:     version,
		Generated:   generated,
		Sites:       sites,
	}
	body, err := xml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("zap: marshal XML report: %w", err)
	}
	out := make([]byte, 0, len(xml.Header)+len(body)+1)
	out = append(out, xml.Header...)
	out = append(out, body...)
	out = append(out, '\n')
	return out, nil
}

func parseSiteAlerts(inner []byte) ([]alertItemXML, error) {
	if len(bytes.TrimSpace(inner)) == 0 {
		return nil, nil
	}
	var wrap siteAlertsXML
	wrapped := make([]byte, 0, len(inner)+len("<site></site>"))
	wrapped = append(wrapped, "<site>"...)
	wrapped = append(wrapped, inner...)
	wrapped = append(wrapped, "</site>"...)
	if err := xml.Unmarshal(wrapped, &wrap); err != nil {
		return nil, err
	}
	return wrap.Alerts, nil
}

func parseSiteIP(host string) (netip.Addr, bool) {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	ip, err := netip.ParseAddr(h)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func parseSitePort(portStr, sslStr string) uint16 {
	if p, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16); err == nil && p > 0 {
		return uint16(p)
	}
	if strings.EqualFold(strings.TrimSpace(sslStr), "true") {
		return 443
	}
	return 80
}

func mapRiskCode(code string) string {
	switch strings.TrimSpace(code) {
	case "3":
		return "high"
	case "2":
		return "medium"
	case "1":
		return "low"
	default:
		return "info"
	}
}
