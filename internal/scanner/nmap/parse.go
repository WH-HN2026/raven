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

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
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
		Name      string `xml:"name,attr"`
		Product   string `xml:"product,attr"`
		Version   string `xml:"version,attr"`
		ExtraInfo string `xml:"extrainfo,attr"`
		Tunnel    string `xml:"tunnel,attr"`
		ServiceFP string `xml:"servicefp,attr"`
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
		PerIP:        func(ip netip.Addr) []byte { return perIP(raw, spans, ip) },
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

// perIP returns raw with every <host>/<hosthint> removed except the <host>
// of ip, or nil if ip has no <host> in this output. The rest of the
// document (header, scaninfo, runstats) is kept byte for byte, so Dojo's
// Nmap parser reads it like any -oX file. A down host has no <hostnames>,
// which Dojo's parser iterates unconditionally, so an empty one is added.
func perIP(raw []byte, spans []hostSpan, ip netip.Addr) []byte {
	ip = ip.Unmap()
	found := false
	var b bytes.Buffer
	b.Grow(len(raw))
	last := int64(0)
	for _, s := range spans {
		if s.isHost && s.ip == ip && !found {
			found = true
			b.Write(raw[last:s.start])
			el := raw[s.start:s.end]
			if !bytes.Contains(el, []byte("<hostnames")) {
				i := bytes.LastIndex(el, []byte("</host>"))
				if i >= 0 {
					b.Write(el[:i])
					b.WriteString("<hostnames>\n</hostnames>\n")
					b.Write(el[i:])
					last = s.end
					continue
				}
			}
			b.Write(el)
			last = s.end
			continue
		}
		b.Write(raw[last:s.start])
		last = s.end
		// drop the newline nmap writes after each element, to keep it tidy
		if last < int64(len(raw)) && raw[last] == '\n' {
			last++
		}
	}
	if !found {
		return nil
	}
	b.Write(raw[last:])
	return b.Bytes()
}
