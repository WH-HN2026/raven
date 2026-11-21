package exchange

import (
	"bytes"
	"cmp"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// NessusService is an open port discovered in a .nessus ReportHost.
type NessusService struct {
	Port  uint16
	Proto string
	Name  string
}

// NessusHostInfo is one parsed <ReportHost> from a .nessus XML file.
type NessusHostInfo struct {
	IP        netip.Addr
	Hostnames []string
	Services  []NessusService
}

// NessusDocument holds the parsed hosts/services of a .nessus report plus
// PerIP to extract a valid single-IP NessusClientData_v2 XML document for
// DefectDojo's "Tenable Scan" parser.
type NessusDocument struct {
	Raw   []byte
	Hosts []NessusHostInfo
	PerIP func(ip netip.Addr) []byte
}

type nessusHostSpan struct {
	start, end int64
	ip         netip.Addr
}

type xmlNessusHost struct {
	Name       string `xml:"name,attr"`
	Properties []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"HostProperties>tag"`
	Items []struct {
		Port     string `xml:"port,attr"`
		SvcName  string `xml:"svc_name,attr"`
		Protocol string `xml:"protocol,attr"`
	} `xml:"ReportItem"`
}

// ParseNessus parses a NessusClientData_v2 (.nessus) XML report, extracting
// each host's IP, hostnames, open services, and byte-span PerIP slices.
func ParseNessus(raw []byte) (*NessusDocument, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	var (
		spans   []nessusHostSpan
		byIP    = make(map[netip.Addr]*NessusHostInfo)
		order   []netip.Addr
		depth   int
		sawRoot bool
	)
	for {
		off := d.InputOffset()
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: nessus xml: %v", ErrInvalid, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if !strings.Contains(t.Name.Local, "NessusClientData_v2") {
					return nil, fmt.Errorf("%w: nessus xml: root is <%s>, want <NessusClientData_v2>", ErrInvalid, t.Name.Local)
				}
				sawRoot = true
				depth++
				continue
			}
			if t.Name.Local == "ReportHost" {
				var rh xmlNessusHost
				if err := d.DecodeElement(&rh, &t); err != nil {
					return nil, fmt.Errorf("%w: nessus <ReportHost>: %v", ErrInvalid, err)
				}
				ip, hostnames, ok := rh.identity()
				spans = append(spans, nessusHostSpan{start: off, end: d.InputOffset(), ip: ip})
				if !ok {
					continue
				}
				info := byIP[ip]
				if info == nil {
					info = &NessusHostInfo{IP: ip}
					byIP[ip] = info
					order = append(order, ip)
				}
				info.Hostnames = mergeUniqueStrings(info.Hostnames, hostnames)
				info.Services = mergeNessusServices(info.Services, rh.services())
				continue
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
	if !sawRoot {
		return nil, fmt.Errorf("%w: nessus xml: no <NessusClientData_v2> element", ErrInvalid)
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("%w: nessus xml: no <ReportHost> with a valid IP address", ErrInvalid)
	}
	hosts := make([]NessusHostInfo, 0, len(order))
	for _, ip := range order {
		hosts = append(hosts, *byIP[ip])
	}
	return &NessusDocument{
		Raw:   raw,
		Hosts: hosts,
		PerIP: func(ip netip.Addr) []byte { return nessusPerIP(raw, spans, ip) },
	}, nil
}

func (rh xmlNessusHost) identity() (netip.Addr, []string, bool) {
	var (
		ip        netip.Addr
		hostnames []string
	)
	for _, tag := range rh.Properties {
		v := strings.TrimSpace(tag.Value)
		if v == "" {
			continue
		}
		switch tag.Name {
		case "host-ip":
			if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
				ip = a.Unmap()
			}
		case "host-fqdn", "hostname", "netbios-name":
			if _, err := netip.ParseAddr(v); err != nil {
				hostnames = append(hostnames, strings.ToLower(strings.TrimSuffix(v, ".")))
			}
		}
	}
	name := strings.TrimSpace(rh.Name)
	if name != "" {
		if a, err := netip.ParseAddr(name); err == nil && a.Zone() == "" {
			if !ip.IsValid() {
				ip = a.Unmap()
			}
		} else {
			hostnames = append(hostnames, strings.ToLower(strings.TrimSuffix(name, ".")))
		}
	}
	if !ip.IsValid() {
		return netip.Addr{}, nil, false
	}
	return ip, cleanStrings(hostnames), true
}

func (rh xmlNessusHost) services() []NessusService {
	var out []NessusService
	for _, item := range rh.Items {
		p, err := strconv.ParseUint(strings.TrimSpace(item.Port), 10, 16)
		if err != nil || p == 0 {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(item.Protocol))
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" {
			continue
		}
		name := strings.TrimSpace(item.SvcName)
		if name == "www" {
			name = "http"
		}
		if name == "general" || name == "unknown" {
			name = ""
		}
		out = append(out, NessusService{Port: uint16(p), Proto: proto, Name: name})
	}
	return out
}

func mergeNessusServices(have, add []NessusService) []NessusService {
	type key struct {
		port  uint16
		proto string
	}
	idx := make(map[key]int, len(have))
	out := slices.Clone(have)
	for i, sv := range out {
		idx[key{sv.Port, sv.Proto}] = i
	}
	for _, sv := range add {
		k := key{sv.Port, sv.Proto}
		if i, ok := idx[k]; ok {
			out[i].Name = cmp.Or(out[i].Name, sv.Name)
			continue
		}
		idx[k] = len(out)
		out = append(out, sv)
	}
	slices.SortFunc(out, func(a, b NessusService) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Proto, b.Proto))
	})
	return out
}

// nessusPerIP returns raw with every <ReportHost> removed except those whose
// IP matches ip, keeping the surrounding <NessusClientData_v2>, <Policy>, and
// <Report> intact byte-for-byte.
func nessusPerIP(raw []byte, spans []nessusHostSpan, ip netip.Addr) []byte {
	ip = ip.Unmap()
	found := false
	var b bytes.Buffer
	b.Grow(len(raw))
	last := int64(0)
	for _, s := range spans {
		if s.ip.IsValid() && s.ip == ip {
			found = true
			b.Write(raw[last:s.end])
			last = s.end
			continue
		}
		b.Write(raw[last:s.start])
		last = s.end
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

// BuildObservations turns the parsed Nessus hosts and open ports into
// scanner.Observations so hosts and services appear in ASI's database.
func (d *NessusDocument) BuildObservations(seen time.Time) (*scanner.Result, []netip.Addr, map[netip.Addr][]string) {
	if seen.IsZero() {
		seen = time.Now().UTC()
	}
	var (
		obs       []scanner.Observation
		ips       = make([]netip.Addr, 0, len(d.Hosts))
		hostnames = make(map[netip.Addr][]string, len(d.Hosts))
	)
	for _, h := range d.Hosts {
		ips = append(ips, h.IP)
		primaryName := ""
		if len(h.Hostnames) > 0 {
			hostnames[h.IP] = slices.Clone(h.Hostnames)
			primaryName = h.Hostnames[0]
		}
		obs = append(obs, scanner.Observation{
			Kind: scanner.ObsHost, IP: h.IP, Hostname: primaryName, At: seen, Up: true,
		})
		for _, sv := range h.Services {
			obs = append(obs, scanner.Observation{
				Kind: scanner.ObsService, IP: h.IP, Hostname: primaryName, At: seen,
				Port: sv.Port, Proto: sv.Proto, Service: sv.Name,
			})
		}
	}
	return &scanner.Result{Raw: d.Raw, Observations: obs, PerIP: d.PerIP}, ips, hostnames
}
