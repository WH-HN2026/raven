//go:build scaletest

// Package scaletest provides a deterministic fake-scanner + fake-Dojo load test
// at 16k (/18) and 65k (/16) hosts. Everything in this package is gated behind
// the "scaletest" build tag so fake scanners can never be compiled into or
// selected by the production binary.
package scaletest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// World defines a deterministic synthetic network where ~30% of IPs are up,
// each with 1–5 services (including HTTP/HTTPS with technologies and nuclei
// matches). Bumping Generation from 0 to 1 perturbs ~5% of the address space
// (new hosts, down hosts with partial re-probe recovery, added/removed ports,
// and service/HTTP fingerprint changes).
type World struct {
	Generation atomic.Int32

	// PerIPDelay scales realistic scan latency down for fast local load tests
	// while keeping batch duration_ms > 0 so S5 adaptive batching exercises its
	// throughput estimator.
	NmapPerIP    time.Duration
	HTTPXPerURL  time.Duration
	NucleiPerURL time.Duration

	NmapCalls    atomic.Int64
	HTTPXCalls   atomic.Int64
	NucleiCalls  atomic.Int64
	ReprobeCalls atomic.Int64
}

type synthService struct {
	Port    uint16
	Name    string
	Tunnel  string // "ssl" or ""
	Product string
	Version string
	CPE     string // cpe:/a:...
	NormCPE string // vendor:product[:version]
	Banner  string
	HTTP    *synthHTTP
}

type synthHTTP struct {
	Status      int
	Title       string
	Server      string
	Cookies     []string
	Env         string
	FaviconHash string
	Techs       []string
	Panel       string // non-empty => emits a nuclei panel/tech match
}

type synthHost struct {
	Up       bool
	Hostname string
	Services []synthService
}

func hashIP(ip netip.Addr) uint64 {
	b := ip.Unmap().As4()
	x := uint64(binary.BigEndian.Uint32(b[:])) + 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

var (
	webServers = []struct {
		product, ver1, ver2, cpe, tech1, tech2 string
	}{
		{"nginx", "1.24.0", "1.26.2", "igor_sysoev:nginx", "Nginx:1.24.0", "Nginx:1.26.2"},
		{"Apache httpd", "2.4.57", "2.4.62", "apache:http_server", "Apache:2.4.57", "Apache:2.4.62"},
		{"Caddy", "2.7.6", "2.8.4", "caddyserver:caddy", "Caddy:2.7.6", "Caddy:2.8.4"},
		{"Envoy", "1.28.0", "1.30.1", "envoyproxy:envoy", "Envoy:1.28.0", "Envoy:1.30.1"},
	}
	appTechs = []string{
		"WordPress:6.4", "PHP:8.2", "Grafana:10.2", "React:18.2",
		"Tomcat:10.1", "Django:5.0", "Spring Boot:3.2", "Jenkins:2.440",
		"GitLab:16.9", "Prometheus:2.50", "Keycloak:24.0", "Drupal:10.2",
	}
	panelTemplates = []struct {
		id, name, vendor, product, severity string
		tags                                []string
	}{
		{"grafana-detect", "Grafana Detect", "grafana", "grafana", "info", []string{"tech", "panel"}},
		{"jenkins-login", "Jenkins Login Panel", "jenkins", "jenkins", "info", []string{"panel"}},
		{"gitlab-detect", "GitLab Detect", "gitlab", "gitlab", "info", []string{"tech", "panel"}},
		{"wordpress-detect", "WordPress Detect", "wordpress", "wordpress", "info", []string{"tech"}},
		{"prometheus-detect", "Prometheus Detect", "prometheus", "prometheus", "info", []string{"tech", "panel"}},
	}
	faviconHashes = []string{"-1169135147", "116323821", "81586312", "-247388890", "708578229"}
)

// hostState computes the deterministic state of ip for the given generation
// and whether the call is an S6 single-port re-probe.
func (w *World) hostState(ip netip.Addr, gen int32, reprobe bool) synthHost {
	h := hashIP(ip)
	baseUp := (h % 100) < 30 // ~30% up
	// ~5% of IPs change in generation >= 1.
	changeBucket := (h / 100) % 100
	changed := gen > 0 && changeBucket < 5

	up := baseUp
	if changed {
		if baseUp && changeBucket < 2 {
			// ~2% of all IPs (~6.6% of up hosts) go down in gen 1.
			// On S6 re-probe, 30% of those recover (flapping), 70% stay down.
			if reprobe && ((h/10000)%10) < 3 {
				up = true
			} else {
				up = false
			}
		} else if !baseUp && changeBucket < 2 {
			// ~1.4% of all IPs (previously down) come up in gen 1.
			up = true
		}
	}
	if !up {
		return synthHost{Up: false}
	}

	b := ip.Unmap().As4()
	hostname := ""
	if (h/10000)%2 == 0 {
		hostname = fmt.Sprintf("srv-%d-%d-%d-%d.lab.internal", b[0], b[1], b[2], b[3])
	}

	// 1..5 services chosen deterministically from common profile ports.
	svcCount := int((h/20000)%5) + 1
	ws := webServers[int((h/100000)%uint64(len(webServers)))]
	app := appTechs[int((h/1000000)%uint64(len(appTechs)))]
	fav := faviconHashes[int((h/10000000)%uint64(len(faviconHashes)))]
	env := ""
	if (h/30000)%10 == 0 {
		env = "staging"
	}
	panel := ""
	if (h/40000)%7 == 0 {
		panel = panelTemplates[int((h/50000)%uint64(len(panelTemplates)))].id
	}

	// Fingerprint mutation for changed up hosts in buckets 2..4.
	fpMutated := changed && baseUp && changeBucket == 4
	portAdded := changed && baseUp && changeBucket == 2
	portRemoved := changed && baseUp && changeBucket == 3

	ver := ws.ver1
	wsTech := ws.tech1
	titleSuffix := ""
	if fpMutated {
		ver = ws.ver2
		wsTech = ws.tech2
		titleSuffix = " v2"
	}

	catalog := []synthService{
		{
			Port: 80, Name: "http", Product: ws.product, Version: ver,
			CPE: "cpe:/a:" + ws.cpe + ":" + ver, NormCPE: ws.cpe + ":" + ver,
			HTTP: &synthHTTP{
				Status: 200, Title: fmt.Sprintf("%s Portal %d.%d%s", ws.product, b[2], b[3], titleSuffix),
				Server: ws.product + "/" + ver, Cookies: []string{"session_id=abc123; HttpOnly"},
				Env: env, FaviconHash: fav, Techs: []string{wsTech, app}, Panel: panel,
			},
		},
		{
			Port: 22, Name: "ssh", Product: "OpenSSH", Version: "8.9p1",
			CPE: "cpe:/a:openbsd:openssh:8.9p1", NormCPE: "openbsd:openssh:8.9p1",
			Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		},
		{
			Port: 443, Name: "http", Tunnel: "ssl", Product: ws.product, Version: ver,
			CPE: "cpe:/a:" + ws.cpe + ":" + ver, NormCPE: ws.cpe + ":" + ver,
			HTTP: &synthHTTP{
				Status: 200, Title: fmt.Sprintf("TLS %s %d.%d%s", ws.product, b[2], b[3], titleSuffix),
				Server: ws.product + "/" + ver, Cookies: []string{"sid=xyz789; Secure; HttpOnly"},
				Env: env, FaviconHash: fav, Techs: []string{wsTech, app}, Panel: panel,
			},
		},
		{
			Port: 8080, Name: "http-proxy", Product: "Apache Tomcat", Version: "10.1.18",
			CPE: "cpe:/a:apache:tomcat:10.1.18", NormCPE: "apache:tomcat:10.1.18",
			HTTP: &synthHTTP{
				Status: 200, Title: fmt.Sprintf("App %d.%d%s", b[2], b[3], titleSuffix),
				Server: "Apache-Coyote/1.1", FaviconHash: fav, Techs: []string{"Tomcat:10.1", app},
			},
		},
		{
			Port: 5432, Name: "postgresql", Product: "PostgreSQL DB", Version: "16.1",
			CPE: "cpe:/a:postgresql:postgresql:16.1", NormCPE: "postgresql:postgresql:16.1",
			Banner: "PostgreSQL 16.1",
		},
	}

	// Pick svcCount services starting at a deterministic offset so not every host has port 80.
	startIdx := int((h / 70000) % 3) // 0, 1, or 2
	svcs := make([]synthService, 0, svcCount+1)
	for i := 0; i < svcCount; i++ {
		svcs = append(svcs, catalog[(startIdx+i)%len(catalog)])
	}
	if portRemoved && len(svcs) > 1 {
		svcs = svcs[:len(svcs)-1]
	}
	if portAdded {
		svcs = append(svcs, synthService{
			Port: 6379, Name: "redis", Product: "Redis key-value store", Version: "7.2.4",
			CPE: "cpe:/a:redis:redis:7.2.4", NormCPE: "redis:redis:7.2.4",
			Banner: "Redis 7.2.4",
		})
	}
	if fpMutated && len(svcs) > 0 && svcs[0].HTTP != nil {
		svcs[0].HTTP.Techs = append(svcs[0].HTTP.Techs, "Cloudflare")
	}

	return synthHost{Up: true, Hostname: hostname, Services: svcs}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FakeNmap implements scanner.Scanner with deterministic synthetic nmap XML.
type FakeNmap struct{ World *World }

var _ scanner.Scanner = (*FakeNmap)(nil)

func (*FakeNmap) Name() string         { return "nmap" }
func (*FakeNmap) DojoScanType() string { return "Nmap Scan" }

func (f *FakeNmap) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	f.World.NmapCalls.Add(1)
	reprobe := !strings.Contains(opt.Ports, ",") && !strings.Contains(opt.Ports, "-")
	if reprobe {
		f.World.ReprobeCalls.Add(1)
	}
	if err := sleepCtx(ctx, time.Duration(len(in.IPs))*f.World.NmapPerIP); err != nil {
		return nil, err
	}

	gen := f.World.Generation.Load()
	now := time.Now().UTC()
	ts := now.Unix()

	var (
		xmlBuf bytes.Buffer
		obs    = make([]scanner.Observation, 0, len(in.IPs)*2)
		byIP   = make(map[netip.Addr][]byte, len(in.IPs)/3)
	)
	header := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nmaprun scanner=\"nmap\" start=\"%d\" version=\"7.99\" xmloutputversion=\"1.05\">\n", ts)
	footer := "</nmaprun>\n"
	xmlBuf.Grow(len(in.IPs) * 260)
	xmlBuf.WriteString(header)

	var hostBuf bytes.Buffer
	for _, rawIP := range in.IPs {
		ip := rawIP.Unmap()
		st := f.World.hostState(ip, gen, reprobe)
		if !st.Up {
			obs = append(obs, scanner.Observation{Kind: scanner.ObsHost, IP: ip, At: now, Up: false})
			xmlBuf.WriteString(`<host><status state="down" reason="no-response"/><address addr="`)
			xmlBuf.WriteString(ip.String())
			xmlBuf.WriteString(`" addrtype="ipv4"/></host>`)
			xmlBuf.WriteByte('\n')
			continue
		}

		obs = append(obs, scanner.Observation{
			Kind: scanner.ObsHost, IP: ip, Hostname: st.Hostname, At: now, Up: true,
		})

		hostBuf.Reset()
		fmt.Fprintf(&hostBuf, `<host starttime="%d" endtime="%d"><status state="up" reason="syn-ack"/>`+"\n", ts, ts)
		fmt.Fprintf(&hostBuf, `<address addr="%s" addrtype="ipv4"/>`+"\n", ip.String())
		if st.Hostname != "" {
			fmt.Fprintf(&hostBuf, `<hostnames><hostname name="%s" type="PTR"/></hostnames>`+"\n", st.Hostname)
		} else {
			hostBuf.WriteString("<hostnames></hostnames>\n")
		}
		hostBuf.WriteString("<ports>\n")
		for _, s := range st.Services {
			svcName := s.Name
			if s.Tunnel == "ssl" && svcName == "http" {
				svcName = "https"
			}
			obs = append(obs, scanner.Observation{
				Kind: scanner.ObsService, IP: ip, Hostname: st.Hostname, At: now,
				Port: s.Port, Proto: "tcp", Service: svcName,
				Product: s.Product, Version: s.Version, CPE: s.NormCPE, Banner: s.Banner,
			})
			fmt.Fprintf(&hostBuf, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack"/><service name="%s"`, s.Port, s.Name)
			if s.Product != "" {
				fmt.Fprintf(&hostBuf, ` product="%s"`, s.Product)
			}
			if s.Version != "" {
				fmt.Fprintf(&hostBuf, ` version="%s"`, s.Version)
			}
			if s.Tunnel != "" {
				fmt.Fprintf(&hostBuf, ` tunnel="%s"`, s.Tunnel)
			}
			hostBuf.WriteString(` method="probed" conf="10">`)
			if s.CPE != "" {
				fmt.Fprintf(&hostBuf, `<cpe>%s</cpe>`, s.CPE)
			}
			hostBuf.WriteString("</service>")
			if s.Banner != "" {
				fmt.Fprintf(&hostBuf, `<script id="banner" output="%s"/>`, s.Banner)
			}
			if s.HTTP != nil {
				fmt.Fprintf(&hostBuf, `<script id="http-title" output="%s"><elem key="title">%s</elem></script>`, s.HTTP.Title, s.HTTP.Title)
			}
			hostBuf.WriteString("</port>\n")
		}
		hostBuf.WriteString("</ports></host>\n")
		chunk := hostBuf.Bytes()
		xmlBuf.Write(chunk)

		// PerIP snippet kept compact per responding IP.
		per := make([]byte, 0, len(header)+len(chunk)+len(footer))
		per = append(per, header...)
		per = append(per, chunk...)
		per = append(per, footer...)
		byIP[ip] = per
	}
	xmlBuf.WriteString(footer)
	return &scanner.Result{
		Raw:          xmlBuf.Bytes(),
		Observations: obs,
		PerIP:        func(ip netip.Addr) []byte { return byIP[ip.Unmap()] },
	}, nil
}

// FakeHTTPX implements scanner.Scanner with deterministic synthetic httpx JSONL.
type FakeHTTPX struct{ World *World }

var _ scanner.Scanner = (*FakeHTTPX)(nil)

func (*FakeHTTPX) Name() string         { return "httpx" }
func (*FakeHTTPX) DojoScanType() string { return "httpx Scan" }

type fakeHTTPXLine struct {
	Timestamp string            `json:"timestamp"`
	Input     string            `json:"input"`
	URL       string            `json:"url"`
	HostIP    string            `json:"host_ip"`
	Status    int               `json:"status_code"`
	Title     string            `json:"title"`
	Header    map[string]string `json:"header"`
	TLS       json.RawMessage   `json:"tls,omitempty"`
	Favicon   string            `json:"favicon,omitempty"`
	Tech      []string          `json:"tech,omitempty"`
}

func (f *FakeHTTPX) Run(ctx context.Context, in scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	f.World.HTTPXCalls.Add(1)
	if err := sleepCtx(ctx, time.Duration(len(in.URLs))*f.World.HTTPXPerURL); err != nil {
		return nil, err
	}
	gen := f.World.Generation.Load()
	now := time.Now().UTC()
	tsStr := now.Format(time.RFC3339)

	var (
		rawBuf bytes.Buffer
		obs    = make([]scanner.Observation, 0, len(in.URLs)*2)
		byIP   = make(map[netip.Addr][]byte, len(in.IPs))
	)
	rawBuf.Grow(len(in.URLs) * 240)

	// Map known hostnames back to IP from input.
	hostToIP := make(map[string]netip.Addr, len(in.Hostnames))
	for ip, names := range in.Hostnames {
		for _, n := range names {
			hostToIP[strings.ToLower(n)] = ip.Unmap()
		}
	}

	for _, rawURL := range in.URLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		portNum, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			continue
		}
		port := uint16(portNum)
		ip, err := netip.ParseAddr(u.Hostname())
		hostname := ""
		if err != nil {
			var ok bool
			ip, ok = hostToIP[strings.ToLower(u.Hostname())]
			if !ok {
				continue
			}
			hostname = u.Hostname()
		}
		ip = ip.Unmap()
		st := f.World.hostState(ip, gen, false)
		if !st.Up {
			continue
		}
		var h *synthHTTP
		for i := range st.Services {
			if st.Services[i].Port == port && st.Services[i].HTTP != nil {
				h = st.Services[i].HTTP
				break
			}
		}
		if h == nil {
			continue
		}
		headers := map[string]string{
			"Server":       h.Server,
			"Content-Type": "text/html; charset=utf-8",
		}
		if len(h.Cookies) > 0 {
			headers["Set-Cookie"] = strings.Join(h.Cookies, ", ")
		}
		if h.Env != "" {
			headers["X-Environment"] = h.Env
		}
		var tlsRaw json.RawMessage
		tlsStr := ""
		if u.Scheme == "https" {
			tlsStr = fmt.Sprintf(`{"subject_cn":"%s","tls_version":"tls13"}`, ip.String())
			tlsRaw = json.RawMessage(tlsStr)
		}
		rec := fakeHTTPXLine{
			Timestamp: tsStr,
			Input:     rawURL,
			URL:       rawURL,
			HostIP:    ip.String(),
			Status:    h.Status,
			Title:     h.Title,
			Header:    headers,
			TLS:       tlsRaw,
			Favicon:   h.FaviconHash,
			Tech:      h.Techs,
		}
		line, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		line = append(line, '\n')
		rawBuf.Write(line)
		byIP[ip] = append(byIP[ip], line...)

		info := &scanner.HTTPInfo{
			Status:       h.Status,
			Title:        h.Title,
			Headers:      headers,
			Cookies:      h.Cookies,
			TLSCert:      tlsStr,
			FaviconHash:  h.FaviconHash,
			Technologies: h.Techs,
		}
		obs = append(obs, scanner.Observation{
			Kind: scanner.ObsHTTP, IP: ip, Hostname: hostname, At: now,
			Port: port, Proto: "tcp", URL: rawURL, HTTP: info,
		})
		for _, tech := range h.Techs {
			obs = append(obs, scanner.Observation{
				Kind: scanner.ObsTech, IP: ip, Hostname: hostname, At: now,
				Port: port, Proto: "tcp", URL: rawURL, Tech: tech,
			})
		}
	}
	return &scanner.Result{
		Raw:          rawBuf.Bytes(),
		Observations: obs,
		PerIP:        func(ip netip.Addr) []byte { return byIP[ip.Unmap()] },
	}, nil
}

// FakeNuclei implements scanner.Scanner with deterministic synthetic nuclei JSONL.
type FakeNuclei struct{ World *World }

var _ scanner.Scanner = (*FakeNuclei)(nil)

func (*FakeNuclei) Name() string         { return "nuclei" }
func (*FakeNuclei) DojoScanType() string { return "Nuclei Scan" }

type fakeNucleiLine struct {
	TemplateID string   `json:"template-id"`
	Type       string   `json:"type"`
	URL        string   `json:"url"`
	MatchedAt  string   `json:"matched-at"`
	IP         string   `json:"ip"`
	Timestamp  string   `json:"timestamp"`
	Matcher    string   `json:"matcher-name"`
	Extracted  []string `json:"extracted-results,omitempty"`
	Info       struct {
		Name     string         `json:"name"`
		Severity string         `json:"severity"`
		Tags     []string       `json:"tags"`
		Metadata map[string]any `json:"metadata,omitempty"`
	} `json:"info"`
}

func (f *FakeNuclei) Run(ctx context.Context, in scanner.Input, _ scanner.Options) (*scanner.Result, error) {
	f.World.NucleiCalls.Add(1)
	if err := sleepCtx(ctx, time.Duration(len(in.URLs))*f.World.NucleiPerURL); err != nil {
		return nil, err
	}
	gen := f.World.Generation.Load()
	now := time.Now().UTC()
	tsStr := now.Format(time.RFC3339)

	var (
		rawBuf bytes.Buffer
		obs    []scanner.Observation
		byIP   = make(map[netip.Addr][]byte)
	)
	for _, rawURL := range in.URLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		portNum, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		st := f.World.hostState(ip, gen, false)
		if !st.Up {
			continue
		}
		var h *synthHTTP
		for i := range st.Services {
			if st.Services[i].Port == uint16(portNum) && st.Services[i].HTTP != nil {
				h = st.Services[i].HTTP
				break
			}
		}
		if h == nil || h.Panel == "" {
			continue
		}
		tmpl := panelTemplates[0]
		for _, pt := range panelTemplates {
			if pt.id == h.Panel {
				tmpl = pt
				break
			}
		}
		matchedAt := rawURL + "/login"
		rec := fakeNucleiLine{
			TemplateID: tmpl.id,
			Type:       "http",
			URL:        rawURL,
			MatchedAt:  matchedAt,
			IP:         ip.String(),
			Timestamp:  tsStr,
			Matcher:    "status-body",
			Extracted:  []string{"build=2026"},
		}
		rec.Info.Name = tmpl.name
		rec.Info.Severity = tmpl.severity
		rec.Info.Tags = tmpl.tags
		rec.Info.Metadata = map[string]any{"vendor": tmpl.vendor, "product": tmpl.product}
		line, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		line = append(line, '\n')
		rawBuf.Write(line)
		byIP[ip] = append(byIP[ip], line...)

		kind := scanner.ObsMatch
		tech := ""
		for _, t := range tmpl.tags {
			if t == "tech" {
				kind = scanner.ObsTech
				tech = tmpl.product
				break
			}
		}
		obs = append(obs, scanner.Observation{
			Kind: kind, IP: ip, At: now, Port: uint16(portNum), Proto: "tcp",
			URL: matchedAt, Product: tmpl.product, CPE: tmpl.vendor + ":" + tmpl.product, Tech: tech,
			Match: &scanner.MatchInfo{
				TemplateID: tmpl.id, Name: tmpl.name, Severity: tmpl.severity,
				Tags: tmpl.tags, Matcher: "status-body", Extracted: rec.Extracted, SourceURL: rawURL,
			},
		})
	}
	raw := rawBuf.Bytes()
	if raw == nil {
		raw = []byte{}
	}
	return &scanner.Result{
		Raw:          raw,
		Observations: obs,
		PerIP:        func(ip netip.Addr) []byte { return byIP[ip.Unmap()] },
	}, nil
}

// LocalOnlyResolver implements targets.Resolver and always refuses DNS lookups
// so the scale test can never issue outbound DNS packets.
type LocalOnlyResolver struct{}

func (LocalOnlyResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("scaletest: outbound DNS lookup blocked")
}
