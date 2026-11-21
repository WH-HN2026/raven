package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Kind is how a port answers.
type Kind string

const (
	KindHTTP   Kind = "http"
	KindHTTPS  Kind = "https"
	KindSSH    Kind = "ssh"    // sends Banner, reads, closes
	KindFTP    Kind = "ftp"    // sends Banner, answers 530 to every line
	KindSilent Kind = "silent" // accepts, says nothing (JetDirect 9100)
)

// Extra paths a persona serves besides "/".
const (
	ExtraTomcatManager  = "tomcat-manager"  // /manager/html → 401 "Tomcat Manager Application"
	ExtraJenkinsFavicon = "jenkins-favicon" // /favicon.ico → the real Jenkins favicon
)

// Service is one open port of a host and the bytes it answers with.
type Service struct {
	Port    int
	Kind    Kind
	Banner  string      // ssh / ftp greeting, without CRLF
	Title   string      // HTML <title>
	Headers [][2]string // response headers on every HTTP path
	Body    string      // extra HTML after the <h1>
	Extra   string
}

// Fingerprint is what a scanner can see of the service; churn "changed"
// always alters it (version or title).
func (s Service) Fingerprint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d|%s|%s|%s|%s|%s", s.Port, s.Kind, s.Banner, s.Title, s.Body, s.Extra)
	for _, h := range s.Headers {
		fmt.Fprintf(&b, "|%s:%s", h[0], h[1])
	}
	return b.String()
}

// Persona names, in catalog order.
var personaNames = []string{
	"nginx-intranet", "apache-php", "iis", "tomcat", "jenkins", "staging",
	"printer", "camera", "router", "tls", "ssh", "ftp",
}

// pr gives the per-host random numbers a persona uses (fixed for an address).
type pr struct{ r [4]uint64 }

func (p pr) n(i int, mod int) int { return int(p.r[i] % uint64(mod)) }

func personaOf(seed uint64, off uint32) int {
	return int(mix(seed, 7001, off) % uint64(len(personaNames)))
}

// Services is the port list of h, sorted by port. The persona and its fixed
// choices depend only on (seed, address); h.Variant moves the parts churn
// changes (a version or a title) to the next value.
func Services(seed uint64, h Host) []Service {
	p := pr{}
	for i := range p.r {
		p.r[i] = mix(seed, 7100+uint64(i), h.Off)
	}
	v := h.Variant
	sshExtra := Service{Port: 22, Kind: KindSSH, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"}
	var out []Service
	switch personaNames[personaOf(seed, h.Off)] {
	case "nginx-intranet":
		versions := []string{"1.18.0", "1.20.0", "1.24.0", "1.26.3"}
		titles := []string{"Intranet", "Wiki", "Status"}
		web := Service{Kind: KindHTTP, Title: titles[p.n(1, 3)],
			Headers: [][2]string{{"Server", "nginx/" + versions[(p.n(0, 4)+v)%4]}}}
		web.Port = 80
		out = append(out, web)
		if p.n(2, 3) == 0 {
			web.Port = 8080
			out = append(out, web)
		}
		if p.n(3, 4) == 0 {
			out = append(out, sshExtra)
		}
	case "apache-php":
		titles := []string{"Intranet portal", "Team portal", "Document archive"}
		out = append(out, Service{Port: 80, Kind: KindHTTP, Title: titles[(p.n(0, 3)+v)%3],
			Headers: [][2]string{{"Server", "Apache/2.4.49 (Unix)"}, {"X-Powered-By", "PHP/7.4.3"}}})
		if p.n(3, 3) == 0 {
			out = append(out, sshExtra)
		}
	case "iis":
		versions := []string{"8.5", "10.0"}
		out = append(out, Service{Port: 80, Kind: KindHTTP, Title: "IIS Windows Server",
			Headers: [][2]string{
				{"Server", "Microsoft-IIS/" + versions[(p.n(0, 2)+v)%2]},
				{"X-Aspnet-Version", "4.0.30319"},
				{"X-Powered-By", "ASP.NET"},
				{"Set-Cookie", fmt.Sprintf("ASP.NET_SessionId=s%016x; path=/; HttpOnly", p.r[1])},
			}})
	case "tomcat":
		versions := []string{"9.0.65", "8.5.78", "10.1.16"}
		out = append(out, Service{Port: 8080, Kind: KindHTTP, Title: "Apache Tomcat/" + versions[(p.n(0, 3)+v)%3],
			Headers: [][2]string{{"Set-Cookie", fmt.Sprintf("JSESSIONID=%016X; Path=/; HttpOnly", p.r[1])}},
			Extra:   ExtraTomcatManager})
		if p.n(3, 2) == 0 {
			out = append(out, sshExtra)
		}
	case "jenkins":
		versions := []string{"2.440", "2.426.3"}
		titles := []string{"Dashboard [Jenkins]", "Sign in [Jenkins]"}
		i := (p.n(0, 2) + v) % 2
		out = append(out, Service{Port: 8080, Kind: KindHTTP, Title: titles[i],
			Headers: [][2]string{{"Server", "Jetty(10.0.18)"}, {"X-Hudson", "1.395"}, {"X-Jenkins", versions[i]}},
			Extra:   ExtraJenkinsFavicon})
	case "staging":
		apps := []string{"App", "Portal", "Shop", "CRM"}
		web := Service{Port: 80, Kind: KindHTTP, Title: apps[(p.n(0, 4)+v)%4] + " (staging)",
			Headers: [][2]string{{"Server", "nginx/1.24.0"}, {"X-Environment", "staging"}}}
		out = append(out, web)
		if p.n(2, 2) == 0 {
			web.Port, web.Kind = 8443, KindHTTPS
			out = append(out, web)
		}
	case "printer":
		models := []string{"HP LaserJet M402dn", "HP LaserJet M507", "HP LaserJet Pro M404n"}
		out = append(out,
			Service{Port: 80, Kind: KindHTTP, Title: models[(p.n(0, 3)+v)%3], Headers: [][2]string{{"Server", "HP HTTP Server"}}},
			Service{Port: 9100, Kind: KindSilent})
	case "camera":
		models := []string{"DS-2CD2042WD-I", "DS-2CD2143G2-IS", "DS-2CD2387G2-LU"}
		out = append(out, Service{Port: 80, Kind: KindHTTP, Title: "Network Camera " + models[(p.n(0, 3)+v)%3],
			Headers: [][2]string{{"Server", "Hikvision-Webs"}},
			Body:    `<script>window.location.href = "doc/page/login.asp?_" + (new Date()).getTime();</script>`})
	case "router":
		titles := []string{"RouterOS router configuration page", "TP-Link Archer C7", "OpenWrt - LuCI"}
		out = append(out, Service{Port: 80, Kind: KindHTTP, Title: titles[(p.n(0, 3)+v)%3]})
		if p.n(3, 2) == 0 {
			out = append(out, Service{Port: 22, Kind: KindSSH, Banner: "SSH-2.0-OpenSSH_7.4"})
		}
	case "tls":
		titles := []string{"Secure portal", "VPN portal", "Webmail"}
		web := Service{Port: 443, Kind: KindHTTPS, Title: titles[(p.n(0, 3)+v)%3],
			Headers: [][2]string{{"Server", "nginx/1.26.3"}}}
		out = append(out, web)
		if p.n(2, 3) == 0 {
			web.Port = 8443
			out = append(out, web)
		}
	case "ssh":
		banners := []string{"SSH-2.0-OpenSSH_7.4", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"}
		out = append(out, Service{Port: 22, Kind: KindSSH, Banner: banners[(p.n(0, 2)+v)%2]})
	case "ftp":
		versions := []string{"3.0.2", "3.0.3"}
		out = append(out, Service{Port: 21, Kind: KindFTP, Banner: "220 (vsFTPd " + versions[(p.n(0, 2)+v)%2] + ")"})
		if p.n(3, 3) == 0 {
			out = append(out, sshExtra)
		}
	}
	slices.SortFunc(out, func(a, b Service) int { return cmp.Compare(a.Port, b.Port) })
	return out
}
