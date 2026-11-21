package nmap

import (
	"bytes"
	"encoding/xml"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// testdata/lab.xml is real nmap 7.99 output: BuildArgs' exact command (ports
// 22,80,443,8080, --max-rate 100) run in the asi image against containers on
// an isolated --internal docker network (see testdata/README.md):
//
//	.10 nginx on 80 + 443 (self-signed TLS), .11 OpenSSH, .12 both, .20 no host.
func loadLab(t *testing.T) *scanner.Result {
	t.Helper()
	raw, err := os.ReadFile("testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

var (
	ipWeb   = netip.MustParseAddr("172.31.250.10")
	ipSSH   = netip.MustParseAddr("172.31.250.11")
	ipMixed = netip.MustParseAddr("172.31.250.12")
	ipNone  = netip.MustParseAddr("172.31.250.20")
)

// key is the part of an Observation the table below compares.
type key struct {
	Kind    scanner.ObservationKind
	IP      string
	Up      bool
	Port    uint16
	Proto   string
	Service string
	Product string
	Version string
	CPE     string
	URL     string
	Title   string
}

func keys(obs []scanner.Observation) []key {
	out := make([]key, 0, len(obs))
	for _, o := range obs {
		k := key{Kind: o.Kind, IP: o.IP.String(), Up: o.Up, Port: o.Port, Proto: o.Proto,
			Service: o.Service, Product: o.Product, Version: o.Version, CPE: o.CPE, URL: o.URL}
		if o.HTTP != nil {
			k.Title = o.HTTP.Title
		}
		out = append(out, k)
	}
	return out
}

func TestParseLab(t *testing.T) {
	res := loadLab(t)
	const title = "ASI S2 Test Page"
	want := []key{
		{Kind: scanner.ObsHost, IP: "172.31.250.20", Up: false},
		{Kind: scanner.ObsHost, IP: "172.31.250.10", Up: true},
		{Kind: scanner.ObsService, IP: "172.31.250.10", Port: 80, Proto: "tcp", Service: "http", Product: "nginx", CPE: "igor_sysoev:nginx"},
		{Kind: scanner.ObsHTTP, IP: "172.31.250.10", Port: 80, Proto: "tcp", Service: "http", URL: "http://172.31.250.10:80", Title: title},
		{Kind: scanner.ObsService, IP: "172.31.250.10", Port: 443, Proto: "tcp", Service: "https", Product: "nginx", CPE: "igor_sysoev:nginx"},
		{Kind: scanner.ObsHTTP, IP: "172.31.250.10", Port: 443, Proto: "tcp", Service: "https", URL: "https://172.31.250.10:443", Title: title},
		{Kind: scanner.ObsHost, IP: "172.31.250.11", Up: true},
		{Kind: scanner.ObsService, IP: "172.31.250.11", Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH", Version: "10.0", CPE: "openbsd:openssh:10.0"},
		{Kind: scanner.ObsHost, IP: "172.31.250.12", Up: true},
		{Kind: scanner.ObsService, IP: "172.31.250.12", Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH", Version: "10.0", CPE: "openbsd:openssh:10.0"},
		{Kind: scanner.ObsService, IP: "172.31.250.12", Port: 80, Proto: "tcp", Service: "http", Product: "nginx", CPE: "igor_sysoev:nginx"},
		{Kind: scanner.ObsHTTP, IP: "172.31.250.12", Port: 80, Proto: "tcp", Service: "http", URL: "http://172.31.250.12:80", Title: title},
		{Kind: scanner.ObsService, IP: "172.31.250.12", Port: 443, Proto: "tcp", Service: "https", Product: "nginx", CPE: "igor_sysoev:nginx"},
		{Kind: scanner.ObsHTTP, IP: "172.31.250.12", Port: 443, Proto: "tcp", Service: "https", URL: "https://172.31.250.12:443", Title: title},
	}
	if got := keys(res.Observations); !reflect.DeepEqual(got, want) {
		t.Fatalf("observations:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseLabDetails(t *testing.T) {
	res := loadLab(t)
	for _, o := range res.Observations {
		if o.At.IsZero() {
			t.Errorf("%s %s: zero At", o.Kind, o.IP)
		}
		switch {
		case o.Kind == scanner.ObsService && o.Service == "ssh":
			if !strings.HasPrefix(o.Banner, "SSH-2.0-OpenSSH_10.0") {
				t.Errorf("ssh banner = %q", o.Banner)
			}
		case o.Kind == scanner.ObsHTTP:
			if o.HTTP.Headers["Server"] != "nginx" {
				t.Errorf("%s headers = %v", o.URL, o.HTTP.Headers)
			}
			if _, ok := o.HTTP.Headers["(Request type"]; ok {
				t.Errorf("%s: request-type line parsed as header", o.URL)
			}
			isTLS := strings.HasPrefix(o.URL, "https://")
			hasPEM := strings.HasPrefix(o.HTTP.TLSCert, "-----BEGIN CERTIFICATE-----")
			if isTLS != hasPEM {
				t.Errorf("%s TLSCert = %.40q", o.URL, o.HTTP.TLSCert)
			}
		}
	}
}

func TestPerIPRoundTrip(t *testing.T) {
	res := loadLab(t)
	for _, ip := range []netip.Addr{ipWeb, ipSSH, ipMixed, ipNone} {
		t.Run(ip.String(), func(t *testing.T) {
			doc := res.PerIP(ip)
			if doc == nil {
				t.Fatal("PerIP returned nil")
			}
			again, err := Parse(doc)
			if err != nil {
				t.Fatalf("PerIP output does not parse: %v", err)
			}
			var want []scanner.Observation
			for _, o := range res.Observations {
				if o.IP == ip {
					want = append(want, o)
				}
			}
			if !reflect.DeepEqual(again.Observations, want) {
				t.Fatalf("round trip:\n got %+v\nwant %+v", keys(again.Observations), keys(want))
			}
			checkDojoShape(t, doc, ip)
		})
	}
	if got := res.PerIP(netip.MustParseAddr("10.9.9.9")); got != nil {
		t.Fatalf("PerIP of unknown IP = %d bytes, want nil", len(got))
	}
}

// checkDojoShape asserts what dojo/tools/nmap/parser.py reads: root <nmaprun>
// with a start attribute, and for each <host> an ipv4 <address> and a
// <hostnames> child (it iterates host.find("hostnames") without a None check).
// It also checks no other IP is left in a <host> or <hosthint>.
func checkDojoShape(t *testing.T, doc []byte, ip netip.Addr) {
	t.Helper()
	var run struct {
		XMLName xml.Name `xml:"nmaprun"`
		Start   string   `xml:"start,attr"`
		Hosts   []struct {
			Addrs []struct {
				Addr string `xml:"addr,attr"`
				Type string `xml:"addrtype,attr"`
			} `xml:"address"`
			Hostnames *struct{} `xml:"hostnames"`
		} `xml:"host"`
		Hints []struct{} `xml:"hosthint"`
	}
	if err := xml.Unmarshal(doc, &run); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if run.Start == "" {
		t.Error("nmaprun has no start attribute")
	}
	if len(run.Hosts) != 1 || len(run.Hints) != 0 {
		t.Fatalf("hosts=%d hosthints=%d, want 1 and 0", len(run.Hosts), len(run.Hints))
	}
	h := run.Hosts[0]
	if h.Hostnames == nil {
		t.Error("host has no <hostnames>")
	}
	var v4 string
	for _, a := range h.Addrs {
		if a.Type == "ipv4" {
			v4 = a.Addr
		}
	}
	if v4 != ip.String() {
		t.Errorf("ipv4 address = %q, want %s", v4, ip)
	}
	if !bytes.HasSuffix(bytes.TrimSpace(doc), []byte("</nmaprun>")) {
		t.Error("document does not end with </nmaprun>")
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		"empty":     "",
		"not nmap":  `<?xml version="1.0"?><foo/>`,
		"truncated": `<?xml version="1.0"?><nmaprun start="1"><host><status state="up"/>`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestParseHostnamesAndServiceNames(t *testing.T) {
	doc := `<?xml version="1.0"?><nmaprun start="1700000000">
<host starttime="1700000001" endtime="1700000002"><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<hostnames><hostname name="www.example.test" type="user"/><hostname name="ptr.example.test" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="993"><state state="open"/><service name="imap" product="Dovecot imapd" tunnel="ssl"/>
<script id="ssl-cert" output="Subject: commonName=mail"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/>
<script id="http-title" output="Did not follow redirect to https://x/"><elem key="redirect_url">https://x/</elem></script>
<script id="http-headers" output="&#xa;  Set-Cookie: a=1&#xa;  Set-Cookie: b=2&#xa;  &#xa;  (Request type: GET)&#xa;"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp"/></port>
</ports></host></nmaprun>`
	res, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	obs := res.Observations
	if len(obs) != 4 {
		t.Fatalf("got %d observations: %+v", len(obs), keys(obs))
	}
	for _, o := range obs {
		if o.Hostname != "www.example.test" {
			t.Errorf("%s hostname = %q", o.Kind, o.Hostname)
		}
		if o.At.Unix() != 1700000002 {
			t.Errorf("%s At = %v, want host endtime", o.Kind, o.At)
		}
	}
	imap := obs[1]
	if imap.Service != "ssl/imap" || imap.HTTP == nil || imap.HTTP.TLSCert != "Subject: commonName=mail" {
		t.Errorf("imaps = %+v", imap)
	}
	web := obs[3]
	if web.Kind != scanner.ObsHTTP || web.URL != "http://10.0.0.5:8080" {
		t.Fatalf("web = %+v", web)
	}
	if !reflect.DeepEqual(web.HTTP.Redirects, []string{"https://x/"}) || !reflect.DeepEqual(web.HTTP.Cookies, []string{"a=1", "b=2"}) {
		t.Errorf("web http = %+v", web.HTTP)
	}
	if web.HTTP.Headers["Set-Cookie"] != "a=1, b=2" {
		t.Errorf("headers = %v", web.HTTP.Headers)
	}
}

func TestNormalizeCPE(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"app with version", "cpe:/a:openbsd:openssh:7.4", "openbsd:openssh:7.4"},
		{"app without version", "cpe:/a:igor_sysoev:nginx", "igor_sysoev:nginx"},
		{"os without version", "cpe:/o:linux:linux_kernel", "linux:linux_kernel"},
		{"os with version", "cpe:/o:linux:linux_kernel:5.15", "linux:linux_kernel:5.15"},
		{"hardware with version", "cpe:/h:cisco:ios:15.2", "cisco:ios:15.2"},
		{"uppercase and spaces", "  CPE:/A:Apache:HTTP_Server:2.4.49  ", "apache:http_server:2.4.49"},
		{"extra trailing parts", "cpe:/a:openbsd:openssh:7.4:p1:pro", "openbsd:openssh:7.4"},
		{"empty version before update", "cpe:/a:vendor:product::sp1", "vendor:product"},
		{"wildcard version", "cpe:/a:vendor:product:*", "vendor:product"},
		{"cpe 2.3 with version", "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*", "openbsd:openssh:7.4"},
		{"cpe 2.3 without version", "cpe:2.3:a:igor_sysoev:nginx:-:*:*:*:*:*:*:*", "igor_sysoev:nginx"},
		{"empty", "", ""},
		{"not a cpe", "openbsd:openssh:7.4", ""},
		{"unknown part", "cpe:/x:vendor:product:1.0", ""},
		{"missing product", "cpe:/a:vendor", ""},
		{"empty product", "cpe:/a:vendor:", ""},
		{"wildcard vendor", "cpe:/a:*:product:1.0", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCPE(tt.in); got != tt.want {
				t.Errorf("normalizeCPE(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSelectCPE(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"empty", nil, ""},
		{"single app", []string{"cpe:/a:openbsd:openssh:7.4"}, "openbsd:openssh:7.4"},
		{"app over os regardless of order", []string{"cpe:/o:linux:linux_kernel:5.15", "cpe:/a:openbsd:openssh:8.9p1"}, "openbsd:openssh:8.9p1"},
		{"unversioned app over versioned os", []string{"cpe:/o:linux:linux_kernel:5.15", "cpe:/a:igor_sysoev:nginx"}, "igor_sysoev:nginx"},
		{"versioned app over unversioned app", []string{"cpe:/a:apache:http_server", "cpe:/a:apache:http_server:2.4.49"}, "apache:http_server:2.4.49"},
		{"first tie-breaker among equal rank", []string{"cpe:/a:openbsd:openssh:8.9p1", "cpe:/a:openssl:openssl:3.0"}, "openbsd:openssh:8.9p1"},
		{"os fallback prefers versioned", []string{"cpe:/o:linux:linux_kernel", "cpe:/o:linux:linux_kernel:5.15"}, "linux:linux_kernel:5.15"},
		{"hardware fallback", []string{"cpe:/h:cisco:ios"}, "cisco:ios"},
		{"skips invalid entries", []string{"not-a-cpe", "cpe:/a:vendor:product:1.0"}, "vendor:product:1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectCPE(tt.in); got != tt.want {
				t.Errorf("selectCPE(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseMultipleCPEs(t *testing.T) {
	doc := `<?xml version="1.0"?><nmaprun start="1700000000">
<host starttime="1700000001" endtime="1700000002"><status state="up"/>
<address addr="10.0.0.8" addrtype="ipv4"/><hostnames/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.9p1">
    <cpe>cpe:/o:linux:linux_kernel</cpe>
    <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
  </service>
</port>
<port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache httpd" version="2.4.49">
    <cpe>cpe:/a:apache:http_server</cpe>
    <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
  </service>
</port>
<port protocol="tcp" portid="445"><state state="open"/>
  <service name="microsoft-ds">
    <cpe>cpe:/o:microsoft:windows_server_2019</cpe>
  </service>
</port>
<port protocol="tcp" portid="9000"><state state="open"/>
  <service name="cslistener"/>
</port>
</ports></host></nmaprun>`
	res, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint16]string{}
	for _, o := range res.Observations {
		if o.Kind == scanner.ObsService {
			got[o.Port] = o.CPE
		}
	}
	want := map[uint16]string{
		22:   "openbsd:openssh:8.9p1",
		80:   "apache:http_server:2.4.49",
		445:  "microsoft:windows_server_2019",
		9000: "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("service CPEs = %v, want %v", got, want)
	}
}
