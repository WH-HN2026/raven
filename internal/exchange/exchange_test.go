package exchange

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/changes"
	"github.com/WH-HN2026/raven/internal/dojo"
	"github.com/WH-HN2026/raven/internal/hosts"
	"github.com/WH-HN2026/raven/internal/scanner"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
	"github.com/WH-HN2026/raven/internal/scanner/nuclei"
	"github.com/WH-HN2026/raven/internal/targets"
)

func TestResultsJSONRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("testdata/sample_results.json")
	if err != nil {
		t.Fatal(err)
	}
	doc1, err := ParseResultsJSON(raw)
	if err != nil {
		t.Fatalf("parse sample json: %v", err)
	}
	if len(doc1.Hosts) != 3 {
		t.Fatalf("hosts = %d, want 3", len(doc1.Hosts))
	}

	encoded, err := EncodeResultsJSON(doc1)
	if err != nil {
		t.Fatalf("encode json: %v", err)
	}
	doc2, err := ParseResultsJSON(encoded)
	if err != nil {
		t.Fatalf("re-parse json: %v", err)
	}
	if len(doc2.Hosts) != len(doc1.Hosts) {
		t.Fatalf("round-trip hosts = %d, want %d", len(doc2.Hosts), len(doc1.Hosts))
	}
	h0 := doc2.Hosts[0]
	if h0.IP != "172.30.0.10" || !h0.IsUp() || !slices.Equal(h0.Hostnames, []string{"web.lab"}) {
		t.Fatalf("host 0 = %+v", h0)
	}
	if len(h0.Services) != 1 || h0.Services[0].Port != 80 || h0.Services[0].Product != "nginx" || h0.Services[0].CPE != "igor_sysoev:nginx:1.24.0" {
		t.Fatalf("host 0 services = %+v", h0.Services)
	}
	if len(h0.Services[0].HTTP) != 1 || h0.Services[0].HTTP[0].Title != "Welcome to Lab" || h0.Services[0].HTTP[0].Status != 200 {
		t.Fatalf("host 0 http = %+v", h0.Services[0].HTTP)
	}
	if len(h0.Services[0].Matches) != 1 || h0.Services[0].Matches[0].TemplateID != "nginx-version-header" {
		t.Fatalf("host 0 matches = %+v", h0.Services[0].Matches)
	}
	if doc2.Hosts[2].IsUp() {
		t.Fatalf("host 2 should be down")
	}

	// BuildImportData produces valid synthesized nmap XML parseable per IP.
	primary, httpRes, nucleiRes, ips, hostnames, err := doc2.BuildImportData()
	if err != nil {
		t.Fatalf("BuildImportData: %v", err)
	}
	if len(ips) != 3 || !slices.Equal(hostnames[netip.MustParseAddr("172.30.0.10")], []string{"web.lab"}) {
		t.Fatalf("ips=%v hostnames=%v", ips, hostnames)
	}
	if httpRes == nil || len(httpRes.Observations) != 1 {
		t.Fatalf("httpRes = %+v", httpRes)
	}
	if nucleiRes == nil || len(nucleiRes.Observations) != 1 || nucleiRes.Observations[0].Kind != scanner.ObsTech {
		t.Fatalf("nucleiRes = %+v", nucleiRes)
	}
	perIP := primary.PerIP(netip.MustParseAddr("172.30.0.10"))
	if !bytes.Contains(perIP, []byte(`addr="172.30.0.10"`)) || bytes.Contains(perIP, []byte(`addr="172.30.0.11"`)) {
		t.Fatalf("synthesized PerIP did not filter cleanly:\n%s", perIP)
	}
	if _, err := nmap.Parse(perIP); err != nil {
		t.Fatalf("nmap.Parse(PerIP) failed: %v", err)
	}
}

func TestResultsCSVRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("testdata/sample_results.csv")
	if err != nil {
		t.Fatal(err)
	}
	doc1, err := ParseResultsCSV(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse sample csv: %v", err)
	}
	var buf bytes.Buffer
	if err := EncodeResultsCSV(&buf, doc1); err != nil {
		t.Fatalf("encode csv: %v", err)
	}
	doc2, err := ParseResultsCSV(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("re-parse csv: %v", err)
	}
	if len(doc2.Hosts) != 3 {
		t.Fatalf("round-trip csv hosts = %d, want 3", len(doc2.Hosts))
	}
	if doc2.Hosts[0].IP != "172.30.0.10" || len(doc2.Hosts[0].Services) != 1 ||
		len(doc2.Hosts[0].Services[0].HTTP) != 1 || len(doc2.Hosts[0].Services[0].Matches) != 1 {
		t.Fatalf("host 0 after csv round-trip = %+v", doc2.Hosts[0])
	}
	if doc2.Hosts[1].IP != "172.30.0.11" || doc2.Hosts[1].Services[0].Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("host 1 after csv round-trip = %+v", doc2.Hosts[1])
	}
	if doc2.Hosts[2].IP != "172.30.0.20" || doc2.Hosts[2].IsUp() {
		t.Fatalf("host 2 after csv round-trip = %+v", doc2.Hosts[2])
	}
}

func TestExportServicesRoundTripIntoResultsImport(t *testing.T) {
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	svcs := []ExportServiceRow{
		{ID: 1, IP: netip.MustParseAddr("172.30.0.10"), Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.24.0", CPE: "igor_sysoev:nginx:1.24.0", State: "open", FirstSeen: now, LastSeen: now},
		{ID: 2, IP: netip.MustParseAddr("172.30.0.10"), Port: 8080, Proto: "tcp", Name: "http", Product: "old", State: "gone", FirstSeen: now, LastSeen: now},
	}

	// CSV export → ParseResultsCSV
	var csvBuf bytes.Buffer
	if err := WriteServicesCSV(&csvBuf, svcs); err != nil {
		t.Fatal(err)
	}
	fromCSV, err := ParseResultsCSV(bytes.NewReader(csvBuf.Bytes()))
	if err != nil {
		t.Fatalf("ParseResultsCSV(exported services): %v", err)
	}
	if len(fromCSV.Hosts) != 1 || len(fromCSV.Hosts[0].Services) != 1 || fromCSV.Hosts[0].Services[0].Port != 80 {
		t.Fatalf("fromCSV = %+v (expected only open port 80)", fromCSV.Hosts)
	}

	// JSON export → ParseResultsJSON
	var jsonBuf bytes.Buffer
	if err := writeJSON(&jsonBuf, svcs); err != nil {
		t.Fatal(err)
	}
	fromJSON, err := ParseResultsJSON(jsonBuf.Bytes())
	if err != nil {
		t.Fatalf("ParseResultsJSON(exported services): %v", err)
	}
	if len(fromJSON.Hosts) != 1 || len(fromJSON.Hosts[0].Services) != 1 || fromJSON.Hosts[0].Services[0].Port != 80 {
		t.Fatalf("fromJSON = %+v (expected only open port 80)", fromJSON.Hosts)
	}
}

func TestTargetsRoundTrip(t *testing.T) {
	entries := []targets.Entry{
		{Kind: targets.KindCIDR, Value: "172.30.0.0/24", Tags: []string{"lab", "web"}, Note: "Local lab"},
		{Kind: targets.KindDomain, Value: "wordpress.lab", Tags: []string{"cms"}, Note: ""},
	}

	var csvBuf bytes.Buffer
	if err := WriteTargetsCSV(&csvBuf, entries); err != nil {
		t.Fatal(err)
	}
	pCSV := targets.ParseCSV(bytes.NewReader(csvBuf.Bytes()))
	if len(pCSV.Errors) != 0 || len(pCSV.Entries) != 2 || pCSV.Entries[0].Value != "172.30.0.0/24" || !slices.Equal(pCSV.Entries[0].Tags, []string{"lab", "web"}) {
		t.Fatalf("targets CSV round-trip: %+v", pCSV)
	}

	var jsonBuf bytes.Buffer
	if err := writeJSON(&jsonBuf, entries); err != nil {
		t.Fatal(err)
	}
	pJSON := targets.ParseJSON(jsonBuf.Bytes())
	if len(pJSON.Errors) != 0 || len(pJSON.Entries) != 2 || pJSON.Entries[1].Value != "wordpress.lab" {
		t.Fatalf("targets JSON round-trip: %+v", pJSON)
	}
}

func TestParseScannerFixtures(t *testing.T) {
	t.Run("nmap lab.xml", func(t *testing.T) {
		raw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
		if err != nil {
			t.Fatal(err)
		}
		if got := DetectImportKind("lab.xml", raw); got != ImportNmapXML {
			t.Fatalf("DetectImportKind = %q, want %q", got, ImportNmapXML)
		}
		res, err := nmap.Parse(raw)
		if err != nil {
			t.Fatalf("nmap.Parse: %v", err)
		}
		if len(res.Observations) == 0 {
			t.Fatal("no observations parsed from lab.xml")
		}
		if slice := res.PerIP(netip.MustParseAddr("172.31.250.10")); len(slice) == 0 {
			t.Fatal("PerIP returned empty for 172.31.250.10")
		}
	})

	t.Run("nuclei lab-http.jsonl", func(t *testing.T) {
		raw, err := os.ReadFile("../scanner/nuclei/testdata/lab-http.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		if got := DetectImportKind("lab-http.jsonl", raw); got != ImportNucleiJSONL {
			t.Fatalf("DetectImportKind = %q, want %q", got, ImportNucleiJSONL)
		}
		res, err := nuclei.Parse(raw)
		if err != nil {
			t.Fatalf("nuclei.Parse: %v", err)
		}
		if len(res.Observations) != 2 {
			t.Fatalf("observations = %d, want 2", len(res.Observations))
		}
		if slice := res.PerIP(netip.MustParseAddr("172.30.0.17")); len(slice) == 0 {
			t.Fatal("PerIP returned empty for 172.30.0.17")
		}
	})

	t.Run("nuclei lab-ssl.jsonl", func(t *testing.T) {
		raw, err := os.ReadFile("../scanner/nuclei/testdata/lab-ssl.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		res, err := nuclei.Parse(raw)
		if err != nil {
			t.Fatalf("nuclei.Parse: %v", err)
		}
		if len(res.Observations) == 0 {
			t.Fatal("no observations from lab-ssl.jsonl")
		}
	})
}

func TestParseNessusAndPerIP(t *testing.T) {
	raw, err := os.ReadFile("testdata/sample.nessus")
	if err != nil {
		t.Fatal(err)
	}
	if got := DetectImportKind("sample.nessus", raw); got != ImportNessus {
		t.Fatalf("DetectImportKind = %q, want %q", got, ImportNessus)
	}
	if got := DetectImportKind("unknown.xml", raw); got != ImportNessus {
		t.Fatalf("DetectImportKind(.xml with NessusClientData_v2) = %q, want %q", got, ImportNessus)
	}

	doc, err := ParseNessus(raw)
	if err != nil {
		t.Fatalf("ParseNessus: %v", err)
	}
	if len(doc.Hosts) != 2 {
		t.Fatalf("hosts = %d, want 2", len(doc.Hosts))
	}
	ip1 := netip.MustParseAddr("172.30.0.10")
	ip2 := netip.MustParseAddr("172.30.0.11")

	if doc.Hosts[0].IP != ip1 || !slices.Equal(doc.Hosts[0].Hostnames, []string{"web.lab"}) || len(doc.Hosts[0].Services) != 2 {
		t.Fatalf("host 0 = %+v", doc.Hosts[0])
	}
	if doc.Hosts[0].Services[0].Port != 80 || doc.Hosts[0].Services[0].Name != "http" || doc.Hosts[0].Services[1].Port != 443 {
		t.Fatalf("host 0 services = %+v", doc.Hosts[0].Services)
	}
	if doc.Hosts[1].IP != ip2 || !slices.Equal(doc.Hosts[1].Hostnames, []string{"ssh.lab"}) || len(doc.Hosts[1].Services) != 1 || doc.Hosts[1].Services[0].Port != 22 {
		t.Fatalf("host 1 = %+v", doc.Hosts[1])
	}

	// PerIP splits into valid single-host NessusClientData_v2 XML.
	s1 := doc.PerIP(ip1)
	if !bytes.Contains(s1, []byte("<NessusClientData_v2>")) || !bytes.Contains(s1, []byte("172.30.0.10")) || bytes.Contains(s1, []byte("172.30.0.11")) {
		t.Fatalf("PerIP(%s) wrong content:\n%s", ip1, s1)
	}
	reparsed, err := ParseNessus(s1)
	if err != nil || len(reparsed.Hosts) != 1 || reparsed.Hosts[0].IP != ip1 {
		t.Fatalf("re-parse PerIP(%s): err=%v hosts=%+v", ip1, err, reparsed)
	}
	if got := doc.PerIP(netip.MustParseAddr("172.30.0.99")); got != nil {
		t.Fatalf("PerIP(missing) = %q, want nil", got)
	}
}

func TestExportFormattersCSV(t *testing.T) {
	now := time.Date(2026, 11, 21, 15, 0, 0, 0, time.UTC)
	assetID := int64(42)
	ip := netip.MustParseAddr("172.30.0.10")
	date := "2026-11-21"

	t.Run("hosts csv", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteHostsCSV(&buf, []hosts.Host{{
			IP: ip, Hostnames: []string{"web.lab"}, State: "active",
			FirstSeen: now, LastSeen: now, DojoAssetID: &assetID,
			OpenServices: 2, OpenPorts: []int32{80, 443}, Technologies: []string{"nginx"},
			Owner: "agh", Criticality: "high", UserTags: []string{"prod"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil || len(recs) != 2 || recs[1][0] != "172.30.0.10" || recs[1][8] != "80;443" {
			t.Fatalf("hosts csv = %v err=%v", recs, err)
		}
	})

	t.Run("findings csv", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteFindingsCSV(&buf, []dojo.MirrorFinding{{
			ID: 7, AssetID: &assetID, IP: &ip, Title: "Open port: 80/tcp",
			Severity: "Info", Active: true, Tags: []string{"raven"}, Scanner: "nmap",
			Date: &date, DojoURL: "http://dojo/finding/7",
		}})
		if err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil || len(recs) != 2 || recs[1][3] != "Open port: 80/tcp" {
			t.Fatalf("findings csv = %v err=%v", recs, err)
		}
	})

	t.Run("changes csv", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteChangesCSV(&buf, &changes.Changes{
			From: changes.RunRef{ID: 1}, To: changes.RunRef{ID: 2},
			HostsNew: []changes.HostChange{{IP: ip, OtherRun: "not_scanned", Ports: []uint16{80}}},
			ServicesChanged: []changes.ServiceChange{{
				IP: ip, Port: 80, Proto: "tcp",
				Before: &changes.Fingerprint{Name: "http", Product: "nginx", Version: "1.22"},
				After:  &changes.Fingerprint{Name: "http", Product: "nginx", Version: "1.24"},
				Fields: []string{"version"},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil || len(recs) != 3 || recs[1][2] != "host_new" || recs[2][2] != "service_changed" || recs[2][8] != "version" {
			t.Fatalf("changes csv = %v err=%v", recs, err)
		}
	})
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		fn   func() error
	}{
		{"empty json", func() error { _, err := ParseResultsJSON(nil); return err }},
		{"bad json", func() error { _, err := ParseResultsJSON([]byte("{nope")); return err }},
		{"unsupported version", func() error {
			_, err := ParseResultsJSON([]byte(`{"version":99,"hosts":[{"ip":"10.0.0.1"}]}`))
			return err
		}},
		{"no hosts json", func() error { _, err := ParseResultsJSON([]byte(`{"version":1,"hosts":[]}`)); return err }},
		{"bad ip json", func() error { _, err := ParseResultsJSON([]byte(`{"hosts":[{"ip":"not-an-ip"}]}`)); return err }},
		{"bad port json", func() error {
			_, err := ParseResultsJSON([]byte(`{"hosts":[{"ip":"10.0.0.1","services":[{"port":0}]}]}`))
			return err
		}},
		{"csv missing ip column", func() error { _, err := ParseResultsCSV(strings.NewReader("host,port\n10.0.0.1,80\n")); return err }},
		{"bad nessus root", func() error { _, err := ParseNessus([]byte(`<nmaprun/>`)); return err }},
		{"empty nessus", func() error {
			_, err := ParseNessus([]byte(`<NessusClientData_v2><Report name="r"/></NessusClientData_v2>`))
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestDetectImportKind(t *testing.T) {
	cases := []struct {
		name string
		data string
		want ImportKind
	}{
		{"a.json", `{"hosts":[]}`, ImportResultsJSON},
		{"a.csv", `ip,port`, ImportResultsCSV},
		{"a.xml", `<nmaprun/>`, ImportNmapXML},
		{"a.nessus", `<NessusClientData_v2/>`, ImportNessus},
		{"a.jsonl", `{"template-id":"x"}`, ImportNucleiJSONL},
		{"noext", `{"template-id":"x","info":{}}`, ImportNucleiJSONL},
		{"noext", `{"hosts":[]}`, ImportResultsJSON},
		{"noext", `ip,port`, ImportResultsCSV},
	}
	for _, tc := range cases {
		if got := DetectImportKind(tc.name, []byte(tc.data)); got != tc.want {
			t.Errorf("DetectImportKind(%q, %q) = %q, want %q", tc.name, tc.data, got, tc.want)
		}
	}
	// Verify JSON marshaling of ExportServiceRow doesn't panic.
	if _, err := json.Marshal(ExportServiceRow{IP: netip.MustParseAddr("10.0.0.1"), Port: 80, Proto: "tcp"}); err != nil {
		t.Fatal(err)
	}
}
