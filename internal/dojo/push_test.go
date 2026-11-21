package dojo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/pipeline"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner/nmap"
)

// fakeClient records the push calls; methods the push doesn't use panic via
// the nil embedded interface.
type fakeClient struct {
	Client
	mu        sync.Mutex
	assets    map[string]*Asset // by name
	engs      map[string]*Engagement
	tests     map[string]*Test
	reimports []recordedImport
	setTags   map[int64][]string
	failIP    string // ReimportScan fails for this asset's tests
	nextID    int64
}

type recordedImport struct {
	ImportRequest
	Body  string
	Asset string // asset name of the target test
}

func newFake() *fakeClient {
	return &fakeClient{assets: map[string]*Asset{}, engs: map[string]*Engagement{},
		tests: map[string]*Test{}, setTags: map[int64][]string{}}
}

func (f *fakeClient) id() int64 { f.nextID++; return f.nextID }

func (f *fakeClient) GetOrCreateAsset(_ context.Context, a AssetSpec) (*Asset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.assets[a.Name]; ok {
		return x, nil
	}
	x := &Asset{ID: f.id(), Name: a.Name, OrganizationID: a.OrganizationID, Tags: a.Tags}
	f.assets[a.Name] = x
	return x, nil
}

func (f *fakeClient) SetAssetTags(_ context.Context, id int64, tags []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setTags[id] = tags
	return nil
}

func (f *fakeClient) GetOrCreateEngagement(_ context.Context, e EngagementSpec) (*Engagement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := strings.Join([]string{itoa(e.AssetID), e.Name}, "/")
	if x, ok := f.engs[k]; ok {
		return x, nil
	}
	x := &Engagement{ID: f.id(), Name: e.Name, AssetID: e.AssetID, Tags: e.Tags}
	f.engs[k] = x
	return x, nil
}

func (f *fakeClient) GetOrCreateTest(_ context.Context, t TestSpec) (*Test, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := strings.Join([]string{itoa(t.EngagementID), t.ScanType, t.Title}, "/")
	if x, ok := f.tests[k]; ok {
		return x, nil
	}
	x := &Test{ID: f.id(), EngagementID: t.EngagementID, Title: t.Title, ScanType: t.ScanType}
	f.tests[k] = x
	return x, nil
}

func (f *fakeClient) assetOfTest(testID int64) string {
	for _, t := range f.tests {
		if t.ID != testID {
			continue
		}
		for _, e := range f.engs {
			if e.ID != t.EngagementID {
				continue
			}
			for _, a := range f.assets {
				if a.ID == e.AssetID {
					return a.Name
				}
			}
		}
	}
	return ""
}

func (f *fakeClient) ReimportScan(_ context.Context, r ImportRequest) (*ImportResult, error) {
	body, err := io.ReadAll(r.File)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	asset := f.assetOfTest(r.TestID)
	if asset == f.failIP {
		return nil, errors.New("dojo is down")
	}
	f.reimports = append(f.reimports, recordedImport{ImportRequest: r, Body: string(body), Asset: asset})
	return &ImportResult{TestID: r.TestID}, nil
}

func (f *fakeClient) importsOf(asset, scanType string) []recordedImport {
	var out []recordedImport
	for _, r := range f.reimports {
		if r.Asset == asset && r.ScanType == scanType {
			out = append(out, r)
		}
	}
	return out
}

func labResult(t *testing.T) *scanner.Result {
	t.Helper()
	raw, err := os.ReadFile("../scanner/nmap/testdata/lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := nmap.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

var (
	ipWeb  = netip.MustParseAddr("172.31.250.10")
	ipSSH  = netip.MustParseAddr("172.31.250.11")
	ipDown = netip.MustParseAddr("172.31.250.20")
)

func TestArgsFromBatchOnlyResponding(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	a := ArgsFromBatch(pipeline.BatchResult{
		RunID: 1, BatchID: 2, ProfileID: 3,
		Responding: []netip.Addr{ipWeb, ipSSH}, // ipDown was in the batch but didn't respond
		Scanner:    nmap.New(nmap.Config{}), Result: labResult(t),
	}, now)
	if !slices.Equal(a.IPs, []netip.Addr{ipWeb, ipSSH}) {
		t.Fatalf("IPs = %v, want only the responding ones", a.IPs)
	}
	if a.Scanner != "nmap" || a.ScanType != "Nmap Scan" || a.RunID != 1 || a.BatchID != 2 || a.ProfileID != 3 || !a.ScanDate.Equal(now) {
		t.Fatalf("args = %+v", a)
	}
	if a.InsertOpts().Queue != PushQueue {
		t.Fatalf("queue %q", a.InsertOpts().Queue)
	}
}

func TestPush(t *testing.T) {
	res := labResult(t)
	date := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	f := newFake()
	p := &Pusher{Client: f, OrganizationID: 7, Parallel: 2}
	batch := func(webAsset int64) PushBatch {
		return PushBatch{RunID: 1, BatchID: 2, Profile: "lab", Scanner: "nmap", ScanType: "Nmap Scan", ScanDate: date,
			Hosts: []PushHost{
				{IP: ipWeb, Hostnames: []string{"Web.Lab"}, FirstSeen: date, OpenPorts: []string{"443/tcp", "80/tcp"},
					AssetID: webAsset, Report: res.PerIP(ipWeb)},
				{IP: ipSSH, AssetID: 99, Report: res.PerIP(ipSSH)}, // pushed before: not a new device
			}}
	}

	out := p.Push(context.Background(), batch(0))
	for _, r := range out {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	if !out[0].NewDevice || out[1].NewDevice {
		t.Fatalf("new device flags = %v, %v; want true, false", out[0].NewDevice, out[1].NewDevice)
	}

	// Only the batch's hosts got assets (never the down one), named by IP, tagged.
	if len(f.assets) != 2 || f.assets[ipDown.String()] != nil {
		t.Fatalf("assets = %v", f.assets)
	}
	web := f.assets[ipWeb.String()]
	if web == nil || web.OrganizationID != 7 || !slices.Equal(web.Tags, []string{"asi", "host:web.lab"}) {
		t.Fatalf("web asset = %+v", web)
	}
	if out[0].AssetID != web.ID {
		t.Fatalf("result asset id %d, want %d", out[0].AssetID, web.ID)
	}
	for _, e := range f.engs {
		if e.Name != "ASI: lab" || !slices.Equal(e.Tags, []string{"asi"}) {
			t.Fatalf("engagement = %+v", e)
		}
	}
	titles := map[string]string{}
	for _, x := range f.tests {
		titles[x.Title] = x.ScanType
	}
	if titles["ASI: nmap"] != "Nmap Scan" || titles["ASI lifecycle"] != "Generic Findings Import" || len(f.tests) != 3 {
		t.Fatalf("tests = %v (want ASI: nmap per IP + one lifecycle)", titles)
	}

	// nmap reimport per IP: its own XML only, close_old_findings, tags on findings.
	for _, ip := range []netip.Addr{ipWeb, ipSSH} {
		rs := f.importsOf(ip.String(), "Nmap Scan")
		if len(rs) != 1 {
			t.Fatalf("%s: %d nmap reimports", ip, len(rs))
		}
		r := rs[0]
		if !r.CloseOldFindings || !r.TagFindings || !slices.Equal(r.Tags, []string{"asi"}) || !r.ScanDate.Equal(date) {
			t.Fatalf("%s: reimport = %+v", ip, r.ImportRequest)
		}
		if !strings.Contains(r.Body, `addr="`+ip.String()+`"`) || strings.Contains(r.Body, `addr="`+ipDown.String()+`"`) {
			t.Fatalf("%s: report is not filtered to the IP", ip)
		}
	}

	// New device: one Generic import, stable uid, Info, not closing old findings.
	nd := f.importsOf(ipWeb.String(), GenericScanType)
	if len(nd) != 1 || len(f.importsOf(ipSSH.String(), GenericScanType)) != 0 {
		t.Fatalf("new-device imports: web %d, ssh %d", len(nd), len(f.importsOf(ipSSH.String(), GenericScanType)))
	}
	if nd[0].CloseOldFindings || !nd[0].TagFindings || !slices.Equal(nd[0].Tags, []string{"asi"}) {
		t.Fatalf("new-device import = %+v", nd[0].ImportRequest)
	}
	var doc struct {
		Findings []genericFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(nd[0].Body), &doc); err != nil {
		t.Fatal(err)
	}
	g := doc.Findings[0]
	if len(doc.Findings) != 1 || g.Title != "New device found: 172.31.250.10" || g.Severity != "Info" ||
		g.UniqueIDForTool != "asi-new-device:172.31.250.10" ||
		!strings.Contains(g.Description, "80/tcp, 443/tcp") || !strings.Contains(g.Description, "Web.Lab") ||
		!strings.Contains(g.Description, "2026-11-21T10:00:00Z") {
		t.Fatalf("new-device finding = %+v", g)
	}

	// Second push: the host now has its asset id, so no second new-device import.
	out = p.Push(context.Background(), batch(out[0].AssetID))
	if out[0].Err != nil || out[0].NewDevice {
		t.Fatalf("second push = %+v", out[0])
	}
	if n := len(f.importsOf(ipWeb.String(), GenericScanType)); n != 1 {
		t.Fatalf("new-device imports after two pushes = %d, want 1", n)
	}
	if n := len(f.importsOf(ipWeb.String(), "Nmap Scan")); n != 2 {
		t.Fatalf("nmap reimports after two pushes = %d, want 2", n)
	}
}

func TestPushFailureIsPerIP(t *testing.T) {
	res := labResult(t)
	f := newFake()
	f.failIP = ipWeb.String()
	p := &Pusher{Client: f, OrganizationID: 1}
	out := p.Push(context.Background(), PushBatch{RunID: 5, BatchID: 6, Profile: "lab", Scanner: "nmap", ScanType: "Nmap Scan",
		Hosts: []PushHost{
			{IP: ipWeb, Report: res.PerIP(ipWeb)},
			{IP: ipSSH, Report: res.PerIP(ipSSH)},
			{IP: ipDown}, // no output for it: refused before any Dojo call
		}})
	if out[0].Err == nil || !strings.Contains(out[0].Err.Error(), "172.31.250.10 (run 5 batch 6)") {
		t.Fatalf("web err = %v", out[0].Err)
	}
	if out[1].Err != nil || out[1].AssetID == 0 {
		t.Fatalf("ssh = %+v", out[1])
	}
	if out[2].Err == nil || f.assets[ipDown.String()] != nil {
		t.Fatalf("down host: err %v, asset %v", out[2].Err, f.assets[ipDown.String()])
	}
}

func TestPushKeepsUserAssetTags(t *testing.T) {
	res := labResult(t)
	f := newFake()
	f.assets[ipWeb.String()] = &Asset{ID: 50, Name: ipWeb.String(), Tags: []string{"asi", "owner:it"}}
	p := &Pusher{Client: f}
	out := p.Push(context.Background(), PushBatch{Profile: "lab", Scanner: "nmap", ScanType: "Nmap Scan",
		Hosts: []PushHost{{IP: ipWeb, Hostnames: []string{"web.lab"}, AssetID: 50, Report: res.PerIP(ipWeb)}}})
	if out[0].Err != nil {
		t.Fatal(out[0].Err)
	}
	if got := f.setTags[50]; !slices.Equal(got, []string{"asi", "owner:it", "host:web.lab"}) {
		t.Fatalf("asset tags = %v", got)
	}
}
