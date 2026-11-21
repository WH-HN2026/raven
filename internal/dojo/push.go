package dojo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Push (architecture §3.6–3.7, §4): per responding IP, the chain
// Asset "<ip>" → Engagement "ASI: <profile>" → Test per scanner, a reimport of
// the scanner output filtered to that IP, and on the first push of an IP an
// INFO "New device found" finding in the "ASI lifecycle" test.

const (
	TagASI = "asi" // on every asset/engagement/test/finding we push; D3 syncs findings tagged with it

	GenericScanType    = "Generic Findings Import"
	LifecycleTestTitle = "ASI lifecycle"
)

// EngagementName is the long-lived engagement of one (IP, profile).
func EngagementName(profile string) string { return "ASI: " + profile }

// TestTitle is the test of one (IP, profile, scanner) inside the engagement.
func TestTitle(scanner string) string { return "ASI: " + scanner }

// NewDeviceUID is the stable unique_id_from_tool of the "New device found" finding.
func NewDeviceUID(ip netip.Addr) string { return "asi-new-device:" + ip.String() }

// PushHost is one responding IP of a batch, as our DB knows it after ingest.
type PushHost struct {
	IP        netip.Addr
	Hostnames []string
	FirstSeen time.Time
	OpenPorts []string // "22/tcp", for the new-device description
	AssetID   int64    // hosts.dojo_asset_id before this push; 0 = never pushed → new device
	Report    []byte   // scanner output filtered to this IP (Result.PerIP)
}

// PushBatch is what one push job sends to Dojo.
type PushBatch struct {
	RunID, BatchID int64
	Profile        string // profile name
	Scanner        string // "nmap"
	ScanType       string // Dojo parser, "Nmap Scan"
	ScanDate       time.Time
	Hosts          []PushHost
}

// HostResult is the outcome for one IP.
type HostResult struct {
	IP        netip.Addr
	AssetID   int64
	NewDevice bool // the new-device finding was (re)imported
	Err       error
}

// Pusher pushes batches to Dojo; IPs are processed in parallel, at most
// Parallel at a time (the client's own request limit bounds it anyway).
type Pusher struct {
	Client         Client
	OrganizationID int64
	Parallel       int // 0 = 4
}

// Push pushes every host of b and returns one result per host, in order.
// It never returns early: a failed IP doesn't stop the others.
func (p *Pusher) Push(ctx context.Context, b PushBatch) []HostResult {
	n := p.Parallel
	if n <= 0 {
		n = 4
	}
	out := make([]HostResult, len(b.Hosts))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i := range b.Hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			h := b.Hosts[i]
			id, nd, err := p.pushHost(ctx, b, h)
			if err != nil {
				err = fmt.Errorf("dojo push %s (run %d batch %d): %w", h.IP, b.RunID, b.BatchID, err)
			}
			out[i] = HostResult{IP: h.IP, AssetID: id, NewDevice: nd, Err: err}
		}()
	}
	wg.Wait()
	return out
}

// AssetTags are the tags ASI puts on an IP's asset.
func AssetTags(hostnames []string) []string {
	tags := []string{TagASI}
	for _, h := range hostnames {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			tags = append(tags, "host:"+h)
		}
	}
	return tags
}

func (p *Pusher) pushHost(ctx context.Context, b PushBatch, h PushHost) (assetID int64, newDevice bool, err error) {
	if len(h.Report) == 0 {
		return 0, false, fmt.Errorf("no %s output for this IP", b.Scanner)
	}
	tags := AssetTags(h.Hostnames)
	asset, err := p.Client.GetOrCreateAsset(ctx, AssetSpec{
		Name: h.IP.String(), Description: "Host " + h.IP.String() + " (managed by ASI)",
		OrganizationID: p.OrganizationID, Tags: tags,
	})
	if err != nil {
		return 0, false, err
	}
	if missing := missingTags(asset.Tags, tags); len(missing) > 0 {
		// Keep whatever is there (user tags), add ours.
		if err := p.Client.SetAssetTags(ctx, asset.ID, append(append([]string{}, asset.Tags...), missing...)); err != nil {
			return 0, false, err
		}
	}
	eng, err := p.Client.GetOrCreateEngagement(ctx, EngagementSpec{
		AssetID: asset.ID, Name: EngagementName(b.Profile), Tags: []string{TagASI},
	})
	if err != nil {
		return 0, false, err
	}
	test, err := p.Client.GetOrCreateTest(ctx, TestSpec{
		EngagementID: eng.ID, ScanType: b.ScanType, Title: TestTitle(b.Scanner),
	})
	if err != nil {
		return 0, false, err
	}
	// Only responding IPs get here, so close_old_findings is safe (§3.7).
	if _, err := p.Client.ReimportScan(ctx, ImportRequest{
		ScanType: b.ScanType, TestID: test.ID,
		FileName: h.IP.String() + "." + b.Scanner + ".xml", File: bytes.NewReader(h.Report),
		CloseOldFindings: true, Tags: []string{TagASI}, TagFindings: true, ScanDate: b.ScanDate,
	}); err != nil {
		return 0, false, err
	}
	if h.AssetID != 0 {
		return asset.ID, false, nil
	}
	if err := p.pushNewDevice(ctx, eng.ID, b, h); err != nil {
		return 0, false, err
	}
	return asset.ID, true, nil
}

// pushNewDevice reimports the one "New device found" finding into the
// lifecycle test. close_old_findings=false keeps the test's other lifecycle
// findings (D4), and Dojo matches the finding by unique_id_from_tool
// (DD_DEDUPLICATION_ALGORITHM_PER_PARSER in deploy/dojo.compose.yml), so a
// retried push leaves it untouched instead of adding a second one.
func (p *Pusher) pushNewDevice(ctx context.Context, engagementID int64, b PushBatch, h PushHost) error {
	test, err := p.Client.GetOrCreateTest(ctx, TestSpec{
		EngagementID: engagementID, ScanType: GenericScanType, Title: LifecycleTestTitle,
	})
	if err != nil {
		return err
	}
	doc, err := NewDeviceReport(h)
	if err != nil {
		return err
	}
	_, err = p.Client.ReimportScan(ctx, ImportRequest{
		ScanType: GenericScanType, TestID: test.ID,
		FileName: "asi-new-device.json", File: bytes.NewReader(doc),
		CloseOldFindings: false, Tags: []string{TagASI}, TagFindings: true, ScanDate: b.ScanDate,
	})
	return err
}

type genericFinding struct {
	Title           string `json:"title"`
	Description     string `json:"description"`
	Severity        string `json:"severity"`
	Date            string `json:"date"`
	UniqueIDForTool string `json:"unique_id_from_tool"`
	Active          bool   `json:"active"`
	Verified        bool   `json:"verified"`
	StaticFinding   bool   `json:"static_finding"`
	DynamicFinding  bool   `json:"dynamic_finding"`
}

// NewDeviceReport is the Generic Findings Import JSON with the one INFO finding.
func NewDeviceReport(h PushHost) ([]byte, error) {
	names, ports := "none known", "none"
	if len(h.Hostnames) > 0 {
		names = strings.Join(h.Hostnames, ", ")
	}
	if len(h.OpenPorts) > 0 {
		ps := append([]string{}, h.OpenPorts...)
		portNum := func(s string) int { n, _ := strconv.Atoi(strings.SplitN(s, "/", 2)[0]); return n }
		sort.SliceStable(ps, func(i, j int) bool { return portNum(ps[i]) < portNum(ps[j]) })
		ports = strings.Join(ps, ", ")
	}
	desc := fmt.Sprintf("ASI saw %s for the first time.\n\n**First seen:** %s\n**Hostnames:** %s\n**Open ports:** %s\n",
		h.IP, h.FirstSeen.UTC().Format(time.RFC3339), names, ports)
	return json.Marshal(map[string]any{"findings": []genericFinding{{
		Title: "New device found: " + h.IP.String(), Description: desc, Severity: "Info",
		Date: h.FirstSeen.UTC().Format(time.DateOnly), UniqueIDForTool: NewDeviceUID(h.IP),
		Active: true, DynamicFinding: true,
	}}})
}

func missingTags(have, want []string) []string {
	set := make(map[string]bool, len(have))
	for _, t := range have {
		set[strings.ToLower(t)] = true
	}
	var out []string
	for _, t := range want {
		if !set[strings.ToLower(t)] {
			out = append(out, t)
		}
	}
	return out
}
