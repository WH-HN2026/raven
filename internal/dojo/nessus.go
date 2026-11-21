package dojo

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Tenable / Nessus push (architecture D6, task P3): .nessus reports are split
// per IP and reimported into the matching IP's Asset using DefectDojo's
// "Tenable Scan" parser, reusing the standard Asset → Engagement → Test chain.

const (
	TenableScanType = "Tenable Scan"
	NessusScanner   = "nessus"
)

// Pusher returns the active Dojo pusher, or nil if Dojo bootstrap hasn't finished.
func (s *PushService) Pusher() *Pusher {
	if s == nil {
		return nil
	}
	return s.pusher.Load()
}

// NessusHost is one IP's slice of a .nessus file.
type NessusHost struct {
	IP        netip.Addr
	Hostnames []string
	Report    []byte // valid NessusClientData_v2 XML for this IP only
}

// NessusBatch is a .nessus import ready to push to DefectDojo.
type NessusBatch struct {
	Profile  string // profile name → engagement "ASI: <profile>"
	ScanDate time.Time
	Hosts    []NessusHost
}

// NessusHostResult is the outcome of pushing one IP's .nessus report.
type NessusHostResult struct {
	IP           netip.Addr    `json:"ip"`
	AssetID      int64         `json:"asset_id"`
	EngagementID int64         `json:"engagement_id"`
	TestID       int64         `json:"test_id"`
	Import       *ImportResult `json:"-"`
	Created      int           `json:"created"`
	Active       int           `json:"active"`
	Total        int           `json:"total"`
	Err          error         `json:"-"`
	Error        string        `json:"error,omitempty"`
}

// PushNessus pushes each host's .nessus slice into its IP Asset in DefectDojo
// under Engagement "ASI: <profile>" and Test "ASI: nessus" ("Tenable Scan").
// Results are returned in the same order as b.Hosts; one IP failing does not
// stop the others.
func (p *Pusher) PushNessus(ctx context.Context, b NessusBatch) []NessusHostResult {
	n := p.Parallel
	if n <= 0 {
		n = 4
	}
	out := make([]NessusHostResult, len(b.Hosts))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i := range b.Hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			r := p.pushNessusHost(ctx, b, b.Hosts[i])
			if r.Err != nil {
				r.Err = fmt.Errorf("dojo nessus push %s: %w", b.Hosts[i].IP, r.Err)
				r.Error = r.Err.Error()
			}
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

func (p *Pusher) pushNessusHost(ctx context.Context, b NessusBatch, h NessusHost) NessusHostResult {
	res := NessusHostResult{IP: h.IP}
	if len(h.Report) == 0 {
		res.Err = fmt.Errorf("no nessus report for %s", h.IP)
		return res
	}
	tags := AssetTags(h.Hostnames)
	asset, err := p.Client.GetOrCreateAsset(ctx, AssetSpec{
		Name:           h.IP.String(),
		Description:    "Host " + h.IP.String() + " (managed by ASI)",
		OrganizationID: p.OrganizationID,
		Tags:           tags,
	})
	if err != nil {
		res.Err = err
		return res
	}
	res.AssetID = asset.ID
	if missing := missingTags(asset.Tags, tags); len(missing) > 0 {
		if err := p.Client.SetAssetTags(ctx, asset.ID, append(append([]string{}, asset.Tags...), missing...)); err != nil {
			res.Err = err
			return res
		}
	}
	eng, err := p.Client.GetOrCreateEngagement(ctx, EngagementSpec{
		AssetID: asset.ID,
		Name:    EngagementName(b.Profile),
		Tags:    []string{TagASI},
	})
	if err != nil {
		res.Err = err
		return res
	}
	res.EngagementID = eng.ID
	test, err := p.Client.GetOrCreateTest(ctx, TestSpec{
		EngagementID: eng.ID,
		ScanType:     TenableScanType,
		Title:        TestTitle(NessusScanner),
	})
	if err != nil {
		res.Err = err
		return res
	}
	res.TestID = test.ID
	imp, err := p.Client.ReimportScan(ctx, ImportRequest{
		ScanType:         TenableScanType,
		TestID:           test.ID,
		FileName:         h.IP.String() + ".nessus",
		File:             bytes.NewReader(h.Report),
		CloseOldFindings: true,
		Tags:             []string{TagASI},
		TagFindings:      true,
		ScanDate:         b.ScanDate,
	})
	if err != nil {
		res.Err = err
		return res
	}
	res.Import = imp
	res.Created = imp.Created
	res.Active = imp.Active
	res.Total = imp.Total
	return res
}
