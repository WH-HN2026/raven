package dojo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

type offlineArgs struct {
	RunID int64 `json:"run_id"`
}

func (offlineArgs) Kind() string { return "dojo_host_offline" }

func (offlineArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: PushQueue, MaxAttempts: pushMaxAttempts}
}

func (s *PushService) AfterRunFinished(ctx context.Context, tx pgx.Tx, runID int64) error {
	_, err := s.river.InsertTx(ctx, tx, offlineArgs{RunID: runID}, nil)
	return err
}

type offlineWorker struct {
	river.WorkerDefaults[offlineArgs]
	s *PushService
}

func (w *offlineWorker) Work(ctx context.Context, job *river.Job[offlineArgs]) error {
	p := w.s.pusher.Load()
	if p == nil {
		return river.JobSnooze(pushNotReadyWait)
	}
	err := w.s.pushOfflineRun(ctx, p, job.Args.RunID)
	if err == nil || job.Attempt >= job.MaxAttempts {
		w.s.afterPush(ctx, job.Args.RunID)
	}
	return err
}

func (s *PushService) pushOfflineRun(ctx context.Context, p *Pusher, runID int64) error {
	q := gen.New(s.pool)
	view, err := q.GetRunView(ctx, runID)
	if err != nil {
		return fmt.Errorf("read run %d: %w", runID, err)
	}
	run := view.Run
	if run.Status != "done" || run.FinishedAt == nil {
		return fmt.Errorf("run %d has not completed", runID)
	}
	var stats struct {
		InactiveIPs []netip.Addr `json:"inactive_ips"`
	}
	if err := json.Unmarshal(run.Stats, &stats); err != nil {
		return fmt.Errorf("read inactive IPs of run %d: %w", runID, err)
	}
	if len(stats.InactiveIPs) == 0 {
		return nil
	}
	profile, err := q.GetProfile(ctx, run.ProfileID)
	if err != nil {
		return fmt.Errorf("get profile %d: %w", run.ProfileID, err)
	}
	hosts, err := q.ListPushHosts(ctx, stats.InactiveIPs)
	if err != nil {
		return fmt.Errorf("list inactive hosts of run %d: %w", runID, err)
	}
	var failures []error
	for _, host := range hosts {
		h := PushHost{IP: host.Ip, Hostnames: host.Hostnames, tags: MergeAssetTags(nil, host.UserTags)}
		if err := p.pushOffline(ctx, profile.Name, *run.FinishedAt, h); err != nil {
			failures = append(failures, fmt.Errorf("push Host offline for %s (run %d): %w", h.IP, runID, err))
		}
	}
	return errors.Join(failures...)
}

func (p *Pusher) pushOffline(ctx context.Context, profile string, date time.Time, h PushHost) error {
	defer p.lockHost(h.IP)()
	asset, err := p.ensureAsset(ctx, h)
	if err != nil {
		return err
	}
	uid := "raven-host-offline:" + h.IP.String()
	// A host can transition under another profile after recovery. Check the
	// whole Asset so the other profile's Test cannot duplicate the finding.
	for off := 0; ; off += 100 {
		page, err := p.Client.ListFindings(ctx, FindingQuery{AssetID: asset.ID, UniqueIDFromTool: uid, Limit: 100, Offset: off})
		if err != nil {
			return err
		}
		for _, finding := range page.Results {
			if finding.UniqueIDFromTool == uid {
				return nil
			}
		}
		if page.Next == "" {
			break
		}
	}
	eng, err := p.Client.GetOrCreateEngagement(ctx, EngagementSpec{
		AssetID: asset.ID, Name: EngagementName(profile), Tags: []string{TagASI},
	})
	if err != nil {
		return err
	}
	doc, err := json.Marshal(map[string][]genericFinding{"findings": {{
		Title: "Host offline: " + h.IP.String(), Severity: "Info", UniqueIDForTool: uid,
		Description: fmt.Sprintf("%s reached the consecutive miss threshold for the %s profile.", h.IP, profile),
		Date:        date.UTC().Format(time.DateOnly), Active: true, DynamicFinding: true,
	}}})
	if err != nil {
		return err
	}
	return p.pushLifecycle(ctx, eng.ID, date, "raven-host-offline.json", doc)
}
