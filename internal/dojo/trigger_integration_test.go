//go:build integration

package dojo

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/WH-HN2026/raven/internal/cve"
	"github.com/WH-HN2026/raven/internal/db/gen"
	"github.com/WH-HN2026/raven/internal/dbtest"
	"github.com/WH-HN2026/raven/internal/pipeline"
	"github.com/WH-HN2026/raven/internal/scanner/nmap"
)

// TestRunPushedTrigger (D7): only the final outcome of a run's last push job
// fires OnRunPushed, once; earlier pushes, unfinished runs and retried
// failures don't.
func TestRunPushedTrigger(t *testing.T) {
	pool := dbtest.Fresh(t)
	ctx := context.Background()
	q := gen.New(pool)
	var profileID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM profiles WHERE name = 'Default'`).Scan(&profileID); err != nil {
		t.Fatal(err)
	}
	nmapRaw := fixture(t, "nmap/testdata/lab.xml")
	now := time.Now().UTC()
	run, err := q.InsertRun(ctx, gen.InsertRunParams{
		ProfileID: profileID, Status: "running", StartedAt: &now,
		HostsTotal: 2, Stats: []byte("{}"), Stages: []string{pipeline.StageNmap},
	})
	must(t, err)
	args := func(seq int32) PushArgs {
		t.Helper()
		b, err := q.InsertBatch(ctx, gen.InsertBatchParams{RunID: run.ID, Seq: seq, Ips: []netip.Addr{ipWeb}})
		must(t, err)
		must(t, q.InsertArtifact(ctx, gen.InsertArtifactParams{RunID: run.ID, BatchID: &b, Scanner: "nmap", Content: string(nmapRaw)}))
		return PushArgs{RunID: run.ID, BatchID: b, ProfileID: profileID, Stages: []string{pipeline.StageNmap},
			Scanner: "nmap", ScanType: "Nmap Scan", IPs: []netip.Addr{ipWeb}, ScanDate: now}
	}
	a1, a2 := args(1), args(2)

	svc, err := NewPushService(pool, map[string]ParseFunc{"nmap": nmap.Parse}) // not started: inserted jobs stay available
	must(t, err)
	svc.SetPusher(&Pusher{Client: newFake(), OrganizationID: 1})
	w := &pushWorker{s: svc}
	work := func(a PushArgs, attempt int) error {
		return w.Work(ctx, &river.Job[PushArgs]{JobRow: &rivertype.JobRow{Attempt: attempt, MaxAttempts: pushMaxAttempts}, Args: a})
	}
	var fired atomic.Int32
	expect := func(step string, want int32) {
		t.Helper()
		if got := fired.Load(); got != want {
			t.Fatalf("%s: OnRunPushed fired %d times, want %d", step, got, want)
		}
	}

	setStatus := func(status string) {
		t.Helper()
		fin := time.Now()
		must(t, q.FinishRun(ctx, gen.FinishRunParams{ID: run.ID, Status: status, FinishedAt: &fin, Stats: []byte("{}")}))
	}

	// Before the hook is wired (Dojo bootstrap not done): the last push of a
	// finished run is a no-op.
	setStatus("done")
	must(t, work(a1, 1))

	svc.OnRunPushed(func() { fired.Add(1) })

	// The run is still running: its pushes are not the last.
	setStatus("running")
	must(t, work(a1, 1))
	expect("run still running", 0)

	// Run done, but batch 2's push is still queued: batch 1's push is not the last.
	setStatus("done")
	ins, err := svc.river.Insert(ctx, a2, nil)
	must(t, err)
	must(t, work(a1, 1))
	expect("another push queued", 0)

	// A retried failure (not the last attempt) doesn't count.
	bad := a2
	bad.ProfileID = -1
	if err := work(bad, 1); err == nil {
		t.Fatal("push with a missing profile succeeded")
	}
	expect("non-final failure", 0)

	// Batch 2's push is the last: fires exactly once.
	_, err = svc.river.JobDelete(ctx, ins.Job.ID) // River would have taken it off the waiting states
	must(t, err)
	must(t, work(a2, 1))
	expect("last push", 1)

	// The final failed attempt of a push is a final outcome too.
	if err := work(bad, pushMaxAttempts); err == nil {
		t.Fatal("push with a missing profile succeeded")
	}
	expect("final failed attempt", 2)
}

// TestCVESyncTriggersSyncer (D7): a triggered CVE pass triggers the mirror
// sync after it; a periodic pass doesn't.
func TestCVESyncTriggersSyncer(t *testing.T) {
	pool := dbtest.Fresh(t)
	m, err := cve.Default()
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncer := &Syncer{}
	cs := &CVESync{Pool: pool, Matcher: m, Next: syncer}
	go cs.Run(ctx, time.Hour)

	time.Sleep(time.Second) // the first (untriggered) pass on an empty DB
	if n := len(syncer.kick.ch()); n != 0 {
		t.Fatalf("untriggered CVE pass triggered the mirror sync (%d)", n)
	}
	for range 10 {
		cs.Trigger()
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(syncer.kick.ch()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("triggered CVE pass did not trigger the mirror sync")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
