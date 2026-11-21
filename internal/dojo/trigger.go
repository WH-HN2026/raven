package dojo

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/WH-HN2026/raven/internal/db/gen"
)

// Trigger is a coalescing wake-up for a periodic loop (D7): any number of
// Fire calls before the loop takes it cause one extra pass. The zero value is
// ready to use.
type Trigger struct {
	once sync.Once
	c    chan struct{}
}

func (t *Trigger) ch() chan struct{} {
	t.once.Do(func() { t.c = make(chan struct{}, 1) })
	return t.c
}

// Fire requests one extra pass; it never blocks.
func (t *Trigger) Fire() {
	select {
	case t.ch() <- struct{}{}:
	default:
	}
}

// loop calls pass now, then on every tick (triggered=false) and every fired
// trigger (triggered=true), until ctx ends.
func loop(ctx context.Context, interval time.Duration, t *Trigger, pass func(triggered bool)) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	triggered := false
	for {
		pass(triggered)
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			triggered = false
		case <-t.ch():
			triggered = true
		}
	}
}

// OnRunPushed sets f to be called after a run's last Dojo push job (main
// passes CVESync.Trigger). Until it is set, run ends trigger nothing.
func (s *PushService) OnRunPushed(f func()) { s.onRunPushed.Store(&f) }

// afterPush is called when a push job of runID reached its final outcome
// (success or last attempt). It calls the OnRunPushed func when that was the
// run's last push.
func (s *PushService) afterPush(ctx context.Context, runID int64) {
	f := s.onRunPushed.Load()
	if f == nil {
		return
	}
	last, err := s.lastPush(ctx, runID)
	if err != nil {
		slog.Warn("dojo push: check run end", "run", runID, "err", err)
		return
	}
	if last {
		slog.Info("dojo push of run done, triggering sync", "run", runID)
		(*f)()
	}
}

// pushWaiting are the states of a push job that has not started yet. Running
// jobs are deliberately not counted: River marks a job completed
// asynchronously, so two jobs finishing together would each still see the
// other as running and neither would fire. This way both fire, and the
// Trigger coalesces them.
var pushWaiting = []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending,
	rivertype.JobStateRetryable, rivertype.JobStateScheduled,
}

// lastPush: the run is finished and none of its push jobs (batch pushes, the
// host-offline push) is still waiting. The run's last batch enqueues its push
// only after committing the run's end, so that push always sees it finished.
func (s *PushService) lastPush(ctx context.Context, runID int64) (bool, error) {
	view, err := gen.New(s.pool).GetRunView(ctx, runID)
	if err != nil {
		return false, err
	}
	switch view.Run.Status {
	case "done", "failed", "stopped":
	default:
		return false, nil
	}
	res, err := s.river.JobList(ctx, river.NewJobListParams().
		Kinds(PushArgs{}.Kind(), offlineArgs{}.Kind()).
		States(pushWaiting...).
		Where("args->>'run_id' = @run_id", river.NamedArgs{"run_id": strconv.FormatInt(runID, 10)}).
		First(1))
	if err != nil {
		return false, err
	}
	return len(res.Jobs) == 0, nil
}
