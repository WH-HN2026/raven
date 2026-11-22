package dojo

import (
	"context"
	"testing"
	"time"
)

// TestTriggerCoalesces: many Fire calls during a pass → exactly one extra pass.
func TestTriggerCoalesces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tr Trigger
	release := make(chan struct{})
	passes := make(chan bool, 10)
	go loop(ctx, time.Hour, &tr, func(triggered bool) {
		passes <- triggered
		if !triggered {
			<-release // hold the first pass while the triggers arrive
		}
	})
	if got := <-passes; got {
		t.Fatal("first pass marked triggered")
	}
	for range 100 {
		tr.Fire() // never blocks
	}
	close(release)
	select {
	case got := <-passes:
		if !got {
			t.Fatal("second pass not marked triggered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no pass after Fire")
	}
	select {
	case <-passes:
		t.Fatal("100 triggers caused more than one extra pass")
	case <-time.After(200 * time.Millisecond):
	}
	// A later trigger is a new pass again.
	tr.Fire()
	select {
	case <-passes:
	case <-time.After(5 * time.Second):
		t.Fatal("no pass after the second Fire")
	}
}

// TestTriggerBeforeLoop: Fire on a zero Trigger before any loop runs neither
// blocks nor panics, and the loop then makes one triggered pass.
func TestTriggerBeforeLoop(t *testing.T) {
	var s Syncer
	s.Trigger()
	s.Trigger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	passes := make(chan bool, 10)
	go loop(ctx, time.Hour, &s.kick, func(triggered bool) { passes <- triggered })
	if <-passes {
		t.Fatal("first pass marked triggered")
	}
	if !<-passes {
		t.Fatal("queued trigger not seen")
	}
	select {
	case <-passes:
		t.Fatal("two early triggers caused two extra passes")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestOnRunPushedUnset: before main wires the hook (Dojo bootstrap not done),
// a push's run-end check is a no-op; it must not touch the (nil) pool/river.
func TestOnRunPushedUnset(t *testing.T) {
	var s PushService
	s.afterPush(context.Background(), 1) // would panic on nil pool if it checked
}
