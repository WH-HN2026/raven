//go:build integration

package nmap

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

// TestRunLab runs real nmap against the IPs in RAVEN_NMAP_IT_TARGETS
// (comma-separated). It needs nmap and raw-socket rights, so it is skipped
// unless the variable is set. Only point it at a lab network you own; see
// testdata/README.md for how it was run against an isolated docker network.
func TestRunLab(t *testing.T) {
	env := os.Getenv("RAVEN_NMAP_IT_TARGETS")
	if env == "" {
		t.Skip("RAVEN_NMAP_IT_TARGETS not set")
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not in PATH")
	}
	var ips []netip.Addr
	for s := range strings.SplitSeq(env, ",") {
		ips = append(ips, netip.MustParseAddr(strings.TrimSpace(s)))
	}
	opt := scanner.Options{Ports: "22,80,443", MaxRate: 100}
	args, _ := BuildArgs(ips, opt, nil)
	t.Logf("nmap %s", strings.Join(args, " "))

	s := New(Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := s.Run(ctx, scanner.Input{IPs: ips}, opt)
	if err != nil {
		t.Fatal(err)
	}
	up := 0
	for _, o := range res.Observations {
		title := ""
		if o.HTTP != nil {
			title = o.HTTP.Title
		}
		t.Logf("%-7s %-15s up=%-5v %d/%s %s %q %q %s %q", o.Kind, o.IP, o.Up, o.Port, o.Proto, o.Service, o.Product, o.Version, o.URL, title)
		if o.Kind == scanner.ObsHost && o.Up {
			up++
			if res.PerIP(o.IP) == nil {
				t.Errorf("PerIP(%s) = nil", o.IP)
			}
		}
	}
	if up == 0 {
		t.Fatal("no host up")
	}
}

// TestRunCancel checks that cancelling ctx kills nmap and Run reports it.
func TestRunCancel(t *testing.T) {
	env := os.Getenv("RAVEN_NMAP_IT_TARGETS")
	if env == "" {
		t.Skip("RAVEN_NMAP_IT_TARGETS not set")
	}
	ip := netip.MustParseAddr(strings.TrimSpace(strings.Split(env, ",")[0]))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := New(Config{}).Run(ctx, scanner.Input{IPs: []netip.Addr{ip}}, scanner.Options{Ports: "1-65535", MaxRate: 10})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Run took %v after cancel", d)
	}
}
