// Package nmap is the nmap implementation of scanner.Scanner (architecture
// §3.3, §7, §9).
//
// One nmap process per batch does both phases of §3.3:
//
//  1. host discovery (what "-sn" alone would do): ICMP echo/timestamp and TCP
//     SYN/ACK pings, or ARP on a local segment. We don't pass -Pn, so nmap
//     only port-scans hosts that answered, and with -v it also writes the
//     down hosts into the XML;
//  2. "-sS -sV" on the profile's ports with the safe scripts
//     http-title, http-headers, ssl-cert and banner.
//
// So a single invocation yields host up/down plus services, which is all
// the ingest needs. The command line comes only from the allowlist in
// args.go; see BuildArgs for the exact flags and why each is there.
package nmap

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

// Config configures the nmap scanner. The zero value is ready to use.
type Config struct {
	Binary string   // path to nmap; "" means "nmap" from PATH
	Extra  []string // extra allowlisted flags (e.g. "-T4"); validated by BuildArgs
}

type Scanner struct{ cfg Config }

// New returns the nmap scanner.
func New(cfg Config) *Scanner {
	if cfg.Binary == "" {
		cfg.Binary = "nmap"
	}
	return &Scanner{cfg: cfg}
}

var _ scanner.Scanner = (*Scanner)(nil)

func (*Scanner) Name() string         { return "nmap" }
func (*Scanner) DojoScanType() string { return "Nmap Scan" }

// Run scans one batch. Cancelling ctx kills nmap (time windows rely on it);
// the partial output is then discarded and ctx's error is returned.
func (s *Scanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	args, err := BuildArgs(in.IPs, opt, s.cfg.Extra)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.cfg.Binary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("nmap run: %w", ctx.Err())
		}
		return nil, fmt.Errorf("nmap run: %w: %s", err, lastLine(stderr.String()))
	}
	return Parse(stdout.Bytes())
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
