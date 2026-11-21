package nmap

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

var testIPs = []netip.Addr{
	netip.MustParseAddr("172.31.250.10"),
	netip.MustParseAddr("172.31.250.11"),
}

func TestBuildArgsExact(t *testing.T) {
	got, err := BuildArgs(testIPs, scanner.Options{Ports: "22,80,443,8080", MaxRate: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "-sS -sV -PE -PP -PS21,22,23,25,80,443,445,3389,8080 -PA80,443 -p 22,80,443,8080 " +
		"--script http-title,http-headers,ssl-cert,banner --max-rate 100 -T3 --max-retries 2 " +
		"--host-timeout 15m --script-timeout 30s -n -v --reason -oX - 172.31.250.10 172.31.250.11"
	if s := strings.Join(got, " "); s != want {
		t.Fatalf("args:\n got %s\nwant %s", s, want)
	}
}

func TestBuildArgsOptions(t *testing.T) {
	ok := scanner.Options{Ports: "1-1024,8080", MaxRate: 500}
	tests := []struct {
		name    string
		ips     []netip.Addr
		opt     scanner.Options
		extra   []string
		wantErr string // "" = must succeed
	}{
		{name: "defaults", opt: ok},
		{name: "extra timing T4", opt: ok, extra: []string{"-T4"}, wantErr: `"-T" given twice`},
		{name: "extra version intensity", opt: ok, extra: []string{"--version-intensity", "5"}},
		{name: "extra version intensity eq form", opt: ok, extra: []string{"--version-intensity=2"}},
		{name: "max-rate zero", opt: scanner.Options{Ports: "80", MaxRate: 0}, wantErr: "--max-rate must be > 0"},
		{name: "max-rate negative", opt: scanner.Options{Ports: "80", MaxRate: -5}, wantErr: "--max-rate must be > 0"},
		{name: "no ports", opt: scanner.Options{MaxRate: 10}, wantErr: "port list is empty"},
		{name: "no targets", ips: []netip.Addr{}, opt: ok, wantErr: "no targets"},
		{name: "invalid target", ips: []netip.Addr{{}}, opt: ok, wantErr: "invalid target"},
		{name: "ipv6 target", ips: []netip.Addr{netip.MustParseAddr("fd00::1")}, opt: ok, wantErr: "IPv6"},
		{name: "4in6 target is unmapped", ips: []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1")}, opt: ok},
		// intrusive or unknown flags
		{name: "-A", opt: ok, extra: []string{"-A"}, wantErr: `"-A" is not allowed`},
		{name: "-sC", opt: ok, extra: []string{"-sC"}, wantErr: `"-sC" is not allowed`},
		{name: "-O", opt: ok, extra: []string{"-O"}, wantErr: `"-O" is not allowed`},
		{name: "-sU", opt: ok, extra: []string{"-sU"}, wantErr: "not allowed"},
		{name: "-Pn", opt: ok, extra: []string{"-Pn"}, wantErr: "not allowed"},
		{name: "-T5", opt: ok, extra: []string{"-T5"}, wantErr: "not allowed"},
		{name: "-iL", opt: ok, extra: []string{"-iL", "/etc/passwd"}, wantErr: "not allowed"},
		{name: "-oN", opt: ok, extra: []string{"-oN", "/tmp/x"}, wantErr: "not allowed"},
		{name: "--script-args", opt: ok, extra: []string{"--script-args", "x=1"}, wantErr: "not allowed"},
		{name: "--datadir", opt: ok, extra: []string{"--datadir=/tmp"}, wantErr: "not allowed"},
		{name: "--min-rate", opt: ok, extra: []string{"--min-rate", "100000"}, wantErr: "not allowed"},
		{name: "script given again", opt: ok, extra: []string{"--script=banner"}, wantErr: "given twice"},
		{name: "ports given again", opt: ok, extra: []string{"-p", "1-65535"}, wantErr: "given twice"},
		{name: "max-rate given again", opt: ok, extra: []string{"--max-rate=100000"}, wantErr: "given twice"},
		{name: "glued -p", opt: ok, extra: []string{"-p1-65535"}, wantErr: "not allowed"},
		{name: "version intensity out of range", opt: ok, extra: []string{"--version-intensity", "10"}, wantErr: "integer in [0, 9]"},
		{name: "dangling value flag", opt: ok, extra: []string{"--host-timeout"}, wantErr: "given twice"},
		{name: "target-like extra", opt: ok, extra: []string{"8.8.8.8"}, wantErr: "not allowed"},
		// port spec injection attempts
		{name: "ports with semicolon", opt: scanner.Options{Ports: "80;rm -rf /", MaxRate: 1}, wantErr: "digits, commas and ranges"},
		{name: "ports with space", opt: scanner.Options{Ports: "80 --script=vuln", MaxRate: 1}, wantErr: "digits, commas and ranges"},
		{name: "ports dash only", opt: scanner.Options{Ports: "-", MaxRate: 1}, wantErr: "digits, commas and ranges"},
		{name: "ports open range", opt: scanner.Options{Ports: "1-", MaxRate: 1}, wantErr: "digits, commas and ranges"},
		{name: "ports protocol prefix", opt: scanner.Options{Ports: "T:80", MaxRate: 1}, wantErr: "digits, commas and ranges"},
		{name: "ports by name", opt: scanner.Options{Ports: "http", MaxRate: 1}, wantErr: "digits, commas and ranges"},
		{name: "port zero", opt: scanner.Options{Ports: "0-80", MaxRate: 1}, wantErr: "out of range"},
		{name: "port too big", opt: scanner.Options{Ports: "65536", MaxRate: 1}, wantErr: "out of range"},
		{name: "reversed range", opt: scanner.Options{Ports: "443-80", MaxRate: 1}, wantErr: "reversed"},
		{name: "full range ok", opt: scanner.Options{Ports: "1-65535", MaxRate: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := tt.ips
			if ips == nil {
				ips = testIPs
			}
			args, err := BuildArgs(ips, tt.opt, tt.extra)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !slices.Contains(args, "--max-rate") {
					t.Fatalf("--max-rate missing: %v", args)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateArgs(t *testing.T) {
	tests := []struct {
		args    []string
		wantErr bool
	}{
		{[]string{"-sS", "-sV", "-p", "80", "--max-rate", "10", "-oX", "-"}, false},
		{[]string{"--script=http-title,banner"}, false},
		{[]string{"--script", "ssl-cert"}, false},
		{[]string{"-PS22,80", "-PA443"}, false},
		{[]string{"--script=vuln"}, true},
		{[]string{"--script=default"}, true},
		{[]string{"--script=+banner"}, true},
		{[]string{"--script", "http-title,http-brute"}, true},
		{[]string{"--script", "banner,"}, true},
		{[]string{"-PS"}, true},
		{[]string{"-PSfoo"}, true},
		{[]string{"-PS22;id"}, true},
		{[]string{"-oX", "/etc/cron.d/x"}, true},
		{[]string{"-sV=1"}, true},
		{[]string{"-n=1"}, true},
		{[]string{"--reason=x"}, true},
		{[]string{"--max-rate", "0"}, true},
		{[]string{"--max-rate", "+5"}, true},
		{[]string{"--max-rate", "05"}, true},
		{[]string{"--host-timeout", "15m;id"}, true},
		{[]string{"--max-retries", "11"}, true},
		{[]string{"-p"}, true},
		{[]string{""}, true},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			err := validateArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateArgs(%q) = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}
