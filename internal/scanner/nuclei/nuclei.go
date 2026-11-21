// Package nuclei runs reviewed fingerprinting templates against live web services.
package nuclei

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/WH-HN2026/zadanie-agh-asi/internal/scanner"
)

const (
	DefaultTemplates = "/opt/nuclei-templates"
	allowedTags      = "tech,panel,ssl,waf,favicon"
	excludedTags     = "intrusive,dos,fuzz,fuzzing,bruteforce,rce,sqli,xss,lfi,rfi,ssrf,xxe,deserialization,injection,traversal,cve,oast,default-login,credential"
)

type Scanner struct {
	Binary         string
	TemplatesDir   string
	CustomDir      string
	LoadSignatures func(context.Context) ([]string, error)
}

var _ scanner.Scanner = (*Scanner)(nil)

func (*Scanner) Name() string         { return "nuclei" }
func (*Scanner) DojoScanType() string { return "Nuclei Scan" }

// BuildArgs is the complete flag allowlist. The caller supplies only local
// copies of approved templates. Custom signatures run in a separate HTTP pass.
func BuildArgs(opt scanner.Options, protocol string, templates []string, custom bool) ([]string, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("nuclei: rate limit must be positive")
	}
	if protocol != "http" && (protocol != "ssl" || custom) {
		return nil, errors.New("nuclei: invalid template protocol")
	}
	if len(templates) == 0 {
		return nil, errors.New("nuclei: no eligible templates")
	}
	args := []string{
		"-silent", "-jsonl", "-omit-raw", "-omit-template",
		"-no-interactsh", "-disable-update-check", "-duc", "-auth=false",
		"-no-httpx", "-disable-redirects",
		"-rl", strconv.Itoa(opt.RateLimit),
		"-etags", excludedTags, "-exclude-type", "code,headless,javascript", "-type", protocol,
	}
	if !custom {
		tags := selectedTags(opt.Tags)
		if len(tags) == 0 {
			return nil, errors.New("nuclei: no eligible official tags")
		}
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	for _, path := range templates {
		args = append(args, "-t", path)
	}
	return args, nil
}

func selectedTags(configured []string) []string {
	var selected []string
	for tag := range strings.SplitSeq(allowedTags, ",") {
		if slices.Contains(configured, tag) {
			selected = append(selected, tag)
		}
	}
	return selected
}

// BuildInput selects the live, literal-IP origins confirmed by httpx. Nuclei
// 3.11 has no per-IP allow flag. Literal origins and disabled redirects keep
// the HTTP requests and TLS handshakes on the confirmed batch endpoints.
func BuildInput(ips []netip.Addr, web []scanner.Observation) scanner.Input {
	batch := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		batch[ip.Unmap()] = true
	}
	var in scanner.Input
	seenIPs, seenURLs := map[netip.Addr]bool{}, map[string]bool{}
	for _, o := range web {
		if o.Kind != scanner.ObsHTTP || o.HTTP == nil || o.HTTP.Status < 100 || o.HTTP.Status > 599 || !batch[o.IP.Unmap()] {
			continue
		}
		origin, port, ok := rootURL(o.URL)
		if !ok || port != o.Port || !literalAddress(origin.Hostname(), o.IP) || seenURLs[origin.String()] {
			continue
		}
		in.URLs = append(in.URLs, origin.String())
		seenURLs[origin.String()] = true
		if ip := o.IP.Unmap(); !seenIPs[ip] {
			in.IPs = append(in.IPs, ip)
			seenIPs[ip] = true
		}
	}
	return in
}

func literalAddress(host string, expected netip.Addr) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && ip.Unmap() == expected.Unmap()
}

func (s *Scanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("nuclei: rate limit must be positive")
	}
	scope := make(map[string]netip.Addr, len(in.URLs))
	var httpURLs, tlsURLs []string
	for _, raw := range in.URLs {
		u, _, ok := rootURL(raw)
		if !ok || !slices.ContainsFunc(in.IPs, func(ip netip.Addr) bool { return literalAddress(u.Hostname(), ip) }) {
			return nil, errors.New("nuclei: expected an HTTP(S) origin on a batch IP")
		}
		ip, _ := netip.ParseAddr(u.Hostname())
		if _, ok := scope[u.String()]; ok {
			continue
		}
		scope[u.String()] = ip.Unmap()
		httpURLs = append(httpURLs, u.String())
		if u.Scheme == "https" {
			tlsURLs = append(tlsURLs, u.String())
		}
	}
	if len(scope) == 0 {
		return Parse(nil)
	}

	dir, err := os.MkdirTemp("", "asi-nuclei-")
	if err != nil {
		return nil, fmt.Errorf("nuclei: create workspace: %w", err)
	}
	defer os.RemoveAll(dir)

	httpPaths, sslPaths, err := s.officialTemplates(dir, selectedTags(opt.Tags), len(tlsURLs) > 0)
	if err != nil {
		return nil, err
	}
	customPaths, err := s.customTemplates(ctx, dir, opt.Signatures)
	if err != nil {
		return nil, err
	}
	var raw []byte
	for _, pass := range []struct {
		protocol string
		paths    []string
		urls     []string
		custom   bool
	}{
		{protocol: "http", paths: httpPaths, urls: httpURLs},
		{protocol: "ssl", paths: sslPaths, urls: tlsURLs},
		{protocol: "http", paths: customPaths, urls: httpURLs, custom: true},
	} {
		if len(pass.paths) == 0 {
			continue
		}
		args, err := BuildArgs(opt, pass.protocol, pass.paths, pass.custom)
		if err != nil {
			return nil, err
		}
		out, err := s.run(ctx, dir, args, pass.urls)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			raw = []byte{} // A successful pass can return no matches.
		}
		raw = append(raw, out...)
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			raw = append(raw, '\n')
		}
	}
	return parse(raw, scope)
}

func (s *Scanner) run(ctx context.Context, dir string, args, urls []string) ([]byte, error) {
	binary := s.Binary
	if binary == "" {
		binary = "nuclei"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	if cmd.Err == nil {
		// Dir changes before exec, so resolve a caller-supplied relative path here.
		path, err := filepath.Abs(cmd.Path)
		if err != nil {
			return nil, fmt.Errorf("nuclei: resolve executable: %w", err)
		}
		cmd.Path = path
	}
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true"}
	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n") + "\n")
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}
	return out, nil
}
