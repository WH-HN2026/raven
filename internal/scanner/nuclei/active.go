package nuclei

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/WH-HN2026/raven/internal/scanner"
)

// Pinned official nuclei-templates pack baked into deploy/Dockerfile.
const (
	TemplatesVersion            = "v10.5.2"
	TemplatesTarballSHA256      = "016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574"
	TemplatesChecksumFileSHA256 = "19efd0802f1b22142dea2607e4f863ccf2c2b523a804ac2fda556883478e986f"
)

// Aggressive nuclei_active template policy (architecture §3.11, §9).
//
// Only the curated HTTP subdirectories of the pinned template tree are passed
// via -t (excluding token-spray, osint, default-logins, credential-stuffing,
// takeovers, honeypot, and DAST/crawler packs). Excluded tags and protocol
// types are always enforced.
const (
	ActiveScannerName   = "nuclei_active"
	ActiveTags          = "cve,exposure,misconfig,tech,panel,sqli,xss,lfi,ssrf,xxe,traversal,injection,intrusive,fuzz"
	ActiveExcludedTags  = "dos,bruteforce,default-login,credential,oast,rce,deserialization,file-upload,token-spray,osint,takeover,login"
	ActiveExcludedTypes = "code,headless,javascript"

	DefaultActiveTimeoutSec    = 5
	DefaultActiveRetries       = 0
	DefaultActiveMaxHostError  = 30
	DefaultActivePerURLTimeout = 10 * time.Minute
)

// ActiveTemplateDirs are the pinned HTTP template subdirectories under
// /opt/nuclei-templates used by nuclei_active. Selecting them explicitly avoids
// external-API packs (token-spray, osint), credential packs (default-logins,
// credential-stuffing), and crawler-dependent DAST templates.
var ActiveTemplateDirs = []string{
	"http/cves",
	"http/exposures",
	"http/misconfiguration",
	"http/vulnerabilities",
	"http/fuzzing",
	"http/exposed-panels",
	"http/technologies",
}

// ActiveConfig configures an aggressive nuclei_active scanner.
type ActiveConfig struct {
	Binary        string
	TemplatesDir  string
	PerURLTimeout time.Duration // hard per-URL time cap (defaults to DefaultActivePerURLTimeout)
	TimeoutSec    int           // nuclei -timeout in seconds (defaults to DefaultActiveTimeoutSec)
	Retries       int           // nuclei -retries, clamped to 0..1 (defaults to DefaultActiveRetries)
	MaxHostError  int           // nuclei -mhe host error cap (defaults to DefaultActiveMaxHostError)
}

// ActiveScanner runs the opt-in aggressive nuclei_active stage (architecture §9).
// Custom signatures are not executed in this stage; only the pinned official
// aggressive template set is run.
type ActiveScanner struct {
	Binary        string
	TemplatesDir  string
	PerURLTimeout time.Duration
	TimeoutSec    int
	Retries       int
	MaxHostError  int
}

var _ scanner.Scanner = (*ActiveScanner)(nil)

// NewActive constructs an aggressive nuclei_active scanner with safe defaults.
func NewActive(cfg ActiveConfig) *ActiveScanner {
	s := &ActiveScanner{
		Binary:        cfg.Binary,
		TemplatesDir:  cfg.TemplatesDir,
		PerURLTimeout: cfg.PerURLTimeout,
		TimeoutSec:    cfg.TimeoutSec,
		Retries:       cfg.Retries,
		MaxHostError:  cfg.MaxHostError,
	}
	if s.PerURLTimeout <= 0 {
		s.PerURLTimeout = DefaultActivePerURLTimeout
	}
	if s.TimeoutSec <= 0 {
		s.TimeoutSec = DefaultActiveTimeoutSec
	}
	if s.MaxHostError <= 0 {
		s.MaxHostError = DefaultActiveMaxHostError
	}
	return s
}

func (*ActiveScanner) Name() string         { return ActiveScannerName }
func (*ActiveScanner) DojoScanType() string { return "Nuclei Scan" }

// BuildActiveArgs is the complete flag allowlist for nuclei_active.
// Every flag is fixed; only the positive rate limit, bounded timeout/retries/mhe
// caps, and verified local template directories are interpolated.
func BuildActiveArgs(opt scanner.Options, templateDirs []string, timeoutSec, retries, maxHostError int) ([]string, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("nuclei_active: rate limit must be positive")
	}
	if timeoutSec < 1 {
		return nil, errors.New("nuclei_active: timeout must be positive")
	}
	if retries < 0 || retries > 1 {
		return nil, errors.New("nuclei_active: retries must be 0 or 1")
	}
	if maxHostError < 1 {
		return nil, errors.New("nuclei_active: max host errors must be positive")
	}
	if len(templateDirs) == 0 {
		return nil, errors.New("nuclei_active: no template directories")
	}
	args := []string{
		"-silent", "-jsonl", "-omit-raw", "-omit-template",
		"-no-interactsh", "-disable-update-check", "-duc", "-auth=false",
		"-no-httpx", "-disable-redirects",
		"-rl", strconv.Itoa(opt.RateLimit),
		"-timeout", strconv.Itoa(timeoutSec),
		"-retries", strconv.Itoa(retries),
		"-mhe", strconv.Itoa(maxHostError),
		"-tags", ActiveTags,
		"-etags", ActiveExcludedTags,
		"-exclude-type", ActiveExcludedTypes,
		"-type", "http",
	}
	for _, dir := range templateDirs {
		if dir == "" {
			return nil, errors.New("nuclei_active: empty template directory")
		}
		args = append(args, "-t", dir)
	}
	return args, nil
}

func (s *ActiveScanner) resolvedTemplateDirs() ([]string, error) {
	root := s.TemplatesDir
	if root == "" {
		root = DefaultTemplates
	}
	dirs := make([]string, 0, len(ActiveTemplateDirs))
	for _, rel := range ActiveTemplateDirs {
		full := filepath.Join(root, rel)
		info, err := os.Stat(full)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("nuclei_active: template directory missing: %s", full)
		}
		dirs = append(dirs, full)
	}
	return dirs, nil
}

func (s *ActiveScanner) effectiveCaps() (timeoutSec, retries, maxHostError int, perURL time.Duration) {
	timeoutSec = s.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = DefaultActiveTimeoutSec
	}
	retries = s.Retries
	maxHostError = s.MaxHostError
	if maxHostError <= 0 {
		maxHostError = DefaultActiveMaxHostError
	}
	perURL = s.PerURLTimeout
	if perURL <= 0 {
		perURL = DefaultActivePerURLTimeout
	}
	return timeoutSec, retries, maxHostError, perURL
}

// Run executes nuclei_active against the validated literal-IP HTTP(S) origins
// in in.URLs with a hard per-URL time cap (bounded by ctx).
func (s *ActiveScanner) Run(ctx context.Context, in scanner.Input, opt scanner.Options) (*scanner.Result, error) {
	if opt.RateLimit < 1 {
		return nil, errors.New("nuclei_active: rate limit must be positive")
	}
	scope := make(map[string]netip.Addr, len(in.URLs))
	var urls []string
	for _, raw := range in.URLs {
		u, _, ok := rootURL(raw)
		if !ok || !slices.ContainsFunc(in.IPs, func(ip netip.Addr) bool { return literalAddress(u.Hostname(), ip) }) {
			return nil, errors.New("nuclei_active: expected an HTTP(S) origin on a batch IP")
		}
		ip, _ := netip.ParseAddr(u.Hostname())
		if _, dup := scope[u.String()]; dup {
			continue
		}
		scope[u.String()] = ip.Unmap()
		urls = append(urls, u.String())
	}
	if len(urls) == 0 {
		return Parse(nil)
	}

	templateDirs, err := s.resolvedTemplateDirs()
	if err != nil {
		return nil, err
	}
	timeoutSec, retries, maxHostError, perURL := s.effectiveCaps()
	args, err := BuildActiveArgs(opt, templateDirs, timeoutSec, retries, maxHostError)
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, perURL*time.Duration(len(urls)))
	defer cancel()

	dir, err := os.MkdirTemp("", "raven-nuclei-active-")
	if err != nil {
		return nil, fmt.Errorf("nuclei_active: create workspace: %w", err)
	}
	defer os.RemoveAll(dir)

	base := &Scanner{Binary: s.Binary}
	out, err := base.run(runCtx, dir, args, urls)
	if err != nil {
		return nil, fmt.Errorf("nuclei_active: %w", err)
	}
	if out == nil {
		out = []byte{}
	}
	return parse(out, scope)
}
