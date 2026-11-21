package signatures

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Proof harness for the built-in pack: every template must be valid, match
// its recorded response (signatures/testdata/<id>/) served from a loopback
// httptest server, and NOT match a neutral response. The matcher below only
// covers the subset our pack uses (word/regex/status, dsl status_code and
// favicon mmh3); it is a test oracle, not a nuclei replacement.

const testdataDir = "../../signatures/testdata"

type proofTemplate struct {
	ID   string `yaml:"id"`
	HTTP []struct {
		Method            string         `yaml:"method"`
		Path              []string       `yaml:"path"`
		Redirects         bool           `yaml:"redirects"`
		MaxRedirects      int            `yaml:"max-redirects"`
		MatchersCondition string         `yaml:"matchers-condition"`
		Matchers          []proofMatcher `yaml:"matchers"`
		Extractors        []proofMatcher `yaml:"extractors"`
	} `yaml:"http"`
}

type proofMatcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"`
	Condition       string   `yaml:"condition"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	DSL             []string `yaml:"dsl"`
	Status          []int    `yaml:"status"`
	Group           int      `yaml:"group"`
	Negative        bool     `yaml:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
}

type fetched struct {
	status       int
	header, body string
}

func (f fetched) part(p string) string {
	switch p {
	case "", "body":
		return f.body
	case "header":
		return f.header
	default: // all, response
		return f.header + "\r\n" + f.body
	}
}

func TestBuiltinPack(t *testing.T) {
	pack, err := Pack()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(pack); n < 30 || n > 60 {
		t.Fatalf("pack has %d templates, want 30..60", n)
	}
	neutral := fixtureServer(t, "_neutral", true)
	seen := map[string]bool{"_neutral": true}
	for _, b := range pack {
		t.Run(b.File, func(t *testing.T) {
			tpl, issues := Validate([]byte(b.YAML))
			if len(issues) > 0 {
				t.Fatalf("invalid: %v", issues)
			}
			if tpl.ID+".yaml" != b.File {
				t.Fatalf("id %s does not match file name %s", tpl.ID, b.File)
			}
			if seen[tpl.ID] {
				t.Fatalf("duplicate id %s", tpl.ID)
			}
			seen[tpl.ID] = true
			var pt proofTemplate
			if err := yaml.Unmarshal([]byte(b.YAML), &pt); err != nil {
				t.Fatal(err)
			}
			srv := fixtureServer(t, tpl.ID, false)
			if ok, ex := run(t, pt, srv.URL); !ok {
				t.Fatalf("does not match its fixture")
			} else if hasRegexExtractor(pt) && len(ex) == 0 {
				t.Fatalf("matched, but its extractors found nothing")
			} else {
				t.Logf("matched fixture, extracted %q", ex)
			}
			if ok, _ := run(t, pt, neutral.URL); ok {
				t.Fatalf("matches the neutral fixture")
			}
		})
	}
	dirs, err := os.ReadDir(testdataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if !seen[d.Name()] {
			t.Errorf("testdata/%s has no template", d.Name())
		}
	}
}

// fixtureServer serves testdata/<name>/response.http (body replaced by
// body.bin if present) at the path in path.txt (default /), 404 elsewhere.
// anyPath serves it on every path (the neutral server).
func fixtureServer(t *testing.T, name string, anyPath bool) *httptest.Server {
	t.Helper()
	dir := filepath.Join(testdataDir, name)
	raw, err := os.ReadFile(filepath.Join(dir, "response.http"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	body, _ := io.ReadAll(resp.Body)
	if bin, err := os.ReadFile(filepath.Join(dir, "body.bin")); err == nil {
		body = bin
	}
	path := "/"
	if p, err := os.ReadFile(filepath.Join(dir, "path.txt")); err == nil {
		path = strings.TrimSpace(string(p))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			t.Errorf("%s: unexpected method %s", name, r.Method)
		}
		if !anyPath && r.URL.RequestURI() != path {
			http.NotFound(w, r)
			return
		}
		for k, vs := range resp.Header {
			if k != "Content-Length" {
				w.Header()[k] = vs
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// run executes the template against base: true if any request/path matched,
// plus what the extractors found on the matching response.
func run(t *testing.T, pt proofTemplate, base string) (bool, []string) {
	t.Helper()
	for _, rq := range pt.HTTP {
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !rq.Redirects || len(via) > rq.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}}
		method := rq.Method
		if method == "" {
			method = http.MethodGet
		}
		for _, p := range rq.Path {
			p = strings.NewReplacer("{{BaseURL}}", base, "{{RootURL}}", base).Replace(p)
			req, _ := http.NewRequest(method, p, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", p, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var hdr strings.Builder
			fmt.Fprintf(&hdr, "%s %s\r\n", resp.Proto, resp.Status)
			_ = resp.Header.Write(&hdr)
			f := fetched{status: resp.StatusCode, header: hdr.String(), body: string(body)}
			if matchAll(t, rq.MatchersCondition, rq.Matchers, f) {
				return true, extract(rq.Extractors, f)
			}
		}
	}
	return false, nil
}

func matchAll(t *testing.T, cond string, ms []proofMatcher, f fetched) bool {
	for _, m := range ms {
		ok := matchOne(t, m, f)
		if cond == "and" && !ok {
			return false
		}
		if cond != "and" && ok {
			return true
		}
	}
	return cond == "and"
}

func matchOne(t *testing.T, m proofMatcher, f fetched) bool {
	part := f.part(m.Part)
	var res []bool
	switch m.Type {
	case "word":
		for _, w := range m.Words {
			if m.CaseInsensitive {
				res = append(res, strings.Contains(strings.ToLower(part), strings.ToLower(w)))
			} else {
				res = append(res, strings.Contains(part, w))
			}
		}
	case "regex":
		for _, r := range m.Regex {
			res = append(res, regexp.MustCompile(r).MatchString(part))
		}
	case "status":
		res = append(res, slices.Contains(m.Status, f.status))
	case "dsl":
		for _, d := range m.DSL {
			res = append(res, evalDSL(t, d, f))
		}
	default:
		t.Fatalf("proof harness does not support matcher type %s", m.Type)
	}
	ok := m.Condition == "and"
	for _, r := range res {
		if m.Condition == "and" {
			ok = ok && r
		} else {
			ok = ok || r
		}
	}
	return ok != m.Negative
}

var (
	dslStatus = regexp.MustCompile(`^status_code\s*==\s*(\d+)$`)
	dslMMH3   = regexp.MustCompile(`^"(-?\d+)"\s*==\s*mmh3\(base64_py\(body\)\)$`)
)

// evalDSL understands only "clause && clause" with the two clause shapes
// the pack uses.
func evalDSL(t *testing.T, expr string, f fetched) bool {
	for _, c := range strings.Split(expr, "&&") {
		c = strings.TrimSpace(c)
		for strings.HasPrefix(c, "(") && strings.HasSuffix(c, ")") {
			c = strings.TrimSpace(c[1 : len(c)-1])
		}
		if m := dslStatus.FindStringSubmatch(c); m != nil {
			if strconv.Itoa(f.status) != m[1] {
				return false
			}
		} else if m := dslMMH3.FindStringSubmatch(c); m != nil {
			if strconv.Itoa(int(faviconHash([]byte(f.body)))) != m[1] {
				return false
			}
		} else {
			t.Fatalf("proof harness does not support DSL clause %q", c)
		}
	}
	return true
}

func hasRegexExtractor(pt proofTemplate) bool {
	for _, rq := range pt.HTTP {
		for _, e := range rq.Extractors {
			if e.Type == "regex" {
				return true
			}
		}
	}
	return false
}

func extract(es []proofMatcher, f fetched) []string {
	var out []string
	for _, e := range es {
		for _, r := range e.Regex {
			if m := regexp.MustCompile(r).FindStringSubmatch(f.part(e.Part)); len(m) > e.Group {
				out = append(out, m[e.Group])
			}
		}
	}
	return out
}

// faviconHash is nuclei's mmh3(base64_py(body)): murmur3 32-bit (seed 0)
// of the base64 text with a newline every 76 chars and at the end.
func faviconHash(b []byte) int32 {
	s := base64.StdEncoding.EncodeToString(b)
	var enc []byte
	for len(s) > 76 {
		enc = append(enc, s[:76]+"\n"...)
		s = s[76:]
	}
	enc = append(enc, s+"\n"...)
	return int32(murmur3(enc))
}

func murmur3(data []byte) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	mix := func(k uint32) uint32 { return bits.RotateLeft32(k*c1, 15) * c2 }
	n := len(data) / 4
	for i := range n {
		k := uint32(data[4*i]) | uint32(data[4*i+1])<<8 | uint32(data[4*i+2])<<16 | uint32(data[4*i+3])<<24
		h ^= mix(k)
		h = bits.RotateLeft32(h, 13)*5 + 0xe6546b64
	}
	var k uint32
	tail := data[4*n:]
	for i := len(tail) - 1; i >= 0; i-- {
		k = k<<8 | uint32(tail[i])
	}
	if len(tail) > 0 {
		h ^= mix(k)
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

func TestFaviconHash(t *testing.T) {
	// murmur3 x86_32 reference vectors (seed 0).
	for in, want := range map[string]uint32{"": 0, "a": 0x3c2569b2, "abc": 0xb3dd93fa, "Hello, world!": 0xc0363e43} {
		if got := murmur3([]byte(in)); got != want {
			t.Errorf("murmur3(%q) = %#x, want %#x", in, got, want)
		}
	}
}
