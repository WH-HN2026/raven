// Package signatures holds custom nuclei templates ("signatures", D7): the
// safe-subset validator (architecture §9), the DB store and the loader of the
// built-in pack in signatures/.
package signatures

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Limits of the safe subset.
const (
	MaxTemplateBytes = 64 << 10
	MaxRequests      = 3  // http: entries
	MaxPaths         = 10 // paths over all requests
	MaxRedirects     = 3
	MaxMatchers      = 20
)

// Issue is one validation problem; Line is 1-based (0 = no position).
type Issue struct {
	Line int    `json:"line"`
	Msg  string `json:"message"`
}

func (i Issue) String() string {
	if i.Line > 0 {
		return fmt.Sprintf("line %d: %s", i.Line, i.Msg)
	}
	return i.Msg
}

// Template is the header of a parsed template (best effort when invalid).
type Template struct {
	ID       string
	Name     string
	Severity string
	Tags     []string
	Paths    []string
}

// Summary joins issues into one message (stored as validation_error).
func Summary(issues []Issue) string {
	s := make([]string, len(issues))
	for i, is := range issues {
		s[i] = is.String()
	}
	return strings.Join(s, "; ")
}

var (
	idRe          = regexp.MustCompile(`^[a-z0-9]+([-_][a-z0-9]+)*$`)
	exprRe        = regexp.MustCompile(`\{\{(.*?)\}\}`)
	headerNameRe  = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	severities    = []string{"info", "low", "medium", "high", "critical", "unknown"}
	allowedVars   = []string{"BaseURL", "RootURL", "Hostname", "Host", "Port", "Scheme"}
	forbiddenHdrs = []string{"authorization", "cookie", "proxy-authorization"}

	// Protocols other than http (and other top-level features that run code or
	// make non-HTTP traffic). Named so the message says why.
	forbiddenTop = map[string]string{
		"requests":       "legacy key requests: is not allowed, use http:",
		"code":           "protocol code is not allowed (http only)",
		"headless":       "protocol headless is not allowed (http only)",
		"javascript":     "protocol javascript is not allowed (http only)",
		"network":        "protocol network is not allowed (http only)",
		"tcp":            "protocol tcp is not allowed (http only)",
		"dns":            "protocol dns is not allowed (http only)",
		"ssl":            "protocol ssl is not allowed (http only)",
		"websocket":      "protocol websocket is not allowed (http only)",
		"whois":          "protocol whois is not allowed (http only)",
		"file":           "protocol file is not allowed (http only)",
		"flow":           "flow (javascript control flow) is not allowed",
		"workflows":      "workflows are not allowed",
		"variables":      "variables are not allowed",
		"self-contained": "self-contained requests are not allowed",
		"signature":      "signature is not allowed",
	}
	forbiddenReq = map[string]string{
		"body":            "request bodies are not allowed",
		"raw":             "raw requests are not allowed",
		"payloads":        "payloads are not allowed",
		"attack":          "attack modes are not allowed",
		"fuzzing":         "fuzzing is not allowed",
		"threads":         "threads are not allowed",
		"race":            "race requests are not allowed",
		"race_count":      "race requests are not allowed",
		"unsafe":          "unsafe requests are not allowed",
		"pipeline":        "pipelined requests are not allowed",
		"iterate-all":     "iterate-all is not allowed",
		"self-contained":  "self-contained requests are not allowed",
		"digest-username": "authentication is not allowed",
		"digest-password": "authentication is not allowed",
		"signature":       "request signing is not allowed",
	}
	allowedTop  = []string{"id", "info", "http"}
	allowedInfo = []string{"name", "author", "severity", "description", "reference", "tags", "metadata", "classification", "remediation", "impact"}
	allowedReq  = []string{"id", "method", "path", "headers", "matchers", "matchers-condition", "extractors",
		"redirects", "host-redirects", "max-redirects", "stop-at-first-match", "max-size", "req-condition"}
	allowedMatcher   = []string{"type", "part", "words", "regex", "status", "dsl", "condition", "negative", "name", "case-insensitive", "match-all"}
	allowedExtractor = []string{"type", "part", "name", "regex", "group", "kval", "dsl", "case-insensitive"}
	matcherTypes     = []string{"word", "regex", "status", "dsl"}
	extractorTypes   = []string{"regex", "kv", "dsl"}
	parts            = []string{"body", "header", "all", "response"}

	// DSL helpers that only transform the response already received. Anything
	// else (resolve, wait_for, rand_*, date/time, gadget generators, …) is rejected.
	safeDSL = []string{
		"contains", "contains_all", "contains_any", "starts_with", "ends_with",
		"line_starts_with", "line_ends_with", "regex", "tolower", "toupper",
		"trim", "trim_left", "trim_right", "trim_space", "trim_prefix", "trim_suffix",
		"len", "to_number", "to_string", "replace", "replace_regex", "concat", "join",
		"base64", "base64_py", "base64_decode", "mmh3", "md5", "sha1", "sha256",
		"hex_encode", "hex_decode", "url_decode", "html_unescape", "compare_versions",
	}
)

type checker struct {
	issues []Issue
	t      Template
	paths  int
}

func (c *checker) add(n *yaml.Node, format string, a ...any) {
	line := 0
	if n != nil {
		line = n.Line
	}
	c.issues = append(c.issues, Issue{Line: line, Msg: fmt.Sprintf(format, a...)})
}

// Validate parses a nuclei template and checks it against the safe subset.
// No issues = valid.
func Validate(src []byte) (Template, []Issue) {
	c := &checker{}
	if len(src) > MaxTemplateBytes {
		c.add(nil, "template is larger than %d bytes", MaxTemplateBytes)
		return c.t, c.issues
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		c.add(nil, "invalid YAML: %v", err)
		return c.t, c.issues
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		c.add(&doc, "template must be a YAML mapping")
		return c.t, c.issues
	}
	root := doc.Content[0]
	c.walkScalars(root)
	if len(c.issues) > 0 { // aliases or forbidden expressions: don't look deeper
		return c.t, c.issues
	}
	c.top(root)
	return c.t, c.issues
}

// walkScalars applies the document-wide rules: no anchors/aliases/merge keys,
// no interactsh/OOB, and {{…}} expressions limited to the URL variables.
func (c *checker) walkScalars(n *yaml.Node) {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		c.add(n, "YAML anchors and aliases are not allowed")
		return
	}
	if n.Kind == yaml.ScalarNode {
		low := strings.ToLower(n.Value)
		if strings.Contains(low, "interactsh") || strings.Contains(low, "oast.") {
			c.add(n, "interactsh / out-of-band markers are not allowed")
			return
		}
		for _, m := range exprRe.FindAllStringSubmatch(n.Value, -1) {
			if !slices.Contains(allowedVars, strings.TrimSpace(m[1])) {
				c.add(n, "template expression %s is not allowed (only %s)", m[0], "{{"+strings.Join(allowedVars, "}}, {{")+"}}")
			}
		}
		return
	}
	for i, ch := range n.Content {
		if n.Kind == yaml.MappingNode && i%2 == 0 && ch.Value == "<<" {
			c.add(ch, "YAML merge keys are not allowed")
			continue
		}
		c.walkScalars(ch)
	}
}

// pairs iterates a mapping, rejecting duplicate keys.
func (c *checker) pairs(m *yaml.Node, what string, fn func(k, v *yaml.Node)) bool {
	if m.Kind != yaml.MappingNode {
		c.add(m, "%s must be a mapping", what)
		return false
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if seen[k.Value] {
			c.add(k, "duplicate key %s", k.Value)
			continue
		}
		seen[k.Value] = true
		fn(k, v)
	}
	return true
}

func (c *checker) str(n *yaml.Node, what string) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		c.add(n, "%s must be a string", what)
		return "", false
	}
	return n.Value, true
}

func (c *checker) boolean(n *yaml.Node, what string) (bool, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		c.add(n, "%s must be true or false", what)
		return false, false
	}
	return n.Value == "true", true
}

func (c *checker) integer(n *yaml.Node, what string) (int, bool) {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!int" {
		if v, err := strconv.Atoi(n.Value); err == nil {
			return v, true
		}
	}
	c.add(n, "%s must be an integer", what)
	return 0, false
}

// strList accepts a sequence of strings.
func (c *checker) strList(n *yaml.Node, what string) []*yaml.Node {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		c.add(n, "%s must be a non-empty list", what)
		return nil
	}
	var out []*yaml.Node
	for _, it := range n.Content {
		if _, ok := c.str(it, what+" item"); ok {
			out = append(out, it)
		}
	}
	return out
}

func (c *checker) top(root *yaml.Node) {
	var info, http *yaml.Node
	c.pairs(root, "template", func(k, v *yaml.Node) {
		switch {
		case forbiddenTop[k.Value] != "":
			c.add(k, "%s", forbiddenTop[k.Value])
		case !slices.Contains(allowedTop, k.Value):
			c.add(k, "key %s is not allowed (only id, info, http)", k.Value)
		case k.Value == "id":
			if s, ok := c.str(v, "id"); ok {
				c.t.ID = s
				if !idRe.MatchString(s) || len(s) > 100 {
					c.add(v, "id %q must be lowercase letters, digits, - or _ (max 100)", s)
				}
			}
		case k.Value == "info":
			info = v
		case k.Value == "http":
			http = v
		}
	})
	if c.t.ID == "" {
		c.add(root, "id is required")
	}
	if info == nil {
		c.add(root, "info is required")
	} else {
		c.info(info)
	}
	if http == nil {
		c.add(root, "http is required (http is the only allowed protocol)")
	} else {
		c.requests(http)
	}
}

func (c *checker) info(n *yaml.Node) {
	c.pairs(n, "info", func(k, v *yaml.Node) {
		switch k.Value {
		case "name":
			c.t.Name, _ = c.str(v, "info.name")
		case "severity":
			if s, ok := c.str(v, "info.severity"); ok {
				c.t.Severity = s
				if !slices.Contains(severities, s) {
					c.add(v, "info.severity must be one of %s", strings.Join(severities, ", "))
				}
			}
		case "tags":
			c.t.Tags = c.tags(v)
		default:
			if !slices.Contains(allowedInfo, k.Value) {
				c.add(k, "info key %s is not allowed", k.Value)
			}
		}
	})
	if strings.TrimSpace(c.t.Name) == "" {
		c.add(n, "info.name is required")
	}
	if c.t.Severity == "" {
		c.add(n, "info.severity is required")
	}
	if len(c.t.Tags) == 0 {
		c.add(n, "info.tags is required")
	}
}

// tags accepts "a,b" or a list.
func (c *checker) tags(n *yaml.Node) []string {
	var raw []string
	switch n.Kind {
	case yaml.ScalarNode:
		raw = strings.Split(n.Value, ",")
	case yaml.SequenceNode:
		for _, it := range c.strList(n, "info.tags") {
			raw = append(raw, it.Value)
		}
	default:
		c.add(n, "info.tags must be a string or a list")
	}
	var out []string
	for _, t := range raw {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (c *checker) requests(n *yaml.Node) {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		c.add(n, "http must be a non-empty list of requests")
		return
	}
	if len(n.Content) > MaxRequests {
		c.add(n, "at most %d http requests are allowed", MaxRequests)
	}
	for _, r := range n.Content {
		c.request(r)
	}
	if c.paths > MaxPaths {
		c.add(n, "at most %d paths are allowed in total, got %d", MaxPaths, c.paths)
	}
}

func (c *checker) request(n *yaml.Node) {
	var hasPath, hasMatch, redirects bool
	var maxRedir *yaml.Node
	ok := c.pairs(n, "http request", func(k, v *yaml.Node) {
		switch {
		case forbiddenReq[k.Value] != "":
			c.add(k, "%s", forbiddenReq[k.Value])
		case strings.HasPrefix(k.Value, "pipeline"):
			c.add(k, "pipelined requests are not allowed")
		case !slices.Contains(allowedReq, k.Value):
			c.add(k, "request key %s is not allowed", k.Value)
		case k.Value == "method":
			if s, ok := c.str(v, "method"); ok && s != "GET" && s != "HEAD" {
				c.add(v, "method %s is not allowed (GET or HEAD only)", s)
			}
		case k.Value == "path":
			hasPath = true
			for _, p := range c.strList(v, "path") {
				c.path(p)
			}
		case k.Value == "headers":
			c.headers(v)
		case k.Value == "matchers":
			hasMatch = c.matchers(v) || hasMatch
		case k.Value == "matchers-condition":
			if s, ok := c.str(v, "matchers-condition"); ok && s != "and" && s != "or" {
				c.add(v, "matchers-condition must be and or or")
			}
		case k.Value == "extractors":
			hasMatch = c.extractors(v) || hasMatch
		case k.Value == "redirects", k.Value == "host-redirects":
			if b, ok := c.boolean(v, k.Value); ok && b {
				redirects = true
			}
		case k.Value == "max-redirects":
			maxRedir = v
			if m, ok := c.integer(v, "max-redirects"); ok && (m < 0 || m > MaxRedirects) {
				c.add(v, "max-redirects must be 0..%d", MaxRedirects)
			}
		case k.Value == "stop-at-first-match", k.Value == "req-condition":
			c.boolean(v, k.Value)
		case k.Value == "max-size":
			if m, ok := c.integer(v, "max-size"); ok && (m < 1 || m > 4<<20) {
				c.add(v, "max-size must be 1..%d", 4<<20)
			}
		case k.Value == "id":
			c.str(v, "request id")
		}
	})
	if !ok {
		return
	}
	if !hasPath {
		c.add(n, "path is required in every request")
	}
	if !hasMatch {
		c.add(n, "every request needs matchers or extractors")
	}
	if redirects && maxRedir == nil {
		c.add(n, "redirects: true needs max-redirects (at most %d)", MaxRedirects)
	}
}

// path must stay on the target: {{BaseURL}} or {{RootURL}} followed by a
// path or query, no whitespace (no CRLF injection).
func (c *checker) path(n *yaml.Node) {
	c.paths++
	p := n.Value
	rest, ok := strings.CutPrefix(p, "{{BaseURL}}")
	if !ok {
		rest, ok = strings.CutPrefix(p, "{{RootURL}}")
	}
	if !ok {
		c.add(n, "path %q must start with {{BaseURL}} or {{RootURL}}", p)
		return
	}
	if rest != "" && rest[0] != '/' && rest[0] != '?' {
		c.add(n, "path %q must continue with / or ? after the base URL", p)
	}
	if strings.ContainsAny(rest, " \t\r\n") || strings.Contains(rest, "{{") || strings.Contains(rest, "://") {
		c.add(n, "path %q must be a plain path (no spaces, expressions or URLs)", p)
	}
}

func (c *checker) headers(n *yaml.Node) {
	c.pairs(n, "headers", func(k, v *yaml.Node) {
		if !headerNameRe.MatchString(k.Value) {
			c.add(k, "invalid header name %q", k.Value)
		}
		if slices.Contains(forbiddenHdrs, strings.ToLower(k.Value)) {
			c.add(k, "header %s is not allowed (no credentials)", k.Value)
		}
		if s, ok := c.str(v, "header value"); ok && strings.ContainsAny(s, "\r\n") {
			c.add(v, "header value must be one line")
		}
	})
}

func (c *checker) list(n *yaml.Node, what string) bool {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		c.add(n, "%s must be a non-empty list", what)
		return false
	}
	if len(n.Content) > MaxMatchers {
		c.add(n, "at most %d %s are allowed", MaxMatchers, what)
	}
	return true
}

func (c *checker) matchers(n *yaml.Node) bool {
	if !c.list(n, "matchers") {
		return false
	}
	for _, m := range n.Content {
		c.matcher(m)
	}
	return true
}

func (c *checker) matcher(n *yaml.Node) {
	var typ string
	have := map[string]*yaml.Node{}
	if !c.pairs(n, "matcher", func(k, v *yaml.Node) {
		have[k.Value] = v
		switch k.Value {
		case "type":
			typ, _ = c.str(v, "matcher type")
		case "part":
			if s, ok := c.str(v, "part"); ok && !slices.Contains(parts, s) {
				c.add(v, "part %s is not allowed (%s)", s, strings.Join(parts, ", "))
			}
		case "words":
			c.strList(v, "words")
		case "regex":
			c.regexes(v)
		case "status":
			c.statuses(v)
		case "dsl":
			c.dsls(v)
		case "condition":
			if s, ok := c.str(v, "condition"); ok && s != "and" && s != "or" {
				c.add(v, "condition must be and or or")
			}
		case "negative", "case-insensitive", "match-all":
			c.boolean(v, k.Value)
		case "name":
			c.str(v, "matcher name")
		default:
			c.add(k, "matcher key %s is not allowed", k.Value)
		}
	}) {
		return
	}
	if !slices.Contains(matcherTypes, typ) {
		c.add(n, "matcher type %q is not allowed (%s)", typ, strings.Join(matcherTypes, ", "))
		return
	}
	need := map[string]string{"word": "words", "regex": "regex", "status": "status", "dsl": "dsl"}[typ]
	if have[need] == nil {
		c.add(n, "%s matcher needs %s", typ, need)
	}
}

func (c *checker) extractors(n *yaml.Node) bool {
	if !c.list(n, "extractors") {
		return false
	}
	for _, e := range n.Content {
		var typ string
		c.pairs(e, "extractor", func(k, v *yaml.Node) {
			switch k.Value {
			case "type":
				typ, _ = c.str(v, "extractor type")
			case "internal":
				c.add(k, "internal extractors (dynamic values) are not allowed")
			case "regex":
				c.regexes(v)
			case "dsl":
				c.dsls(v)
			case "kval":
				c.strList(v, "kval")
			case "group":
				c.integer(v, "group")
			case "case-insensitive":
				c.boolean(v, k.Value)
			case "part":
				if s, ok := c.str(v, "part"); ok && !slices.Contains(parts, s) {
					c.add(v, "part %s is not allowed (%s)", s, strings.Join(parts, ", "))
				}
			case "name":
				c.str(v, "extractor name")
			default:
				c.add(k, "extractor key %s is not allowed", k.Value)
			}
		})
		if e.Kind == yaml.MappingNode && !slices.Contains(extractorTypes, typ) {
			c.add(e, "extractor type %q is not allowed (%s)", typ, strings.Join(extractorTypes, ", "))
		}
	}
	return true
}

func (c *checker) regexes(n *yaml.Node) {
	for _, r := range c.strList(n, "regex") {
		if _, err := regexp.Compile(r.Value); err != nil {
			c.add(r, "invalid regex: %v", err)
		}
	}
}

func (c *checker) statuses(n *yaml.Node) {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		c.add(n, "status must be a non-empty list")
		return
	}
	for _, s := range n.Content {
		if v, ok := c.integer(s, "status"); ok && (v < 100 || v > 599) {
			c.add(s, "status %d is not an HTTP status", v)
		}
	}
}

func (c *checker) dsls(n *yaml.Node) {
	for _, d := range c.strList(n, "dsl") {
		for _, fn := range dslCalls(d.Value) {
			if !slices.Contains(safeDSL, fn) {
				c.add(d, "DSL function %s is not allowed", fn)
			}
		}
	}
}

// dslCalls returns the names of the functions called in a DSL expression
// (identifiers followed by "("), skipping string literals.
func dslCalls(expr string) []string {
	var out []string
	for i := 0; i < len(expr); {
		ch := expr[i]
		switch {
		case ch == '"' || ch == '\'' || ch == '`':
			j := i + 1
			for j < len(expr) && expr[j] != ch {
				if expr[j] == '\\' {
					j++
				}
				j++
			}
			i = j + 1
		case isIdentStart(ch):
			j := i
			for j < len(expr) && (isIdentStart(expr[j]) || expr[j] >= '0' && expr[j] <= '9') {
				j++
			}
			k := j
			for k < len(expr) && (expr[k] == ' ' || expr[k] == '\t') {
				k++
			}
			if k < len(expr) && expr[k] == '(' {
				out = append(out, expr[i:j])
			}
			i = j
		default:
			i++
		}
	}
	return out
}

func isIdentStart(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
