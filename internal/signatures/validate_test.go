package signatures

import (
	"strings"
	"testing"
)

const goodTemplate = `id: asi-test-good
info:
  name: Good template
  author: asi
  severity: info
  tags: asi,test
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    redirects: true
    max-redirects: 2
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Admin"
      - type: status
        status:
          - 200
`

// req builds a template whose single request has the given extra lines
// (indented 4 spaces), with a valid path and matcher.
func req(extra string) string {
	return `id: asi-test
info:
  name: T
  severity: info
  tags: asi
http:
  - path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
` + extra
}

func TestValidateGood(t *testing.T) {
	cases := map[string]string{
		"basic": goodTemplate,
		"head + list tags + favicon dsl": `id: asi-fav
info:
  name: Fav
  severity: info
  tags: [asi, favicon]
http:
  - method: HEAD
    path: ["{{BaseURL}}/favicon.ico", "{{RootURL}}/x?y=1"]
    headers:
      User-Agent: asi
    matchers:
      - type: dsl
        dsl:
          - 'status_code==200 && ("81586312" == mmh3(base64_py(body)))'
          - 'contains(tolower(header), "x-powered-by") && len(body) > 0'
`,
		"regex extractor + negative word": req(`    extractors:
      - type: regex
        part: header
        group: 1
        regex: ['(?i)server: ([^\r\n]+)']
`),
		"string containing function-like text": req(`    stop-at-first-match: true
    matchers-condition: or
`) + `  - path: ["{{BaseURL}}/b"]
    matchers:
      - type: dsl
        dsl: ['contains(body, "resolve(x) wait_for(1)")']
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			tpl, issues := Validate([]byte(src))
			if len(issues) > 0 {
				t.Fatalf("want valid, got %v", issues)
			}
			if tpl.ID == "" || tpl.Name == "" || len(tpl.Tags) == 0 {
				t.Fatalf("header not parsed: %+v", tpl)
			}
		})
	}
}

func TestValidateEvil(t *testing.T) {
	cases := []struct {
		name, src, want string
		line            int // 0 = don't check
	}{
		{"post method", strings.Replace(goodTemplate, "method: GET", "method: POST", 1), "method POST is not allowed", 8},
		{"lowercase get", strings.Replace(goodTemplate, "method: GET", "method: get", 1), "method get is not allowed", 8},
		{"body", req("    body: 'a=1'\n"), "request bodies are not allowed", 12},
		{"raw request", req("    raw:\n      - |\n        GET / HTTP/1.1\n"), "raw requests are not allowed", 12},
		{"payloads", req("    payloads:\n      p: [a, b]\n"), "payloads are not allowed", 12},
		{"attack", req("    attack: clusterbomb\n"), "attack modes are not allowed", 12},
		{"fuzzing", req("    fuzzing:\n      - part: query\n"), "fuzzing is not allowed", 12},
		{"race", req("    race: true\n"), "race requests are not allowed", 12},
		{"unsafe", req("    unsafe: true\n"), "unsafe requests are not allowed", 12},
		{"pipeline", req("    pipeline-concurrent-connections: 40\n"), "pipelined requests are not allowed", 12},
		{"digest auth", req("    digest-username: admin\n"), "authentication is not allowed", 12},
		{"authorization header", req("    headers:\n      Authorization: Basic YWRtaW46YWRtaW4=\n"), "header Authorization is not allowed", 13},
		{"crlf header", req("    headers:\n      X-A: \"a\\r\\nX-B: b\"\n"), "header value must be one line", 13},
		{"code protocol", goodTemplate + "code:\n  - engine: [sh]\n    source: id\n", "protocol code is not allowed", 22},
		{"headless", goodTemplate + "headless:\n  - steps: []\n", "protocol headless is not allowed", 22},
		{"javascript", goodTemplate + "javascript:\n  - code: 'x'\n", "protocol javascript is not allowed", 22},
		{"network", goodTemplate + "tcp:\n  - inputs: [{data: x}]\n", "protocol tcp is not allowed", 22},
		{"dns", goodTemplate + "dns:\n  - name: x\n", "protocol dns is not allowed", 22},
		{"websocket", goodTemplate + "websocket:\n  - address: x\n", "protocol websocket is not allowed", 22},
		{"whois", goodTemplate + "whois:\n  - query: x\n", "protocol whois is not allowed", 22},
		{"flow", goodTemplate + "flow: http(1)\n", "flow (javascript control flow) is not allowed", 22},
		{"legacy requests", strings.Replace(goodTemplate, "http:", "requests:", 1), "use http:", 7},
		{"interactsh in path", strings.Replace(goodTemplate, "/admin", "/?u={{interactsh-url}}", 1), "interactsh", 10},
		{"oob host in header", req("    headers:\n      X-Callback: abc.oast.fun\n"), "out-of-band", 13},
		{"dsl expression in path", strings.Replace(goodTemplate, "/admin", "/{{rand_base(8)}}", 1), "template expression {{rand_base(8)}} is not allowed", 10},
		{"dsl resolve", req("      - type: dsl\n        dsl: ['resolve(\"x\") != \"\"']\n"), "DSL function resolve is not allowed", 13},
		{"dsl wait_for", req("      - type: dsl\n        dsl: ['wait_for(10)']\n"), "DSL function wait_for is not allowed", 13},
		{"too many redirects", strings.Replace(goodTemplate, "max-redirects: 2", "max-redirects: 10", 1), "max-redirects must be 0..3", 12},
		{"redirects without max", strings.Replace(goodTemplate, "    max-redirects: 2\n", "", 1), "redirects: true needs max-redirects", 8},
		{"too many paths", strings.Replace(goodTemplate, `      - "{{BaseURL}}/admin"`, strings.Repeat(`      - "{{BaseURL}}/a"`+"\n", 11)[:len(strings.Repeat(`      - "{{BaseURL}}/a"`+"\n", 11))-1], 1), "at most 10 paths", 8},
		{"other host path", strings.Replace(goodTemplate, "{{BaseURL}}/admin", "http://evil.example/admin", 1), "must start with {{BaseURL}}", 10},
		{"userinfo trick", strings.Replace(goodTemplate, "{{BaseURL}}/admin", "{{BaseURL}}@evil.example/", 1), "must continue with / or ?", 10},
		{"missing name", strings.Replace(goodTemplate, "  name: Good template\n", "", 1), "info.name is required", 3},
		{"missing severity", strings.Replace(goodTemplate, "  severity: info\n", "", 1), "info.severity is required", 3},
		{"bad severity", strings.Replace(goodTemplate, "severity: info", "severity: extreme", 1), "info.severity must be one of", 5},
		{"missing tags", strings.Replace(goodTemplate, "  tags: asi,test\n", "", 1), "info.tags is required", 3},
		{"missing id", strings.Replace(goodTemplate, "id: asi-test-good\n", "", 1), "id is required", 0},
		{"bad id", strings.Replace(goodTemplate, "asi-test-good", "../etc/passwd", 1), "must be lowercase", 1},
		{"no matchers", strings.Replace(goodTemplate, goodTemplate[strings.Index(goodTemplate, "    matchers-condition"):], "", 1), "needs matchers or extractors", 8},
		{"internal extractor", req("    extractors:\n      - type: regex\n        internal: true\n        regex: ['x']\n"), "internal extractors", 14},
		{"xpath extractor", req("    extractors:\n      - type: xpath\n        xpath: ['/a']\n"), "extractor key xpath is not allowed", 14},
		{"binary matcher", req("      - type: binary\n        binary: ['00']\n"), "matcher key binary is not allowed", 13},
		{"bad regex", req("      - type: regex\n        regex: ['(']\n"), "invalid regex", 13},
		{"anchor/alias", "id: a\ninfo: &i\n  name: x\n  severity: info\n  tags: a\nhttp: *i\n", "anchors and aliases", 2},
		{"unknown top key", goodTemplate + "variables:\n  a: b\n", "variables are not allowed", 22},
		{"not yaml", "id: [unclosed", "invalid YAML", 0},
		{"too many requests", goodTemplate + strings.Repeat(goodTemplate[strings.Index(goodTemplate, "  - method"):], 3), "at most 3 http requests", 8},
	}
	if len(cases) < 20 {
		t.Fatalf("need at least 20 evil cases, have %d", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, issues := Validate([]byte(tc.src))
			if len(issues) == 0 {
				t.Fatalf("want rejected, got valid:\n%s", tc.src)
			}
			for _, is := range issues {
				if strings.Contains(is.Msg, tc.want) {
					if tc.line != 0 && is.Line != tc.line {
						t.Fatalf("issue %q at line %d, want line %d", is.Msg, is.Line, tc.line)
					}
					return
				}
			}
			t.Fatalf("want an issue containing %q, got %v", tc.want, issues)
		})
	}
}

func TestDSLCalls(t *testing.T) {
	got := dslCalls(`status_code==200 && ("x(" == mmh3 (base64_py(body))) && contains(body, 'a(b)')`)
	want := []string{"mmh3", "base64_py", "contains"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

// All problems are reported at once, with lines, and the id is still parsed.
func TestValidateReportsAllIssues(t *testing.T) {
	src := `id: evil
info:
  name: Evil
  severity: high
  tags: demo
http:
  - method: POST
    body: "user=admin&pass=admin"
    path: ["{{BaseURL}}/login?cb={{interactsh-url}}"]
    matchers:
      - type: dsl
        dsl: ['resolve("x") != ""']
`
	tpl, issues := Validate([]byte(src))
	if tpl.ID != "evil" {
		t.Fatalf("id not parsed: %+v", tpl)
	}
	want := []string{"line 9: interactsh", "line 7: method POST", "line 8: request bodies", "line 12: DSL function resolve"}
	got := Summary(issues)
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %s", w, got)
		}
	}
}
