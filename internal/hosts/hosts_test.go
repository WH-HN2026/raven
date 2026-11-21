package hosts

import (
	"reflect"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func TestBuildWhere(t *testing.T) {
	tests := []struct {
		name     string
		f        Filter
		want     []string // substrings of the WHERE clause, in order
		wantArgs []any
	}{
		{name: "none", f: Filter{}, want: nil, wantArgs: nil},
		{name: "state", f: Filter{State: "active"}, want: []string{"h.state = $1"}, wantArgs: []any{"active"}},
		{
			name:     "port",
			f:        Filter{Port: ptr(443)},
			want:     []string{"s.state = 'open' AND s.port = $1"},
			wantArgs: []any{443},
		},
		{
			name:     "tech is case-insensitive",
			f:        Filter{Tech: "Nginx"},
			want:     []string{"http_observations", "lower(t) = lower($1)"},
			wantArgs: []any{"Nginx"},
		},
		{name: "tag", f: Filter{Tag: "dmz"}, want: []string{"$1 = ANY(h.user_tags)"}, wantArgs: []any{"dmz"}},
		{name: "q ip", f: Filter{Q: "10.0.0.5"}, want: []string{"h.ip <<= $1::inet"}, wantArgs: []any{"10.0.0.5/32"}},
		{name: "q cidr is masked", f: Filter{Q: " 10.0.0.77/24 "}, want: []string{"h.ip <<= $1::inet"}, wantArgs: []any{"10.0.0.0/24"}},
		{name: "q ipv6", f: Filter{Q: "fd00::1"}, want: []string{"h.ip <<= $1::inet"}, wantArgs: []any{"fd00::1/128"}},
		{
			name:     "q text prefix or hostname",
			f:        Filter{Q: "10.0."},
			want:     []string{"starts_with(host(h.ip), $1)", "strpos(lower(hn), lower($1))"},
			wantArgs: []any{"10.0."},
		},
		{
			name:     "all combined, numbered in order",
			f:        Filter{State: "unstable", Port: ptr(22), Tech: "php", Tag: "prod", Q: "web"},
			want:     []string{"h.state = $1", "s.port = $2", "lower($3)", "$4 = ANY", "starts_with(host(h.ip), $5)"},
			wantArgs: []any{"unstable", 22, "php", "prod", "web"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			where, args := buildWhere(tt.f)
			if tt.want == nil {
				if where != "" || args != nil {
					t.Fatalf("want no filter, got %q %v", where, args)
				}
				return
			}
			if !strings.HasPrefix(where, " WHERE ") {
				t.Fatalf("where = %q", where)
			}
			rest := where
			for _, w := range tt.want {
				i := strings.Index(rest, w)
				if i < 0 {
					t.Fatalf("%q not found (in order) in %q", w, where)
				}
				rest = rest[i+len(w):]
			}
			if !reflect.DeepEqual(args, tt.wantArgs) {
				t.Fatalf("args = %#v, want %#v", args, tt.wantArgs)
			}
			// No user value is ever spliced into the SQL text.
			for _, a := range args {
				if s, ok := a.(string); ok && strings.Contains(where, s) {
					t.Fatalf("value %q appears in SQL %q", s, where)
				}
			}
		})
	}
}

func TestBuildList(t *testing.T) {
	list, count, args := buildList(Filter{State: "active", Tag: "x", Limit: 50, Offset: 100})
	if !strings.HasSuffix(list, "ORDER BY h.ip LIMIT $3 OFFSET $4) h ORDER BY h.ip") {
		t.Fatalf("list = %q", list)
	}
	if !strings.HasPrefix(count, "SELECT count(*) FROM hosts h WHERE ") || strings.Contains(count, "LIMIT") {
		t.Fatalf("count = %q", count)
	}
	if !reflect.DeepEqual(args, []any{"active", "x", int32(50), int32(100)}) {
		t.Fatalf("args = %#v", args)
	}
	list, _, args = buildList(Filter{Limit: 10})
	if !strings.Contains(list, "FROM hosts h ORDER BY h.ip LIMIT $1 OFFSET $2) h ORDER BY h.ip") || len(args) != 2 {
		t.Fatalf("list = %q args %v", list, args)
	}
}

func TestApplyServiceOverrides(t *testing.T) {
	scan := ServiceFields{Name: "http", Product: "nginx", Version: "1.25.3"}
	tests := []struct {
		name      string
		overrides string
		want      ServiceFields
		wantOver  []string
	}{
		{name: "nil", overrides: "", want: scan, wantOver: []string{}},
		{name: "empty object", overrides: `{}`, want: scan, wantOver: []string{}},
		{name: "null", overrides: `null`, want: scan, wantOver: []string{}},
		{name: "malformed", overrides: `{"name":`, want: scan, wantOver: []string{}},
		{
			name:      "product only",
			overrides: `{"product":"OpenResty"}`,
			want:      ServiceFields{Name: "http", Product: "OpenResty", Version: "1.25.3"},
			wantOver:  []string{"product"},
		},
		{
			name:      "all three, stable order",
			overrides: `{"version":"2","name":"https","product":"Caddy"}`,
			want:      ServiceFields{Name: "https", Product: "Caddy", Version: "2"},
			wantOver:  []string{"name", "product", "version"},
		},
		{
			name:      "empty string clears",
			overrides: `{"version":""}`,
			want:      ServiceFields{Name: "http", Product: "nginx", Version: ""},
			wantOver:  []string{"version"},
		},
		{
			name:      "non-string and unknown keys ignored",
			overrides: `{"name":5,"product":null,"owner":"bob","banner":"x"}`,
			want:      scan,
			wantOver:  []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, over := applyServiceOverrides(scan, []byte(tt.overrides))
			if got != tt.want || !reflect.DeepEqual(over, tt.wantOver) {
				t.Fatalf("got %+v %v, want %+v %v", got, over, tt.want, tt.wantOver)
			}
		})
	}
}

func TestDecodeHeaders(t *testing.T) {
	tests := []struct {
		in   string
		want map[string]string
	}{
		{"", map[string]string{}},
		{`{"Server":"nginx","Set-Cookie":["a=1","b=2"],"X-N":3}`, map[string]string{"Server": "nginx", "Set-Cookie": "a=1, b=2", "X-N": "3"}},
		{"Server: nginx\r\nX-Environment: staging\nbogus\nVary: a\nVary: b", map[string]string{
			"Server": "nginx", "X-Environment": "staging", "Vary": "a, b",
		}},
	}
	for _, tt := range tests {
		if got := decodeHeaders(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("decodeHeaders(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestDecodeStrings(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"[]", []string{}},
		{`["PHPSESSID=x; HttpOnly","b=2"]`, []string{"PHPSESSID=x; HttpOnly", "b=2"}},
		{"a=1\n\n b=2 \n", []string{"a=1", "b=2"}},
		{`[{"url":"http://x/","status":301}]`, []string{`{"status":301,"url":"http://x/"}`}},
	}
	for _, tt := range tests {
		if got := decodeStrings(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("decodeStrings(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
