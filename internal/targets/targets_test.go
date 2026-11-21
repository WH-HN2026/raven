package targets

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		in       string
		kind     Kind
		value    string
		errorHas string
	}{
		{"10.0.0.1", KindIP, "10.0.0.1", ""},
		{" 10.0.0.1 ", KindIP, "10.0.0.1", ""},
		{"::ffff:10.0.0.1", KindIP, "10.0.0.1", ""},
		{"10.0.0.0/24", KindCIDR, "10.0.0.0/24", ""},
		{"10.0.0.77/24", KindCIDR, "10.0.0.0/24", ""}, // masked
		{"Example.AGH.edu.pl.", KindDomain, "example.agh.edu.pl", ""},
		{"wordpress", KindDomain, "wordpress", ""}, // single-label (lab containers)
		{"10.0.0.256", "", "", "invalid IP"},
		{"10.0.0.0/33", "", "", "invalid CIDR"},
		{"bad_host!", "", "", "not an IP, CIDR or domain"},
		{"-bad.example", "", "", "invalid domain"},
		{"", "", "", "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			k, v, err := Classify(tt.in)
			if tt.errorHas != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errorHas) {
					t.Fatalf("err = %v, want containing %q", err, tt.errorHas)
				}
				return
			}
			if err != nil || k != tt.kind || v != tt.value {
				t.Fatalf("got %s %q %v, want %s %q", k, v, err, tt.kind, tt.value)
			}
		})
	}
}

func TestNewEntryTargetRules(t *testing.T) {
	tests := []struct {
		in       string
		kind     Kind
		errorHas string
	}{
		{"10.1.0.0/16", "", ""},
		{"10.0.0.0/15", "", "limit is 2^16"},
		{"10.0.0.0/8", "", "limit is 2^16"},
		{"127.0.0.1", "", ""},
		{"0.0.0.0", "", ""},
		{"224.0.0.1", "", ""},
		{"169.254.1.1", "", ""},
		{"255.255.255.255", "", ""},
		{"127.0.0.0/30", "", ""},
		{"2001:db8::1", "", "IPv6"},
		{"2001:db8::/120", "", "IPv6"},
		{"10.0.0.1", KindDomain, "is a ip, not a domain"},
		{"10.0.0.1", KindIP, ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := NewEntry(tt.in, tt.kind, nil, "")
			if tt.errorHas == "" && err != nil || tt.errorHas != "" && (err == nil || !strings.Contains(err.Error(), tt.errorHas)) {
				t.Fatalf("err = %v, want %q", err, tt.errorHas)
			}
		})
	}
}

func values(p *Parsed) string {
	var s []string
	for _, e := range p.Entries {
		s = append(s, string(e.Kind)+":"+e.Value)
	}
	return strings.Join(s, " ")
}

func lines(p *Parsed) []int {
	out := []int{}
	for _, e := range p.Errors {
		out = append(out, e.Line)
	}
	return out
}

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		parse     func() *Parsed
		want      string
		errLines  []int
		checkTags map[string][]string
	}{
		{
			name: "manual: newlines, commas, comments, dup",
			parse: func() *Parsed {
				return ParseManual("10.0.0.1, 10.0.0.0/30\n# comment\n\nexample.org 10.0.0.1 # trailing\nnope!\n10.0.0.300")
			},
			want: "ip:10.0.0.1 cidr:10.0.0.0/30 domain:example.org", errLines: []int{5, 6},
		},
		{
			name: "csv with header, tags and notes, one bad line",
			parse: func() *Parsed {
				return ParseCSV(strings.NewReader("value,tags,note\n10.0.0.1,web;prod,main box\n10.0.0.0/24,lab\nnot a host,,\nexample.org\n10.0.0.1,db,\n"))
			},
			want: "ip:10.0.0.1 cidr:10.0.0.0/24 domain:example.org", errLines: []int{4},
			checkTags: map[string][]string{"10.0.0.1": {"db", "prod", "web"}},
		},
		{
			name: "csv without header, too many columns, BOM",
			parse: func() *Parsed {
				return ParseCSV(strings.NewReader("\ufeff10.0.0.1\n10.0.0.2,a,b,c\n\n10.0.0.3,\"x|y\"\n"))
			},
			want: "ip:10.0.0.1 ip:10.0.0.3", errLines: []int{2},
			checkTags: map[string][]string{"10.0.0.3": {"x", "y"}},
		},
		{
			name:  "csv bad quote keeps going",
			parse: func() *Parsed { return ParseCSV(strings.NewReader("10.0.0.1\n10.0.0.2,\"a\"b\n10.0.0.3\n")) },
			want:  "ip:10.0.0.1 ip:10.0.0.3", errLines: []int{2},
		},
		{
			name: "json array with line numbers",
			parse: func() *Parsed {
				return ParseJSON([]byte("[\n  {\"value\": \"10.0.0.1\", \"tags\": [\"a\"], \"note\": \"n\"},\n  {\"value\": \"bogus value\"},\n  {\"value\": \"10.0.0.0/16\", \"kind\": \"cidr\"},\n  {\"value\": \"10.0.0.9\", \"kind\": \"domain\"},\n  {\"valu\": \"x\"}\n]"))
			},
			want: "ip:10.0.0.1 cidr:10.0.0.0/16", errLines: []int{3, 5, 6},
		},
		{
			name:  "json not an array",
			parse: func() *Parsed { return ParseJSON([]byte(`{"value":"10.0.0.1"}`)) },
			want:  "", errLines: []int{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.parse()
			if got := values(p); got != tt.want {
				t.Errorf("entries = %q, want %q", got, tt.want)
			}
			if got := lines(p); !reflect.DeepEqual(got, tt.errLines) {
				t.Errorf("error lines = %v, want %v (%+v)", got, tt.errLines, p.Errors)
			}
			for v, tags := range tt.checkTags {
				for _, e := range p.Entries {
					if e.Value == v && !reflect.DeepEqual(e.Tags, tags) {
						t.Errorf("%s tags = %v, want %v", v, e.Tags, tags)
					}
				}
			}
		})
	}
}

func TestParseUploadDetect(t *testing.T) {
	for _, tt := range []struct{ name, data, src string }{
		{"t.json", `[{"value":"10.0.0.1"}]`, "json"},
		{"t.csv", "10.0.0.1\n", "csv"},
		{"blob", "  [{\"value\":\"10.0.0.1\"}]", "json"},
		{"blob", "10.0.0.1,x\n", "csv"},
	} {
		p, src := ParseUpload(tt.name, []byte(tt.data))
		if src != tt.src || len(p.Entries) != 1 {
			t.Errorf("%s %q: src=%s entries=%d", tt.name, tt.data, src, len(p.Entries))
		}
	}
}

// fakeDNS maps names to addresses; unknown names fail like NXDOMAIN.
type fakeDNS map[string][]string

func (f fakeDNS) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("want ip4")
	}
	ss, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func ent(v string) Entry {
	e, err := NewEntry(v, "", nil, "")
	if err != nil {
		panic(err)
	}
	return e
}

func rules(vs ...string) []Rule {
	var out []Rule
	for _, v := range vs {
		k, val, _ := Classify(v)
		out = append(out, Rule{Kind: k, Value: val})
	}
	return out
}

func ips(sl *ScanList) string {
	var s []string
	for _, a := range sl.IPs {
		s = append(s, a.String())
	}
	return strings.Join(s, " ")
}

func TestExpand(t *testing.T) {
	dns := fakeDNS{
		"web.lab":      {"10.0.0.5", "10.0.0.6"},
		"alias.lab":    {"10.0.0.5"},
		"staging.lab":  {"10.0.9.9"},
		"v6only.lab":   {"2001:db8::1"},
		"loop.lab":     {"127.0.0.1"},
		"blocked.corp": {"10.0.0.6"},
	}
	tests := []struct {
		name      string
		targets   []string
		scope     Scope
		want      string
		hostnames map[string][]string
		stats     [4]int // candidates, notIncluded, excluded, rejected
		warnHas   string
	}{
		{
			name:    "no includes: targets are the include set; de-dup",
			targets: []string{"10.0.0.0/30", "10.0.0.1", "10.0.0.3"},
			want:    "10.0.0.0 10.0.0.1 10.0.0.2 10.0.0.3", stats: [4]int{4, 0, 0, 0},
		},
		{
			name:    "include filters, exclude applied after include",
			targets: []string{"10.0.0.0/29", "192.168.1.1"},
			scope:   Scope{Include: rules("10.0.0.0/30", "10.0.0.6"), Exclude: rules("10.0.0.2")},
			want:    "10.0.0.0 10.0.0.1 10.0.0.3 10.0.0.6", stats: [4]int{9, 4, 1, 0},
		},
		{
			name:    "global blacklist wins over an exact include",
			targets: []string{"10.0.0.7", "10.0.0.8"},
			scope:   Scope{Include: rules("10.0.0.7", "10.0.0.8"), Exclude: rules("10.0.0.0/29")},
			want:    "10.0.0.8", stats: [4]int{2, 0, 1, 0},
		},
		{
			name:      "domains resolved, map kept, shared IP de-duplicated",
			targets:   []string{"web.lab", "alias.lab", "10.0.0.5", "nx.lab"},
			want:      "10.0.0.5 10.0.0.6",
			hostnames: map[string][]string{"10.0.0.5": {"web.lab", "alias.lab"}, "10.0.0.6": {"web.lab"}},
			stats:     [4]int{2, 0, 0, 0}, warnHas: "resolve nx.lab",
		},
		{
			name:    "include domain matches by host name suffix and resolved IP",
			targets: []string{"web.lab", "staging.lab", "10.0.0.100"},
			scope:   Scope{Include: rules("lab")},
			want:    "10.0.0.5 10.0.0.6 10.0.9.9", stats: [4]int{4, 1, 0, 0},
		},
		{
			name:    "exclude domain: by host name, and by its resolved IP",
			targets: []string{"web.lab", "staging.lab"},
			scope:   Scope{Exclude: rules("staging.lab", "blocked.corp")},
			want:    "10.0.0.5", stats: [4]int{3, 0, 2, 0},
		},
		{
			name:    "unresolvable exclude domain still excludes by name",
			targets: []string{"staging.lab"},
			scope:   Scope{Exclude: rules("lab", "gone.example")},
			want:    "", stats: [4]int{1, 0, 1, 0}, warnHas: "gone.example",
		},
		{
			name:    "IPv6-only resolution is dropped, loopback resolution is kept",
			targets: []string{"v6only.lab", "loop.lab"},
			want:    "127.0.0.1", stats: [4]int{1, 0, 0, 0}, warnHas: "v6only.lab",
		},
		{
			name:    "special IPv4 ranges are plain targets; IPv6 target is dropped",
			targets: []string{"127.0.0.0/30", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "2001:db8::1"},
			want:    "0.0.0.0 127.0.0.0 127.0.0.1 127.0.0.2 127.0.0.3 169.254.1.1 224.0.0.1 255.255.255.255",
			stats:   [4]int{9, 0, 0, 1}, warnHas: "dropped 1 IPv6 addresses",
		},
		{
			name:    "blacklist still excludes loopback",
			targets: []string{"127.0.0.1", "10.0.0.1"},
			scope:   Scope{Exclude: rules("127.0.0.0/8")},
			want:    "10.0.0.1", stats: [4]int{2, 0, 1, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts []Entry
			for _, v := range tt.targets {
				ts = append(ts, ent(v))
			}
			sl, err := Expand(context.Background(), ts, tt.scope, dns, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if got := ips(sl); got != tt.want {
				t.Errorf("IPs = %q, want %q", got, tt.want)
			}
			st := [4]int{sl.Stats.Candidates, sl.Stats.NotIncluded, sl.Stats.Excluded, sl.Stats.Rejected}
			if st != tt.stats {
				t.Errorf("stats = %v, want %v", st, tt.stats)
			}
			for ip, names := range tt.hostnames {
				if got := sl.Hostnames[netip.MustParseAddr(ip)]; !reflect.DeepEqual(got, names) {
					t.Errorf("hostnames[%s] = %v, want %v", ip, got, names)
				}
			}
			if tt.warnHas != "" && !strings.Contains(strings.Join(sl.Warnings, "\n"), tt.warnHas) {
				t.Errorf("warnings %q, want containing %q", sl.Warnings, tt.warnHas)
			}
		})
	}
}

func TestExpandDomainMap(t *testing.T) {
	sl, err := Expand(context.Background(), []Entry{ent("web.lab")}, Scope{Exclude: rules("10.0.0.6")},
		fakeDNS{"web.lab": {"10.0.0.6", "10.0.0.5", "10.0.0.5"}}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// the domain map keeps every resolved address, even excluded ones
	want := []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.6")}
	if got := sl.Domains["web.lab"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("Domains = %v", got)
	}
	if _, ok := sl.Hostnames[netip.MustParseAddr("10.0.0.6")]; ok {
		t.Fatal("hostnames kept for an excluded IP")
	}
}

func TestExpandSlash16(t *testing.T) {
	sl, err := Expand(context.Background(), []Entry{ent("10.20.0.0/16"), ent("10.20.255.255")},
		Scope{Exclude: rules("10.20.128.0/17")}, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if sl.Stats.Candidates != 65536 {
		t.Fatalf("candidates = %d, want 65536", sl.Stats.Candidates)
	}
	if len(sl.IPs) != 32768 || sl.Stats.Excluded != 32768 {
		t.Fatalf("IPs = %d excluded = %d, want 32768 each", len(sl.IPs), sl.Stats.Excluded)
	}
	if first, last := sl.IPs[0].String(), sl.IPs[len(sl.IPs)-1].String(); first != "10.20.0.0" || last != "10.20.127.255" {
		t.Fatalf("boundaries %s..%s", first, last)
	}

	full, err := Expand(context.Background(), []Entry{ent("10.30.0.0/16")}, Scope{}, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(full.IPs); n != 65536 || full.IPs[0].String() != "10.30.0.0" || full.IPs[n-1].String() != "10.30.255.255" {
		t.Fatalf("full /16: %d IPs, %s..%s", n, full.IPs[0], full.IPs[n-1])
	}
}

func TestExpandLimits(t *testing.T) {
	big := Entry{Kind: KindCIDR, Value: "10.0.0.0/15"} // bypasses NewEntry's check, as a stale DB row would
	if _, err := Expand(context.Background(), []Entry{big}, Scope{}, nil, Limits{}); err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
		t.Fatalf("/15 err = %v", err)
	}
	if _, err := Expand(context.Background(), []Entry{big}, Scope{}, nil, Limits{MaxHostBits: 17}); err != nil {
		t.Fatalf("/15 with MaxHostBits 17: %v", err)
	}
	if _, err := Expand(context.Background(), []Entry{ent("10.0.0.0/24"), ent("10.0.1.0/24")}, Scope{}, nil, Limits{MaxIPs: 300}); err == nil {
		t.Fatal("MaxIPs not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Expand(ctx, []Entry{ent("10.0.0.0/16")}, Scope{}, nil, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx err = %v", err)
	}
}
