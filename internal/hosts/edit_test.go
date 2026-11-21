package hosts

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func sp(s string) *string { return &s }

func TestNormalizeUserTags(t *testing.T) {
	tests := []struct {
		in      []string
		want    []string
		wantErr bool
	}{
		{in: nil, want: []string{}},
		{in: []string{" Prod ", "dmz", "prod", ""}, want: []string{"dmz", "prod"}},
		{in: []string{"team/web", "v1.2", "a_b-c"}, want: []string{"a_b-c", "team/web", "v1.2"}},
		{in: []string{"has space"}, wantErr: true},
		{in: []string{"a,b"}, wantErr: true},
		{in: []string{"user:x"}, wantErr: true}, // ':' is reserved for the Dojo prefix
		{in: []string{"-lead"}, wantErr: true},
		{in: []string{strings.Repeat("a", 65)}, wantErr: true},
	}
	for _, tt := range tests {
		got, err := NormalizeUserTags(tt.in)
		if tt.wantErr {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%v: err = %v, want ErrInvalid", tt.in, err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%v: got %v, %v; want %v", tt.in, got, err, tt.want)
		}
	}
}

func TestPatchNormalize(t *testing.T) {
	tags := []string{"B", "a"}
	tests := []struct {
		name    string
		in      Patch
		check   func(Patch) bool
		wantErr string
	}{
		{name: "empty", in: Patch{}, wantErr: "nothing to change"},
		{name: "criticality lowercased", in: Patch{Criticality: sp(" HIGH ")}, check: func(p Patch) bool { return *p.Criticality == "high" }},
		{name: "criticality cleared", in: Patch{Criticality: sp("")}, check: func(p Patch) bool { return *p.Criticality == "" }},
		{name: "bad criticality", in: Patch{Criticality: sp("urgent")}, wantErr: "criticality"},
		{name: "owner trimmed", in: Patch{Owner: sp("  web team ")}, check: func(p Patch) bool { return *p.Owner == "web team" }},
		{name: "owner multiline", in: Patch{Owner: sp("a\nb")}, wantErr: "owner"},
		{name: "owner too long", in: Patch{Owner: sp(strings.Repeat("x", 201))}, wantErr: "owner"},
		{name: "notes too long", in: Patch{Notes: sp(strings.Repeat("x", maxNotesLen+1))}, wantErr: "notes"},
		{name: "tags normalized", in: Patch{UserTags: &tags}, check: func(p Patch) bool { return reflect.DeepEqual(*p.UserTags, []string{"a", "b"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.normalize()
			if tt.wantErr != "" {
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want ErrInvalid with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || !tt.check(got) {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestMergeOverrides(t *testing.T) {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	tests := []struct {
		name    string
		cur     string
		patch   map[string]json.RawMessage
		want    string
		wantErr string
	}{
		{name: "set on empty", cur: `{}`, patch: map[string]json.RawMessage{"product": raw(`" OpenResty "`)}, want: `{"product":"OpenResty"}`},
		{name: "null cur", cur: ``, patch: map[string]json.RawMessage{"name": raw(`"http"`)}, want: `{"name":"http"}`},
		{name: "merge keeps others", cur: `{"product":"OpenResty","x":1}`, patch: map[string]json.RawMessage{"version": raw(`"1.2"`)},
			want: `{"product":"OpenResty","version":"1.2","x":1}`},
		{name: "null clears", cur: `{"product":"OpenResty","version":"1"}`, patch: map[string]json.RawMessage{"product": raw(`null`)},
			want: `{"version":"1"}`},
		{name: "empty string is an override", cur: `{}`, patch: map[string]json.RawMessage{"version": raw(`""`)}, want: `{"version":""}`},
		{name: "empty patch", cur: `{}`, patch: nil, wantErr: "nothing to change"},
		{name: "unknown key", cur: `{}`, patch: map[string]json.RawMessage{"port": raw(`"1"`)}, wantErr: "only name, product, version"},
		{name: "non-string", cur: `{}`, patch: map[string]json.RawMessage{"name": raw(`5`)}, wantErr: "string or null"},
		{name: "too long", cur: `{}`, patch: map[string]json.RawMessage{"name": raw(`"` + strings.Repeat("a", 201) + `"`)}, wantErr: "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergeOverrides([]byte(tt.cur), tt.patch)
			if tt.wantErr != "" {
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want ErrInvalid with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %s, %v; want %s", got, err, tt.want)
			}
		})
	}
}
