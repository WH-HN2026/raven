package targets

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Entry is one parsed target.
type Entry struct {
	Kind  Kind     `json:"kind"`
	Value string   `json:"value"`
	Tags  []string `json:"tags"`
	Note  string   `json:"note,omitempty"`
}

// LineError points at a bad input line (1-based). For JSON it is the line
// where the bad array element starts.
type LineError struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// Parsed is the result of parsing one input: the valid entries (de-duplicated
// by kind+value, tags merged) and an error per bad line.
type Parsed struct {
	Entries []Entry     `json:"targets"`
	Errors  []LineError `json:"errors"`

	index map[string]int // kind+value → position in Entries
}

// MaxUploadBytes bounds an upload; the HTTP layer enforces it.
const MaxUploadBytes = 10 << 20

// NewEntry validates one target value. kind may be empty (auto-detect); if
// given it must match what was detected.
func NewEntry(value string, kind Kind, tags []string, note string) (Entry, error) {
	k, v, err := Classify(value)
	if err != nil {
		return Entry{}, err
	}
	if kind != "" && kind != k {
		return Entry{}, fmt.Errorf("%q is a %s, not a %s", value, k, kind)
	}
	if err := checkTarget(k, v, DefaultMaxHostBits); err != nil {
		return Entry{}, err
	}
	return Entry{Kind: k, Value: v, Tags: cleanTags(tags), Note: strings.TrimSpace(note)}, nil
}

func cleanTags(tags []string) []string {
	out := []string{}
	for _, t := range tags {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

// add appends e, merging it into an earlier entry with the same kind+value.
func (p *Parsed) add(e Entry) {
	key := string(e.Kind) + " " + e.Value
	if i, ok := p.index[key]; ok {
		p.Entries[i].Tags = cleanTags(append(p.Entries[i].Tags, e.Tags...))
		if e.Note != "" {
			p.Entries[i].Note = e.Note
		}
		return
	}
	p.index[key] = len(p.Entries)
	p.Entries = append(p.Entries, e)
}

func (p *Parsed) fail(line int, format string, args ...any) {
	p.Errors = append(p.Errors, LineError{Line: line, Message: fmt.Sprintf(format, args...)})
}

func newParsed() *Parsed {
	return &Parsed{Entries: []Entry{}, Errors: []LineError{}, index: map[string]int{}}
}

// ParseManual parses free text: targets separated by newlines, commas or
// spaces; '#' starts a comment.
func ParseManual(text string) *Parsed {
	p := newParsed()
	for i, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' }) {
			e, err := NewEntry(f, "", nil, "")
			if err != nil {
				p.fail(i+1, "%v", err)
				continue
			}
			p.add(e)
		}
	}
	return p
}

// ParseCSV parses `value,tags,note`. The header row is optional (detected by
// a first cell "value"); tags are separated by ';' or '|'; tags and note may
// be omitted. Blank lines and lines starting with '#' are skipped.
func ParseCSV(r io.Reader) *Parsed {
	p := newParsed()
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.Comment = '#'
	first := true
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line, _ := cr.FieldPos(0)
		if err != nil {
			var pe *csv.ParseError
			if !errors.As(err, &pe) {
				p.fail(line, "%v", err)
				break
			}
			p.fail(pe.StartLine, "%v", pe.Err)
			continue
		}
		isHeader := first && strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(rec[0], "\ufeff")), "value")
		first = false
		if isHeader {
			continue
		}
		if len(rec) > 3 {
			p.fail(line, "expected at most 3 columns (value,tags,note), got %d", len(rec))
			continue
		}
		var tags []string
		note := ""
		if len(rec) > 1 {
			tags = strings.FieldsFunc(rec[1], func(r rune) bool { return r == ';' || r == '|' })
		}
		if len(rec) > 2 {
			note = rec[2]
		}
		if strings.TrimSpace(rec[0]) == "" && len(rec) == 1 {
			continue // blank line
		}
		e, err := NewEntry(strings.TrimPrefix(rec[0], "\ufeff"), "", tags, note)
		if err != nil {
			p.fail(line, "%v", err)
			continue
		}
		p.add(e)
	}
	return p
}

// jsonItem is one element of the JSON format: [{"value", "tags", "note"}].
// "kind" is optional and checked against the detected kind.
type jsonItem struct {
	Value string   `json:"value"`
	Kind  Kind     `json:"kind"`
	Tags  []string `json:"tags"`
	Note  string   `json:"note"`
}

// ParseJSON parses a JSON array of {value, tags?, note?, kind?} objects.
func ParseJSON(data []byte) *Parsed {
	p := newParsed()
	lineAt := func(off int64) int {
		// skip the separator/whitespace before the element, then count lines
		for off < int64(len(data)) && bytes.IndexByte([]byte(" \t\r\n,"), data[off]) >= 0 {
			off++
		}
		return 1 + bytes.Count(data[:off], []byte("\n"))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		p.fail(lineAt(0), "expected a JSON array of {value, tags, note} objects")
		return p
	}
	for dec.More() {
		line := lineAt(dec.InputOffset())
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			p.fail(line, "invalid JSON: %v", err)
			return p
		}
		var it jsonItem
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&it); err != nil {
			p.fail(line, "invalid element: %v", err)
			continue
		}
		e, err := NewEntry(it.Value, it.Kind, it.Tags, it.Note)
		if err != nil {
			p.fail(line, "%v", err)
			continue
		}
		p.add(e)
	}
	if _, err := dec.Token(); err != nil {
		p.fail(lineAt(dec.InputOffset()), "invalid JSON: %v", err)
	}
	return p
}

// ParseUpload picks the format from the file name (.json / .csv) or, failing
// that, from the content (a leading '[' means JSON). It returns the parse
// result and the target source ("csv" or "json").
func ParseUpload(filename string, data []byte) (*Parsed, string) {
	name := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(name, ".json"):
		return ParseJSON(data), "json"
	case strings.HasSuffix(name, ".csv"), strings.HasSuffix(name, ".txt"):
		return ParseCSV(bytes.NewReader(data)), "csv"
	case bytes.HasPrefix(bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\ufeff"))), []byte("[")):
		return ParseJSON(data), "json"
	default:
		return ParseCSV(bytes.NewReader(data)), "csv"
	}
}
