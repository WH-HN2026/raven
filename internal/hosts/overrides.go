package hosts

import (
	"encoding/json"
	"strings"
)

// ServiceFields are the scan-owned service fields a user can override
// (services.overrides keys).
type ServiceFields struct {
	Name    string `json:"name"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// applyServiceOverrides layers services.overrides on top of the scan values
// (architecture §5): a string value under name/product/version replaces the
// scan value. It returns the effective values and the overridden field names
// (in name, product, version order). Other keys and non-string values are
// ignored; malformed JSON means no overrides.
func applyServiceOverrides(scan ServiceFields, overrides []byte) (ServiceFields, []string) {
	eff, fields := scan, []string{}
	var m map[string]any
	if len(overrides) == 0 || json.Unmarshal(overrides, &m) != nil {
		return eff, fields
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"name", &eff.Name}, {"product", &eff.Product}, {"version", &eff.Version}} {
		if v, ok := m[f.key].(string); ok {
			*f.dst = v
			fields = append(fields, f.key)
		}
	}
	return eff, fields
}

// objectOrEmpty returns a JSON object for the API: overrides are always an
// object, never null.
func objectOrEmpty(b []byte) json.RawMessage {
	if len(b) == 0 || strings.TrimSpace(string(b)) == "null" {
		return json.RawMessage("{}")
	}
	return json.RawMessage(b)
}

// decodeHeaders turns decrypted headers into a map. The canonical format
// (written by the nuclei ingest) is a JSON object of strings; a raw
// "Name: value" header block is accepted too.
func decodeHeaders(s string) map[string]string {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) == nil {
		for k, v := range m {
			switch x := v.(type) {
			case string:
				out[k] = x
			case []any:
				var parts []string
				for _, p := range x {
					if ps, ok := p.(string); ok {
						parts = append(parts, ps)
					}
				}
				out[k] = strings.Join(parts, ", ")
			default:
				if b, err := json.Marshal(x); err == nil {
					out[k] = string(b)
				}
			}
		}
		return out
	}
	for line := range strings.SplitSeq(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if prev, dup := out[k]; dup {
			v = prev + ", " + v
		}
		out[k] = v
	}
	return out
}

// decodeStrings turns decrypted cookies (a JSON array of strings, or one per
// line) and redirects (a JSON array of strings) into a slice.
func decodeStrings(s string) []string {
	out := []string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	var arr []any
	if json.Unmarshal([]byte(s), &arr) == nil {
		for _, v := range arr {
			switch x := v.(type) {
			case string:
				out = append(out, x)
			default:
				if b, err := json.Marshal(x); err == nil {
					out = append(out, string(b))
				}
			}
		}
		return out
	}
	for line := range strings.SplitSeq(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
