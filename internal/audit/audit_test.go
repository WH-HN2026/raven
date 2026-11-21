package audit

import (
	"strings"
	"testing"
)

func TestDiffRedactsSensitiveValues(t *testing.T) {
	const marker = "PLAINTEXT-MARKER"
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, `{}`},
		{"plain keys kept", map[string]any{"username": "ed", "role": "viewer"}, `{"role":"viewer","username":"ed"}`},
		{"notes", map[string]any{"notes": marker}, `{"notes":"[redacted]"}`},
		{"from/to object under notes", map[string]any{"notes": map[string]string{"from": marker, "to": marker}}, `{"notes":"[redacted]"}`},
		{"suffix match", map[string]any{"new_password": marker, "api_token": marker}, `{"api_token":"[redacted]","new_password":"[redacted]"}`},
		{"_enc column", map[string]any{"banner_enc": marker}, `{"banner_enc":"[redacted]"}`},
		{"nested in list", map[string]any{"fields": []any{map[string]any{"headers": marker}}}, `{"fields":[{"headers":"[redacted]"}]}`},
		{"bool marker kept", map[string]any{"notes": true, "password_reset": true}, `{"notes":true,"password_reset":true}`},
		{"case-insensitive", map[string]any{"Cookies": marker}, `{"Cookies":"[redacted]"}`},
		{"not a suffix match", map[string]any{"notesfield": "x", "keyword": "y"}, `{"keyword":"y","notesfield":"x"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Diff(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("Diff = %s, want %s", got, tt.want)
			}
			if strings.Contains(string(got), marker) {
				t.Errorf("marker leaked: %s", got)
			}
		})
	}
}
