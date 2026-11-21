package config

import "testing"

func TestLoadMaxWorkers(t *testing.T) {
	const encKey = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name    string
		val     string
		want    int
		wantErr bool
	}{
		{name: "default", val: "", want: 2},
		{name: "one", val: "1", want: 1},
		{name: "four", val: "4", want: 4},
		{name: "zero", val: "0", wantErr: true},
		{name: "negative", val: "-3", wantErr: true},
		{name: "not a number", val: "many", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("RAVEN_DATABASE_URL", "postgres://raven:pw@127.0.0.1:5433/raven")
			t.Setenv("RAVEN_ENCRYPTION_KEY", encKey)
			t.Setenv("RAVEN_MAX_WORKERS", tt.val)
			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() succeeded with MaxWorkers=%d, want error", cfg.MaxWorkers)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.MaxWorkers != tt.want {
				t.Fatalf("MaxWorkers = %d, want %d", cfg.MaxWorkers, tt.want)
			}
		})
	}
}

func TestLoadZAP(t *testing.T) {
	const encKey = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name    string
		url     string
		key     string
		wantURL string
		wantErr bool
	}{
		{name: "unset disables zap", url: "", key: "", wantURL: ""},
		{name: "valid trims slash", url: "http://zap:8080/", key: "secret", wantURL: "http://zap:8080"},
		{name: "missing key rejected", url: "http://zap:8080", key: "", wantErr: true},
		{name: "bad scheme rejected", url: "ftp://zap:8080", key: "secret", wantErr: true},
		{name: "missing host rejected", url: "http://", key: "secret", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("RAVEN_DATABASE_URL", "postgres://raven:pw@127.0.0.1:5433/raven")
			t.Setenv("RAVEN_ENCRYPTION_KEY", encKey)
			t.Setenv("RAVEN_ZAP_URL", tt.url)
			t.Setenv("RAVEN_ZAP_API_KEY", tt.key)
			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() succeeded with ZAPURL=%q, want error", cfg.ZAPURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.ZAPURL != tt.wantURL || cfg.ZAPAPIKey != tt.key {
				t.Fatalf("got (%q, %q), want (%q, %q)", cfg.ZAPURL, cfg.ZAPAPIKey, tt.wantURL, tt.key)
			}
		})
	}
}
