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
			t.Setenv("ASI_DATABASE_URL", "postgres://asi:pw@127.0.0.1:5433/asi")
			t.Setenv("ASI_ENCRYPTION_KEY", encKey)
			t.Setenv("ASI_MAX_WORKERS", tt.val)
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
