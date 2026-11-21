package auth

import "testing"

func TestHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := HashPassword("correct horse")
	if h == h2 {
		t.Fatal("hashes of the same password must differ (random salt)")
	}
	tests := []struct {
		name     string
		hash     string
		password string
		ok       bool
		wantErr  bool
	}{
		{"match", h, "correct horse", true, false},
		{"wrong password", h, "Correct horse", false, false},
		{"empty password", h, "", false, false},
		{"malformed hash", "plaintext", "correct horse", false, true},
		{"wrong algorithm", "$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA", "x", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := VerifyPassword(tt.hash, tt.password)
			if (err != nil) != tt.wantErr || ok != tt.ok {
				t.Fatalf("VerifyPassword = %v, %v; want %v, err=%v", ok, err, tt.ok, tt.wantErr)
			}
		})
	}
}
