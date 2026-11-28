package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParsePawPalAPIKey verifies that Parse requires and preserves the configured key.
func TestParsePawPalAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		wantKey     string
		wantError   bool
	}{
		{name: "missing", environment: nil, wantError: true},
		{name: "empty", environment: map[string]string{"PAWPAL_API_KEY": ""}, wantError: true},
		{name: "configured", environment: map[string]string{"PAWPAL_API_KEY": "test-key", "DOWNLOAD_SIGNING_KEY": strings.Repeat("ab", 32), "DATA_ENCRYPTION_ACTIVE_VERSION": "v1", "DATA_ENCRYPTION_KEY_V1": strings.Repeat("cd", 32)}, wantKey: "test-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.environment, t.TempDir())
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), "PAWPAL_API_KEY") {
					t.Fatalf("Parse(%v): got error %v, want error identifying PAWPAL_API_KEY", tt.environment, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%v): unexpected error: %v", tt.environment, err)
			}
			if got.PawPalAPIKey != tt.wantKey {
				t.Errorf("Parse(%v): got PawPalAPIKey %q, want %q", tt.environment, got.PawPalAPIKey, tt.wantKey)
			}
		})
	}
}

// TestParseTrustedProxyHops verifies the default, valid hop counts, and invalid values.
func TestParseTrustedProxyHops(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int
		invalid bool
	}{
		{name: "default", value: "", want: 0},
		{name: "zero", value: "0", want: 0},
		{name: "one proxy", value: "1", want: 1},
		{name: "multiple proxies", value: "2", want: 2},
		{name: "negative", value: "-1", invalid: true},
		{name: "not an integer", value: "1.5", invalid: true},
		{name: "overflow", value: "999999999999999999999999999999999", invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			environment := map[string]string{
				"PAWPAL_API_KEY":                 "test",
				"DOWNLOAD_SIGNING_KEY":           strings.Repeat("ab", 32),
				"TRUST_PROXY_HOPS":               tt.value,
				"DATA_ENCRYPTION_ACTIVE_VERSION": "v1",
				"DATA_ENCRYPTION_KEY_V1":         strings.Repeat("cd", 32),
			}
			got, err := Parse(environment, t.TempDir())
			if tt.invalid {
				if err == nil || !strings.Contains(err.Error(), "TRUST_PROXY_HOPS") {
					t.Fatalf("Parse TRUST_PROXY_HOPS=%q: got error %v, want TRUST_PROXY_HOPS validation error", tt.value, err)
				}
				return
			}
			if err != nil || got.TrustedProxyHops != tt.want {
				t.Fatalf("Parse TRUST_PROXY_HOPS=%q: got hops %d, error %v; want %d, nil", tt.value, got.TrustedProxyHops, err, tt.want)
			}
		})
	}
}

// TestParseDownloadSigningKey checks the required key's format and decoded value.
func TestParseDownloadSigningKey(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"missing", "", false},
		{"short", strings.Repeat("a", 63), false},
		{"long", strings.Repeat("a", 65), false},
		{"non-hex", strings.Repeat("z", 64), false},
		{"valid", strings.Repeat("ab", 32), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(map[string]string{"PAWPAL_API_KEY": "test", "DOWNLOAD_SIGNING_KEY": tt.value, "DATA_ENCRYPTION_ACTIVE_VERSION": "v1", "DATA_ENCRYPTION_KEY_V1": strings.Repeat("cd", 32)}, t.TempDir())
			if !tt.valid {
				if err == nil || !strings.Contains(err.Error(), "DOWNLOAD_SIGNING_KEY") {
					t.Fatalf("Parse key %q: got error %v, want DOWNLOAD_SIGNING_KEY error", tt.value, err)
				}
				return
			}
			var want [32]byte
			for i := range want {
				want[i] = 0xab
			}
			if err != nil || got.DownloadSigningKey != want {
				t.Fatalf("Parse key %q: got %x, error %v; want %x, nil", tt.value, got.DownloadSigningKey, err, want)
			}
		})
	}
}

// TestParseEncryptionKeys verifies encryption configuration is required and versioned keys are decoded.
func TestParseEncryptionKeys(t *testing.T) {
	for _, tc := range []struct {
		name      string
		version   string
		key       string
		wantError string
	}{
		{"missing configuration", "", "", "DATA_ENCRYPTION_ACTIVE_VERSION"},
		{"missing active key", "v1", "", "no encryption key configured for active version"},
		{"invalid key", "v1", "not-hex", "DATA_ENCRYPTION_KEY_V1"},
		{"valid", "V1", strings.Repeat("ab", 32), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"PAWPAL_API_KEY": "test", "DOWNLOAD_SIGNING_KEY": strings.Repeat("12", 32)}
			if tc.version != "" {
				env["DATA_ENCRYPTION_ACTIVE_VERSION"] = tc.version
			}
			if tc.key != "" {
				env["DATA_ENCRYPTION_KEY_V1"] = tc.key
			}
			got, err := Parse(env, t.TempDir())
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Parse %s: got %v; want error mentioning %s", tc.name, err, tc.wantError)
				}
				return
			}
			if err != nil || got.ActiveEncryptionKeyVersion != "v1" || got.EncryptionKeys["v1"] != [32]byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab} {
				t.Fatalf("Parse valid encryption configuration: got %+v, %v", got, err)
			}
		})
	}
}

// TestLoadEnvironment verifies local file loading, process precedence and file errors for both loaders.
func TestLoadEnvironment(t *testing.T) {
	for _, name := range []string{"PAWPAL_API_KEY", "DOWNLOAD_SIGNING_KEY", "ATTACKER_LAB_PORT", "DATA_ENCRYPTION_ACTIVE_VERSION", "DATA_ENCRYPTION_KEY_V1"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	content := "PAWPAL_API_KEY=file-key\nDOWNLOAD_SIGNING_KEY=" + strings.Repeat("12", 32) + "\nATTACKER_LAB_PORT=4141\nDATA_ENCRYPTION_ACTIVE_VERSION=v1\nDATA_ENCRYPTION_KEY_V1=" + strings.Repeat("56", 32) + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil || cfg.PawPalAPIKey != "file-key" || cfg.DownloadSigningKey[0] != 0x12 {
		t.Fatalf("Load file: got config %+v, error %v; want file key and signing key 12", cfg, err)
	}
	lab, err := LoadAttackerLab(dir)
	if err != nil || lab.Port != 4141 {
		t.Fatalf("LoadAttackerLab file: got %+v, error %v; want port 4141", lab, err)
	}
	t.Setenv("PAWPAL_API_KEY", "process-key")
	t.Setenv("ATTACKER_LAB_PORT", "4242")
	cfg, err = Load(dir)
	if err != nil || cfg.PawPalAPIKey != "process-key" {
		t.Fatalf("Load override: got %+v, error %v; want process-key", cfg, err)
	}
	lab, err = LoadAttackerLab(dir)
	if err != nil || lab.Port != 4242 {
		t.Fatalf("LoadAttackerLab override: got %+v, error %v; want port 4242", lab, err)
	}
	t.Setenv("DATA_ENCRYPTION_ACTIVE_VERSION", "v1")
	t.Setenv("DATA_ENCRYPTION_KEY_V1", strings.Repeat("56", 32))
	t.Setenv("DOWNLOAD_SIGNING_KEY", strings.Repeat("34", 32))
	cfg, err = Load(t.TempDir())
	if err != nil || cfg.DownloadSigningKey[0] != 0x34 {
		t.Fatalf("Load missing file: got %+v, error %v; want process signing key 34", cfg, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("invalid line without equals\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load malformed file: got nil error, want parse error")
	}
	if _, err := LoadAttackerLab(dir); err == nil {
		t.Fatal("LoadAttackerLab malformed file: got nil error, want parse error")
	}
}
