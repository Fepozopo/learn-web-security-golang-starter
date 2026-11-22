package config

import (
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
		{name: "configured", environment: map[string]string{"PAWPAL_API_KEY": "test-key"}, wantKey: "test-key"},
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
