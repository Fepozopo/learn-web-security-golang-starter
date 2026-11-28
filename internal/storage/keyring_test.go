package storage

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestKeyringRotation verifies new writes use the active key while old data remains readable.
func TestKeyringRotation(t *testing.T) {
	keys := map[string][32]byte{"v1": {1}, "v2": {2}}
	old, err := NewKeyring("v1", keys)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewKeyring("v2", keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		writer  *Keyring
		version string
	}{
		{"old", old, "v1"}, {"new", rotated, "v2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serialized, err := tc.writer.Encrypt([]byte("sensitive secret"))
			if err != nil {
				t.Fatalf("Encrypt with %s: %v", tc.version, err)
			}
			var fields struct {
				KeyVersion string `json:"keyVersion"`
			}
			if err := json.Unmarshal([]byte(serialized), &fields); err != nil {
				t.Fatalf("invalid serialized payload: %v", err)
			}
			if fields.KeyVersion != tc.version || strings.Contains(serialized, "sensitive secret") {
				t.Fatalf("Encrypt with %s: got version %q or exposed plaintext: %q", tc.version, fields.KeyVersion, serialized)
			}
			plaintext, err := rotated.Decrypt(serialized)
			if err != nil || string(plaintext) != "sensitive secret" {
				t.Fatalf("rotated Decrypt(%s) = %q, %v; want original plaintext", tc.version, plaintext, err)
			}
		})
	}
	serialized, err := old.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	withoutOld, err := NewKeyring("v2", map[string][32]byte{"v2": {2}})
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := withoutOld.Decrypt(serialized); err == nil || plaintext != nil {
		t.Fatalf("Decrypt without v1 = %q, %v; want nil and error", plaintext, err)
	}
}

// TestKeyringRejectsInvalidInputs verifies failures do not return plaintext or ciphertext.
func TestKeyringRejectsInvalidInputs(t *testing.T) {
	var missing *Keyring
	if got, err := missing.Encrypt([]byte("secret")); err == nil || got != "" {
		t.Fatalf("nil keyring Encrypt = %q, %v; want empty and error", got, err)
	}
	if got, err := missing.Decrypt("invalid"); err == nil || got != nil {
		t.Fatalf("nil keyring Decrypt = %q, %v; want nil and error", got, err)
	}
	keyring, err := NewKeyring("v1", map[string][32]byte{"v1": {1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "not json", `{"keyVersion":"v1"}`} {
		if got, err := keyring.Decrypt(value); err == nil || got != nil {
			t.Errorf("Decrypt(%q) = %q, %v; want nil and error", value, got, err)
		}
	}
	serialized, err := keyring.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := NewKeyring("v1", map[string][32]byte{"v1": {2}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := wrong.Decrypt(serialized); err == nil || got != nil {
		t.Fatalf("Decrypt with wrong key = %q, %v; want nil and error", got, err)
	}
}
