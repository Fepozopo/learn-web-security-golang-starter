package storage

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestEncryptDecrypt checks round trips, payload sizes, and fresh nonces.
func TestEncryptDecrypt(t *testing.T) {
	key := [32]byte{1, 2, 3}
	for _, tt := range []struct {
		name      string
		plaintext []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"binary", []byte{0, 1, 2, 255}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt(%x): unexpected error: %v", tt.plaintext, err)
			}
			if len(payload.Nonce) != 12 || len(payload.AuthTag) != 16 || len(payload.Ciphertext) != len(tt.plaintext) {
				t.Fatalf("Encrypt(%x): nonce/tag/ciphertext lengths = %d/%d/%d, want 12/16/%d", tt.plaintext, len(payload.Nonce), len(payload.AuthTag), len(payload.Ciphertext), len(tt.plaintext))
			}
			got, err := Decrypt(payload, key)
			if err != nil || !bytes.Equal(got, tt.plaintext) {
				t.Fatalf("Decrypt(Encrypt(%x)) = %x, %v; want %x, nil", tt.plaintext, got, err, tt.plaintext)
			}
			other, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("second Encrypt(%x): unexpected error: %v", tt.plaintext, err)
			}
			if bytes.Equal(payload.Nonce, other.Nonce) {
				t.Fatalf("Encrypt(%x) reused nonce %x", tt.plaintext, payload.Nonce)
			}
		})
	}
}

// TestDecryptKnownVector verifies compatibility with an AES-256-GCM test vector.
func TestDecryptKnownVector(t *testing.T) {
	tag, err := hex.DecodeString("530f8afbc74536b9a963b4f1c4cb738b")
	if err != nil {
		t.Fatal(err)
	}
	payload := EncryptedPayload{Nonce: make([]byte, 12), AuthTag: tag}
	got, err := Decrypt(payload, [32]byte{})
	if err != nil || len(got) != 0 {
		t.Fatalf("Decrypt(zero-key empty-message vector) = %x, %v; want empty plaintext, nil", got, err)
	}
}

// TestDecryptRejectsInvalidPayload verifies malformed and modified data is rejected.
func TestDecryptRejectsInvalidPayload(t *testing.T) {
	key := [32]byte{1}
	original, err := Encrypt([]byte("sensitive"), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		modify func(*EncryptedPayload, *[32]byte)
	}{
		{"missing nonce", func(p *EncryptedPayload, _ *[32]byte) { p.Nonce = nil }},
		{"short nonce", func(p *EncryptedPayload, _ *[32]byte) { p.Nonce = p.Nonce[:11] }},
		{"long nonce", func(p *EncryptedPayload, _ *[32]byte) { p.Nonce = append(p.Nonce, 0) }},
		{"missing tag", func(p *EncryptedPayload, _ *[32]byte) { p.AuthTag = nil }},
		{"short tag", func(p *EncryptedPayload, _ *[32]byte) { p.AuthTag = p.AuthTag[:15] }},
		{"long tag", func(p *EncryptedPayload, _ *[32]byte) { p.AuthTag = append(p.AuthTag, 0) }},
		{"modified nonce", func(p *EncryptedPayload, _ *[32]byte) { p.Nonce[0] ^= 1 }},
		{"modified tag", func(p *EncryptedPayload, _ *[32]byte) { p.AuthTag[0] ^= 1 }},
		{"modified ciphertext", func(p *EncryptedPayload, _ *[32]byte) { p.Ciphertext[0] ^= 1 }},
		{"wrong key", func(_ *EncryptedPayload, k *[32]byte) { k[0] ^= 1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := EncryptedPayload{
				Nonce:      bytes.Clone(original.Nonce),
				AuthTag:    bytes.Clone(original.AuthTag),
				Ciphertext: bytes.Clone(original.Ciphertext),
			}
			testKey := key
			tt.modify(&payload, &testKey)
			got, err := Decrypt(payload, testKey)
			if err == nil || got != nil {
				t.Fatalf("Decrypt(%s) = %x, %v; want nil plaintext and an error", tt.name, got, err)
			}
		})
	}
}
