package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const (
	gcmNonceSize = 12
	gcmTagSize   = 16
)

// EncryptedPayload holds an AES-256-GCM ciphertext and its nonce and authentication tag.
type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

// Encrypt encrypts plaintext with key using AES-256-GCM and a fresh random nonce.
// It returns the ciphertext and authentication tag separately, or an error.
func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	tagStart := len(sealed) - gcmTagSize
	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    sealed[tagStart:],
		Ciphertext: sealed[:tagStart:tagStart],
	}, nil
}

// Decrypt authenticates and decrypts payload with key using AES-256-GCM.
// It returns the plaintext, or an error for malformed or unauthentic payloads.
func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != gcmNonceSize || len(payload.AuthTag) != gcmTagSize {
		return nil, fmt.Errorf("invalid AES-GCM nonce or authentication tag length")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	// Allocate a new buffer so appending the tag cannot modify the caller's ciphertext.
	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)
	plaintext, err := gcm.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("authenticate and decrypt payload: %w", err)
	}
	return plaintext, nil
}
