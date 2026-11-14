package uploads

import (
	"strings"
	"testing"
	"time"
)

// TestSignedDownloadPath checks the signed URL against an independent HMAC-SHA-256 vector.
func TestSignedDownloadPath(t *testing.T) {
	got := CreateSignedDownloadPath([32]byte{}, 42, time.Unix(1700000000, 0))
	want := "/files/42/signed-download?expires=1700000300&signature=2c72d20197c70587a054f5fd00132b1a1ae2665e139ac718d2abd73535ffbd91"
	if got != want {
		t.Errorf("CreateSignedDownloadPath with file 42 = %q, want %q", got, want)
	}
}

// TestVerifySignedDownload checks authentication, expiration, and malformed inputs.
func TestVerifySignedDownload(t *testing.T) {
	const signature = "2c72d20197c70587a054f5fd00132b1a1ae2665e139ac718d2abd73535ffbd91"
	otherKey := [32]byte{1}
	tests := []struct {
		name      string
		key       [32]byte
		fileID    int64
		expires   string
		signature string
		now       int64
		want      bool
	}{
		{"valid", [32]byte{}, 42, "1700000300", signature, 1700000000, true},
		{"uppercase hex", [32]byte{}, 42, "1700000300", strings.ToUpper(signature), 1700000000, true},
		{"wrong key", otherKey, 42, "1700000300", signature, 1700000000, false},
		{"wrong file", [32]byte{}, 43, "1700000300", signature, 1700000000, false},
		{"modified expiration", [32]byte{}, 42, "1700000301", signature, 1700000000, false},
		{"modified signature", [32]byte{}, 42, "1700000300", "0" + signature[1:], 1700000000, false},
		{"invalid hex", [32]byte{}, 42, "1700000300", strings.Repeat("z", 64), 1700000000, false},
		{"empty signature", [32]byte{}, 42, "1700000300", "", 1700000000, false},
		{"short signature", [32]byte{}, 42, "1700000300", signature[:63], 1700000000, false},
		{"empty expiration", [32]byte{}, 42, "", signature, 1700000000, false},
		{"invalid expiration", [32]byte{}, 42, "-1", signature, 1700000000, false},
		{"overflow expiration", [32]byte{}, 42, "99999999999999999999", signature, 1700000000, false},
		{"expiration boundary", [32]byte{}, 42, "1700000300", signature, 1700000300, false},
		{"expired", [32]byte{}, 42, "1700000300", signature, 1700000301, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifySignedDownload(tt.key, tt.fileID, tt.expires, tt.signature, time.Unix(tt.now, 0))
			if got != tt.want {
				t.Errorf("VerifySignedDownload(key=%x, fileID=%d, expires=%q, signature=%q, now=%d) = %t, want %t", tt.key, tt.fileID, tt.expires, tt.signature, tt.now, got, tt.want)
			}
		})
	}
}
