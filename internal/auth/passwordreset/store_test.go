package passwordreset

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	// Register the SQLite driver used by the password reset store.
	_ "modernc.org/sqlite"
)

// TestCreate verifies token encoding, hash-only storage, and the expiration boundary.
func TestCreate(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.ExecContext(ctx, `CREATE TABLE password_reset_tokens (
		id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE,
		expires_at TEXT NOT NULL, used_at TEXT
	)`)
	if err != nil {
		t.Fatalf("create token table: %v", err)
	}

	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store := NewStore(db)
	store.now = func() time.Time { return now }
	token, err := store.Create(ctx, 42)
	if err != nil {
		t.Fatalf("create token for user 42: %v", err)
	}
	decoded, err := hex.DecodeString(token.Value)
	if err != nil || len(decoded) != 32 || token.Value != hex.EncodeToString(decoded) {
		t.Fatalf("token %q: expected 32 lowercase hexadecimal bytes, got %d bytes and error %v", token.Value, len(decoded), err)
	}
	var storedHash string
	if err := db.QueryRowContext(ctx, "SELECT token_hash FROM password_reset_tokens WHERE id = ?", token.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read token %d: %v", token.ID, err)
	}
	digest := sha256.Sum256([]byte(token.Value))
	if expected := fmt.Sprintf("%x", digest); storedHash != expected || storedHash == token.Value {
		t.Errorf("stored hash for token %q: got %q, want SHA-256 %q", token.Value, storedHash, expected)
	}
	if expected := now.Add(15 * time.Minute); !token.ExpiresAt.Equal(expected) {
		t.Errorf("expiration for token %q: got %v, want %v", token.Value, token.ExpiresAt, expected)
	}

	for _, tc := range []struct {
		name string
		time time.Time
		want bool
	}{
		{"before expiration", now.Add(15*time.Minute - time.Millisecond), true},
		{"at expiration", now.Add(15 * time.Minute), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store.now = func() time.Time { return tc.time }
			_, found, err := store.Validate(ctx, token.Value)
			if err != nil || found != tc.want {
				t.Errorf("validate at %v: got found=%v error=%v, want found=%v and no error", tc.time, found, err, tc.want)
			}
		})
	}
}
