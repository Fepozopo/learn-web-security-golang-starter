package mfa

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite" // Register the SQLite driver for the isolated test database.
)

// TestConsumeBackupCode verifies that only the owner can consume a code once.
func TestConsumeBackupCode(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`CREATE TABLE totp_backup_codes (user_id INTEGER, code_hash TEXT, used_at TEXT);
		INSERT INTO totp_backup_codes (user_id, code_hash) VALUES
		(1, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');`)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, nil)
	cases := []struct {
		name   string
		userID int64
		code   string
		want   bool
	}{
		{"wrong user", 2, "abc", false},
		{"empty code", 1, "", false},
		{"unknown code", 1, "other", false},
		{"unused code", 1, "abc", true},
		{"used code", 1, "abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.ConsumeBackupCode(context.Background(), tc.userID, tc.code)
			if err != nil || got != tc.want {
				t.Fatalf("ConsumeBackupCode(userID=%d, code=%q) = %v, %v; want %v, nil", tc.userID, tc.code, got, err, tc.want)
			}
		})
	}
}
