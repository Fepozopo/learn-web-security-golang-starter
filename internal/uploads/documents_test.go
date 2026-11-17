package uploads

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uuid"
)

// TestStoreDocument checks byte-based detection, UUID names, and rejection without writes.
func TestStoreDocument(t *testing.T) {
	tests := []struct {
		name, contents, contentType, extension string
	}{
		{"pdf", "%PDF-data", "application/pdf", ".pdf"},
		{"jpeg", "\xff\xd8\xffdata", "image/jpeg", ".jpg"},
		{"png", "\x89PNG\r\n\x1a\ndata", "image/png", ".png"},
		{"webp", "RIFF0000WEBPdata", "image/webp", ".webp"},
		{"empty", "", "", ""},
		{"truncated signature", "%PDF", "", ""},
		{"unsupported", "not a document", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "uploads")
			stored, valid, err := StoreDocument([]byte(tt.contents), directory, nil)
			if err != nil || valid != (tt.contentType != "") {
				t.Fatalf("StoreDocument(%q) = (%+v, %t, %v), want valid %t and no error", tt.contents, stored, valid, err, tt.contentType != "")
			}
			if !valid {
				if stored != (StoredDocument{}) {
					t.Errorf("unsupported contents returned metadata %+v, want empty", stored)
				}
				if _, err := os.Stat(directory); !os.IsNotExist(err) {
					t.Errorf("unsupported contents: directory stat error = %v, want not exist", err)
				}
				return
			}
			if stored.ContentType != tt.contentType || filepath.Dir(stored.StoragePath) != directory || filepath.Ext(stored.StoragePath) != tt.extension {
				t.Errorf("StoreDocument(%q) metadata = %+v, want type %q and path in %q with extension %q", tt.contents, stored, tt.contentType, directory, tt.extension)
			}
			name := strings.TrimSuffix(filepath.Base(stored.StoragePath), tt.extension)
			if _, err := uuid.Parse(name); err != nil {
				t.Errorf("storage name %q is not a UUID: %v", name, err)
			}
			got, err := os.ReadFile(stored.StoragePath)
			if err != nil || !bytes.Equal(got, []byte(tt.contents)) {
				t.Errorf("stored contents = %q, error = %v; want %q and no error", got, err, tt.contents)
			}
			again, _, err := StoreDocument([]byte(tt.contents), directory, nil)
			if err != nil || again.StoragePath == stored.StoragePath {
				t.Errorf("second storage path = %q, error = %v; want a different path from %q", again.StoragePath, err, stored.StoragePath)
			}
		})
	}
}
