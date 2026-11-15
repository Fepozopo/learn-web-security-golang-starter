package uploads

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestIsInsideDirectory checks strict lexical containment, including sibling prefixes.
func TestIsInsideDirectory(t *testing.T) {
	tests := []struct {
		name, directory, candidate string
		want                       bool
	}{
		{"child", "root", "root/file", true},
		{"nested", "root", "root/sub/file", true},
		{"dot-dot prefix in name", "root", "root/..file", true},
		{"root", "root", "root", false},
		{"parent", "root/sub", "root", false},
		{"outside", "root", "other/file", false},
		{"sibling prefix", "root", "root-other/file", false},
		{"relative path error", "root", "/absolute/file", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInsideDirectory(tt.directory, tt.candidate); got != tt.want {
				t.Errorf("isInsideDirectory(%q, %q) = %t, want %t", tt.directory, tt.candidate, got, tt.want)
			}
		})
	}
}

// TestExtractTaxDocumentArchiveRejectsUnsafeEntries checks that no entries are written
// when a later entry violates the archive path policy.
func TestExtractTaxDocumentArchiveRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name, entry string
		mode        os.FileMode
	}{
		{"absolute", "/outside.txt", 0},
		{"backslash", `folder\outside.txt`, 0},
		{"traversal", "../outside.txt", 0},
		{"root", "folder/..", 0},
		{"symlink", "link", os.ModeSymlink | 0o777},
		{"ignored traversal", "__MACOSX/../../outside.txt", 0},
		{"ignored symlink", ".DS_Store", os.ModeSymlink | 0o777},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contents bytes.Buffer
			writer := zip.NewWriter(&contents)
			for _, header := range []*zip.FileHeader{{Name: "valid.txt"}, {Name: tt.entry}} {
				if header.Name == tt.entry {
					header.SetMode(tt.mode)
				}
				entry, err := writer.CreateHeader(header)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte("contents")); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			_, err := ExtractTaxDocumentArchive(nil, contents.Bytes(), directory)
			var archiveErr *ArchiveImportError
			if !errors.As(err, &archiveErr) || archiveErr.StatusCode != 400 {
				t.Fatalf("entry %q: error = %v, want ArchiveImportError with status 400", tt.entry, err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("entry %q: extraction directory contains %v, want no files", tt.entry, entries)
			}
		})
	}
}

// TestExtractTaxDocumentArchiveAcceptsNestedEntry checks that a safe document is extracted.
func TestExtractTaxDocumentArchiveAcceptsNestedEntry(t *testing.T) {
	var contents bytes.Buffer
	writer := zip.NewWriter(&contents)
	entry, err := writer.Create("nested/document.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("document")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive, err := ExtractTaxDocumentArchive(nil, contents.Bytes(), t.TempDir())
	if err != nil {
		t.Fatalf("extract safe archive: %v", err)
	}
	if len(archive.Documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(archive.Documents))
	}
	path := filepath.Join(archive.ImportDirectory, "nested", "document.txt")
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "document" {
		t.Errorf("read %q: got %q and error %v, want %q and no error", path, got, err, "document")
	}
}
