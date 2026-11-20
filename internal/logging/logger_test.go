package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestEventRedactsSensitiveFields checks the encoded record and the caller's fields.
func TestEventRedactsSensitiveFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	logger, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})

	fields := map[string]any{
		"sessionId": "session", "resetToken": "token", "resetLink": "link",
		"secret": nil, "adminNotes": 42, "storagePath": "/private/file",
		"SessionId": "different case", "nested": map[string]any{"secret": "nested value"},
	}
	if err := logger.Event("example", fields); err != nil {
		t.Fatalf("Event(example, %v): %v", fields, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Unmarshal(%q): %v", data, err)
	}
	for _, key := range []string{"sessionId", "resetToken", "resetLink", "secret", "adminNotes", "storagePath"} {
		if got := record[key]; got != "[REDACTED]" {
			t.Errorf("record[%q] = %v, want [REDACTED]", key, got)
		}
	}
	for key, want := range map[string]any{
		"event": "example", "SessionId": "different case", "nested": map[string]any{"secret": "nested value"},
	} {
		if got := record[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("record[%q] = %#v, want %#v", key, got, want)
		}
	}
	if got := fields["sessionId"]; got != "session" {
		t.Errorf("fields[sessionId] = %v after Event, want session", got)
	}
}
