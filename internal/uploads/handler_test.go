package uploads

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// TestDownloadAccess verifies that only the owner and privileged users receive a download link.
func TestDownloadAccess(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO users (id, email, display_name, role, password_hash) VALUES
		(1, 'owner@example.com', 'Owner', 'customer', 'unused'),
		(2, 'other@example.com', 'Other', 'customer', 'unused'),
		(3, 'support@example.com', 'Support', 'support', 'unused'),
		(4, 'admin@example.com', 'Admin', 'admin', 'unused');
		INSERT INTO uploaded_files (id, user_id, original_name, storage_path, content_type)
		VALUES (10, 1, 'document.pdf', 'document.pdf', 'application/pdf')`)
	if err != nil {
		t.Fatal(err)
	}
	accountStore := accounts.NewStore(db)
	tokens := make(map[int64]string)
	for _, id := range []int64{1, 2, 3, 4} {
		session, err := accountStore.CreateSession(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		tokens[id] = session.Token
	}
	renderer, err := templates.Load(filepath.Join("..", "..", "web", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(accountStore, NewStore(db), renderer, nil, nil, "", 0, [32]byte{})

	for _, tc := range []struct {
		name   string
		userID int64
		fileID string
		status int
	}{
		{"owner", 1, "10", http.StatusFound},
		{"other customer", 2, "10", http.StatusNotFound},
		{"support", 3, "10", http.StatusFound},
		{"administrator", 4, "10", http.StatusFound},
		{"missing file", 1, "999", http.StatusNotFound},
		{"invalid file ID", 1, "invalid", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/uploads/"+tc.fileID, nil)
			req.SetPathValue("id", tc.fileID)
			req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: tokens[tc.userID]})
			response := httptest.NewRecorder()
			handler.Download(response, req)
			if response.Code != tc.status {
				t.Fatalf("user %d, file %q: status = %d, want %d", tc.userID, tc.fileID, response.Code, tc.status)
			}
			if tc.status == http.StatusFound && response.Header().Get("Location") == "" {
				t.Errorf("user %d, file %q: missing download redirect", tc.userID, tc.fileID)
			}
			if tc.status == http.StatusNotFound && (!strings.Contains(response.Body.String(), "File Not Found") || response.Header().Get("Location") != "") {
				t.Errorf("user %d, file %q: body = %q, location = %q; want File Not Found and no redirect", tc.userID, tc.fileID, response.Body.String(), response.Header().Get("Location"))
			}
		})
	}
}
