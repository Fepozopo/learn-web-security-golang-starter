package orders

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

// TestDetailOwnership verifies that order details are visible only to their owner.
func TestDetailOwnership(t *testing.T) {
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
		(2, 'other@example.com', 'Other', 'customer', 'unused');
		INSERT INTO orders (id, user_id, status, total_cents) VALUES (10, 1, 'paid', 1234)`)
	if err != nil {
		t.Fatal(err)
	}
	accountStore := accounts.NewStore(db)
	owner, err := accountStore.CreateSession(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := accountStore.CreateSession(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := templates.Load(filepath.Join("..", "..", "web", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(NewStore(db), accountStore, renderer, nil)

	for _, tc := range []struct {
		name, id, token, text string
		status                int
	}{
		{name: "owner", id: "10", token: owner.Token, status: http.StatusOK, text: "Order #10"},
		{name: "other user", id: "10", token: other.Token, status: http.StatusNotFound, text: "Order Not Found"},
		{name: "missing order", id: "999", token: owner.Token, status: http.StatusNotFound, text: "Order Not Found"},
		{name: "invalid order", id: "invalid", token: owner.Token, status: http.StatusNotFound, text: "Order Not Found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/orders/"+tc.id, nil)
			req.SetPathValue("id", tc.id)
			req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: tc.token})
			response := httptest.NewRecorder()
			handler.Detail(response, req)
			if response.Code != tc.status || !strings.Contains(response.Body.String(), tc.text) {
				t.Errorf("order %q: status = %d, body = %q; want status %d and body containing %q", tc.id, response.Code, response.Body.String(), tc.status, tc.text)
			}
		})
	}
}
