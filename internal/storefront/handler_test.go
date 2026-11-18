package storefront

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// TestProductEscapesStoredReview verifies that reloading a product renders stored markup as text.
func TestProductEscapesStoredReview(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	const payload = `<img src=x onerror=alert(1)>`
	_, err = db.ExecContext(ctx, `INSERT INTO users (id, email, display_name, role, password_hash) VALUES (1, 'reviewer@example.com', 'Reviewer', 'customer', 'unused');
		INSERT INTO products (id, name, description, image_path, price_cents, cost_cents) VALUES (1, 'Product', '', '', 100, 0);
		INSERT INTO reviews (user_id, product_id, rating, body) VALUES (1, 1, 5, ?)`, payload)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := templates.Load(filepath.Join("..", "..", "web", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(NewStore(db), accounts.NewStore(db), renderer, nil, 10)
	for reload := 0; reload < 2; reload++ {
		req := httptest.NewRequest(http.MethodGet, "/products/1", nil)
		req.SetPathValue("id", "1")
		response := httptest.NewRecorder()
		handler.Product(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, body = %q; want %d", reload, response.Code, response.Body.String(), http.StatusOK)
		}
		body := response.Body.String()
		if !strings.Contains(body, `&lt;img src=x onerror=alert(1)&gt;`) || strings.Contains(body, payload) {
			t.Errorf("request %d: response = %q; want escaped review %q and no raw markup", reload, body, payload)
		}
	}
}
