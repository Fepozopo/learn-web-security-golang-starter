package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storefront"
)

// TestPublicResponses verifies the public API exposes only its intended fields and active products.
func TestPublicResponses(t *testing.T) {
	ctx := t.Context()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO users (id, email, display_name, role, password_hash) VALUES (1, 'owner@example.com', 'Owner', 'customer', 'unused');
		INSERT INTO products (id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active) VALUES
		(1, 'Bear', 'A bear', '/bear.png', 500, 200, 4, 1),
		(2, 'Hidden', 'Inactive', '/hidden.png', 100, 50, 1, 0);
		INSERT INTO orders (id, user_id, status, total_cents, admin_notes, shipping_details_encrypted, created_at) VALUES
		(10, 1, 'paid', 1000, 'private note', 'private ciphertext', '2024-01-01');
		INSERT INTO order_items (order_id, product_id, quantity, price_cents) VALUES (10, 1, 2, 500)`)
	if err != nil {
		t.Fatal(err)
	}
	accountStore := accounts.NewStore(db)
	session, err := accountStore.CreateSession(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(accountStore, orders.NewStore(db), storefront.NewStore(db), nil, nil, 10)
	for _, tc := range []struct {
		name, path, id, want string
		handle               http.HandlerFunc
	}{
		{name: "products", path: "/api/products", handle: handler.Products, want: `{"products":[{"id":1,"name":"Bear","description":"A bear","image_path":"/bear.png","price_cents":500}]}`},
		{name: "account orders", path: "/api/account/orders", handle: handler.AccountOrders, want: `{"orders":[{"id":10,"status":"paid","total_cents":1000,"created_at":"2024-01-01"}]}`},
		{name: "order detail", path: "/api/orders/10", id: "10", handle: handler.Order, want: `{"order":{"id":10,"status":"paid","total_cents":1000,"created_at":"2024-01-01"},"items":[{"product_id":1,"product_name":"Bear","quantity":2,"price_cents":500}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.SetPathValue("id", tc.id)
			req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: session.Token})
			response := httptest.NewRecorder()
			tc.handle(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s: status = %d, want 200; body = %s", tc.path, response.Code, response.Body.String())
			}
			var got, want any
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatalf("GET %s: invalid JSON: %v", tc.path, err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("GET %s: body = %s, want %s", tc.path, response.Body.String(), tc.want)
			}
		})
	}
}
