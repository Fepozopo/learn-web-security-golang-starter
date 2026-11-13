package checkout

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/cart"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storage"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// TestSubmitIgnoresDiscount verifies that submitted discounts cannot change the persisted cart total.
func TestSubmitIgnoresDiscount(t *testing.T) {
	for _, tc := range []struct {
		name     string
		discount string
	}{
		{name: "zero", discount: "0"},
		{name: "positive", discount: "2500"},
		{name: "negative", discount: "-2500"},
		{name: "invalid", discount: "not-a-number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			db, err := database.Open(ctx, filepath.Join(dir, "test.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			if err := database.Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			_, err = db.ExecContext(ctx, `INSERT INTO users (id, email, display_name, role, password_hash) VALUES (1, 'buyer@example.com', 'Buyer', 'customer', 'unused');
				INSERT INTO products (id, name, description, image_path, price_cents, cost_cents, inventory_count) VALUES
				(1, 'Bear', '', '', 1200, 0, 10), (2, 'Honey', '', '', 350, 0, 10);
				INSERT INTO cart_items (user_id, product_id, quantity) VALUES (1, 1, 2), (1, 2, 1)`)
			if err != nil {
				t.Fatal(err)
			}
			accountStore := accounts.NewStore(db)
			session, err := accountStore.CreateSession(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			keyring, err := storage.NewKeyring("v1", map[string][32]byte{"v1": {}})
			if err != nil {
				t.Fatal(err)
			}
			logger, err := logging.Open(filepath.Join(dir, "app.log"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = logger.Close() })
			renderer, err := templates.Load(filepath.Join("..", "..", "web", "templates"))
			if err != nil {
				t.Fatal(err)
			}
			handler := NewHandler(cart.NewStore(db), orders.NewStore(db), accountStore, keyring, renderer, logger, 0)
			form := url.Values{
				"shippingName": {"Buyer"}, "shippingAddress": {"1 Main St"},
				"shippingCity": {"Town"}, "shippingRegion": {"CA"}, "shippingPostalCode": {"12345"},
				"discountCents": {tc.discount},
			}
			req := httptest.NewRequest(http.MethodPost, "/checkout", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: session.Token})
			response := httptest.NewRecorder()
			handler.Submit(response, req)
			if response.Code != http.StatusFound {
				t.Fatalf("discount %q: status = %d, body = %q; want %d", tc.discount, response.Code, response.Body.String(), http.StatusFound)
			}
			var total int64
			if err := db.QueryRowContext(ctx, "SELECT total_cents FROM orders WHERE user_id = 1").Scan(&total); err != nil {
				t.Fatal(err)
			}
			if total != 2750 {
				t.Errorf("discount %q: order total = %d cents; want 2750", tc.discount, total)
			}
		})
	}
}
