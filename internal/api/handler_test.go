package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/orders"
)

// TestOrderOwnership verifies that only the owner can retrieve an order.
func TestOrderOwnership(t *testing.T) {
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
	handler := NewHandler(accountStore, orders.NewStore(db), nil, nil, nil, 0)
	for _, tc := range []struct {
		name, id, token string
		status          int
	}{
		{name: "owner", id: "10", token: owner.Token, status: http.StatusOK},
		{name: "other user", id: "10", token: other.Token, status: http.StatusNotFound},
		{name: "missing order", id: "999", token: owner.Token, status: http.StatusNotFound},
		{name: "invalid order", id: "invalid", token: owner.Token, status: http.StatusNotFound},
		{name: "unauthenticated", id: "10", status: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/orders/"+tc.id, nil)
			req.SetPathValue("id", tc.id)
			if tc.token != "" {
				req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: tc.token})
			}
			response := httptest.NewRecorder()
			handler.Order(response, req)
			if response.Code != tc.status {
				t.Fatalf("order %q: status = %d, want %d; body = %s", tc.id, response.Code, tc.status, response.Body.String())
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("order %q: invalid JSON response: %v", tc.id, err)
			}
			if tc.status == http.StatusNotFound {
				if len(body) != 1 || string(body["error"]) != `"Order not found"` {
					t.Errorf("order %q: body = %s, want {\"error\":\"Order not found\"}", tc.id, response.Body.String())
				}
			} else if tc.status == http.StatusOK {
				var order struct{ ID int64 }
				if err := json.Unmarshal(body["order"], &order); err != nil || order.ID != 10 {
					t.Errorf("order %q: order = %s, want order ID 10 (error: %v)", tc.id, body["order"], err)
				}
				if string(body["items"]) != "[]" {
					t.Errorf("order %q: items = %s, want []", tc.id, body["items"])
				}
			}
		})
	}
}

// TestWarehouseOrdersAuthorization checks that only active keys with the required scope can list orders.
func TestWarehouseOrdersAuthorization(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, key := range []struct {
		raw, scope string
		revoked    any
	}{
		{raw: "valid-key", scope: "orders:read"},
		{raw: "wrong-scope", scope: "catalog:read"},
		{raw: "revoked-key", scope: "orders:read", revoked: "2020-01-01T00:00:00Z"},
	} {
		digest := sha256.Sum256([]byte(key.raw))
		if _, err := db.ExecContext(ctx, "INSERT INTO api_keys (name, key_hash, scope, revoked_at) VALUES (?, ?, ?, ?)", key.raw, hex.EncodeToString(digest[:]), key.scope, key.revoked); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewHandler(nil, orders.NewStore(db), nil, NewStore(db), nil, 0)
	for _, tc := range []struct {
		name string
		key  string
		want int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "invalid", key: "unknown", want: http.StatusUnauthorized},
		{name: "revoked", key: "revoked-key", want: http.StatusUnauthorized},
		{name: "wrong scope", key: "wrong-scope", want: http.StatusForbidden},
		{name: "valid", key: "valid-key", want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/integrations/warehouse/orders", nil)
			req.Header.Set("X-API-Key", tc.key)
			response := httptest.NewRecorder()
			handler.WarehouseOrders(response, req)
			if response.Code != tc.want {
				t.Fatalf("key %q: status = %d, want %d; body = %s", tc.key, response.Code, tc.want, response.Body.String())
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("key %q: invalid JSON response: %v", tc.key, err)
			}
			if tc.want != http.StatusOK {
				var message string
				if err := json.Unmarshal(body["error"], &message); err != nil || message == "" {
					t.Errorf("key %q: error = %s, want a nonempty JSON error message", tc.key, body["error"])
				}
			} else if string(body["orders"]) != "[]" {
				t.Errorf("key %q: orders = %s, want []", tc.key, body["orders"])
			}
		})
	}
}
