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

	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/orders"
)

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
