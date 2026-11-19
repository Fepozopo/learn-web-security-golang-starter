package httpserver

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/storage"
)

// TestProductCORS verifies public product access without granting account or order APIs cross-origin access.
func TestProductCORS(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(t.Context(), filepath.Join(dir, "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO users (id, email, display_name, role, password_hash) VALUES (1, 'user@example.com', 'User', 'customer', 'unused');
		INSERT INTO orders (id, user_id, status, total_cents) VALUES (1, 1, 'paid', 100)`); err != nil {
		t.Fatal(err)
	}
	session, err := accounts.NewStore(db).CreateSession(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	logger, err := logging.Open(filepath.Join(dir, "test.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	keyring, err := storage.NewKeyring("v1", map[string][32]byte{"v1": {1}})
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(db, logger, Options{
		AppOrigin: "http://localhost:4000", MaxUploadBytes: 1024, MaxRequestBodyBytes: 1024,
		EncryptionKeyring: keyring, DataDirectory: dir,
		TemplateDirectory: filepath.Join("..", "..", "web", "templates"),
		PublicDirectory:   filepath.Join("..", "..", "web", "public"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })

	for _, tc := range []struct {
		name, method, path, origin, allowOrigin, allowMethods string
		status                                                int
	}{
		{name: "public products", method: "GET", path: "/api/products", origin: "https://attacker.example", allowOrigin: "*", status: http.StatusOK},
		{name: "products without origin", method: "GET", path: "/api/products", allowOrigin: "*", status: http.StatusOK},
		{name: "product preflight", method: "OPTIONS", path: "/api/products", origin: "https://attacker.example", allowOrigin: "*", allowMethods: "GET", status: http.StatusNoContent},
		{name: "account orders", method: "GET", path: "/api/account/orders", origin: "https://attacker.example", status: http.StatusOK},
		{name: "order", method: "GET", path: "/api/orders/1", origin: "https://attacker.example", status: http.StatusOK},
		{name: "account preflight", method: "OPTIONS", path: "/api/account/orders", origin: "https://attacker.example", status: http.StatusNotFound},
		{name: "order preflight", method: "OPTIONS", path: "/api/orders/1", origin: "https://attacker.example", status: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Access-Control-Request-Headers", "Authorization, X-Custom")
			req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: session.Token})
			response := httptest.NewRecorder()
			app.Handler.ServeHTTP(response, req)
			if response.Code != tc.status {
				t.Errorf("%s %s: status = %d, want %d; body = %s", tc.method, tc.path, response.Code, tc.status, response.Body.String())
			}
			for header, want := range map[string]string{"Access-Control-Allow-Origin": tc.allowOrigin, "Access-Control-Allow-Methods": tc.allowMethods} {
				if got := response.Header().Get(header); got != want {
					t.Errorf("%s %s: %s = %q, want %q", tc.method, tc.path, header, got, want)
				}
			}
			for _, header := range []string{"Access-Control-Allow-Credentials", "Access-Control-Allow-Headers"} {
				if _, present := response.Header()[http.CanonicalHeaderKey(header)]; present {
					t.Errorf("%s %s: unexpected %s header: %q", tc.method, tc.path, header, response.Header().Values(header))
				}
			}
			if tc.status == http.StatusNoContent && response.Body.Len() != 0 {
				t.Errorf("%s %s: body = %q, want empty", tc.method, tc.path, response.Body.String())
			}
		})
	}
}
