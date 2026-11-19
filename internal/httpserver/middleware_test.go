package httpserver

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// TestSecurityHeaders checks the baseline, nonce propagation, and response forwarding.
func TestSecurityHeaders(t *testing.T) {
	var previousNonce string
	for _, status := range []int{http.StatusNoContent, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var nonce string
			handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nonce = httpx.CSPNonce(r.Context())
				w.WriteHeader(status)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			decoded, err := base64.StdEncoding.DecodeString(nonce)
			if err != nil || len(decoded) != 16 || nonce == previousNonce {
				t.Errorf("status %d: nonce = %q, decoded length = %d, error = %v; want a fresh base64-encoded 16-byte nonce", status, nonce, len(decoded), err)
			}
			previousNonce = nonce
			for header, want := range map[string]string{
				"Content-Security-Policy":           "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self'; img-src 'self' data:; frame-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
				"Referrer-Policy":                   "strict-origin-when-cross-origin",
				"X-Content-Type-Options":            "nosniff",
				"X-Frame-Options":                   "SAMEORIGIN",
				"Cross-Origin-Opener-Policy":        "same-origin",
				"Cross-Origin-Resource-Policy":      "same-origin",
				"Origin-Agent-Cluster":              "?1",
				"X-DNS-Prefetch-Control":            "off",
				"X-Download-Options":                "noopen",
				"X-Permitted-Cross-Domain-Policies": "none",
				"X-XSS-Protection":                  "0",
			} {
				if got := response.Result().Header.Get(header); got != want {
					t.Errorf("status %d: %s = %q; want %q", status, header, got, want)
				}
			}
			if response.Code != status {
				t.Errorf("status = %d; want %d", response.Code, status)
			}
		})
	}
}

// TestStaticResourcePolicy verifies that only widget assets allow cross-origin loading.
func TestStaticResourcePolicy(t *testing.T) {
	root, err := os.OpenRoot("../../web/public")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	handler := securityHeaders(newStaticHandler(root))
	for _, tc := range []struct {
		method, path, policy string
		status               int
	}{
		{http.MethodGet, "/shipping-widget.css", "cross-origin", http.StatusOK},
		{http.MethodHead, "/shipping-widget.js", "cross-origin", http.StatusOK},
		{http.MethodGet, "/shipping-widget.js", "cross-origin", http.StatusOK},
		{http.MethodGet, "/shipping-widget.html", "same-origin", http.StatusOK},
		{http.MethodGet, "/styles.css", "same-origin", http.StatusOK},
		{http.MethodGet, "/missing.css", "same-origin", http.StatusNotFound},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
			if response.Code != tc.status {
				t.Errorf("%s %s: status = %d; want %d", tc.method, tc.path, response.Code, tc.status)
			}
			if got := response.Header().Get("Cross-Origin-Resource-Policy"); got != tc.policy {
				t.Errorf("%s %s: Cross-Origin-Resource-Policy = %q; want %q", tc.method, tc.path, got, tc.policy)
			}
		})
	}
}

// TestValidateSource checks source validation and whether the next handler runs.
func TestValidateSource(t *testing.T) {
	renderer, err := templates.Load("../../web/templates")
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}

	tests := []struct {
		name     string
		method   string
		origins  []string
		referers []string
		want     int
	}{
		{name: "GET without source", method: http.MethodGet, want: http.StatusNoContent},
		{name: "POST trusted origin", method: http.MethodPost, origins: []string{"https://example.com"}, want: http.StatusNoContent},
		{name: "POST trusted referer", method: http.MethodPost, referers: []string{"https://example.com/path?x=1"}, want: http.StatusNoContent},
		{name: "POST missing source", method: http.MethodPost, want: http.StatusForbidden},
		{name: "POST empty origin cannot fall back", method: http.MethodPost, origins: []string{""}, referers: []string{"https://example.com/"}, want: http.StatusForbidden},
		{name: "POST untrusted origin cannot fall back", method: http.MethodPost, origins: []string{"https://evil.example"}, referers: []string{"https://example.com/"}, want: http.StatusForbidden},
		{name: "POST duplicate origin", method: http.MethodPost, origins: []string{"https://example.com", "https://evil.example"}, want: http.StatusForbidden},
		{name: "POST origin with path", method: http.MethodPost, origins: []string{"https://example.com/path"}, want: http.StatusForbidden},
		{name: "POST null origin", method: http.MethodPost, origins: []string{"null"}, want: http.StatusForbidden},
		{name: "POST malformed referer", method: http.MethodPost, referers: []string{"https://example.com/%zz"}, want: http.StatusForbidden},
		{name: "POST relative referer", method: http.MethodPost, referers: []string{"/path"}, want: http.StatusForbidden},
		{name: "POST untrusted referer", method: http.MethodPost, referers: []string{"https://example.com.evil.example/"}, want: http.StatusForbidden},
		{name: "POST referer with userinfo", method: http.MethodPost, referers: []string{"https://user@example.com/"}, want: http.StatusForbidden},
		{name: "POST duplicate referer", method: http.MethodPost, referers: []string{"https://example.com/", "https://evil.example/"}, want: http.StatusForbidden},
		{name: "POST different port", method: http.MethodPost, referers: []string{"https://example.com:443/"}, want: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := validateSource("https://example.com", renderer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(test.method, "/", nil)
			for _, origin := range test.origins {
				request.Header.Add("Origin", origin)
			}
			for _, referer := range test.referers {
				request.Header.Add("Referer", referer)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || called != (test.want == http.StatusNoContent) {
				t.Errorf("method %q origins %q referers %q: status = %d, handler called = %t; want status %d, handler called = %t", test.method, test.origins, test.referers, response.Code, called, test.want, test.want == http.StatusNoContent)
			}
			if test.want == http.StatusForbidden && (!strings.Contains(response.Header().Get("Content-Type"), "text/html") || !strings.Contains(response.Body.String(), "Forbidden")) {
				t.Errorf("method %q origins %q referers %q: expected HTML forbidden page, got content type %q and body %q", test.method, test.origins, test.referers, response.Header().Get("Content-Type"), response.Body.String())
			}
		})
	}
}
