package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// TestContentSecurityPolicy checks the policy on responses from the next handler.
func TestContentSecurityPolicy(t *testing.T) {
	const want = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
	handler := contentSecurityPolicy(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := response.Result().Header.Get("Content-Security-Policy"); got != want {
		t.Errorf("Content-Security-Policy = %q; want %q", got, want)
	}
	if response.Code != http.StatusNoContent {
		t.Errorf("status = %d; want %d", response.Code, http.StatusNoContent)
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
