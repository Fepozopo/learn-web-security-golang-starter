package httpx_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// TestErrorResponses checks that server errors hide details and preserve status codes.
func TestErrorResponses(t *testing.T) {
	renderer, err := templates.Load("../../web/templates")
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}

	const title = "Diagnostic title"
	const message = "Sensitive diagnostic"
	cases := []struct {
		name    string
		status  int
		title   string
		message string
	}{
		{"below boundary", 499, title, message},
		{"boundary", 500, "Something Went Wrong", "The request failed. Try again, or return to the store."},
		{"service unavailable", 503, "Something Went Wrong", "The request failed. Try again, or return to the store."},
		{"upper boundary", 599, "Something Went Wrong", "The request failed. Try again, or return to the store."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("JSON", func(t *testing.T) {
				response := httptest.NewRecorder()
				httpx.RespondWithError(response, tc.status, message)
				var body map[string]string
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("status %d: invalid JSON %q: %v", tc.status, response.Body.String(), err)
				}
				if response.Code != tc.status || body["error"] != tc.message {
					t.Errorf("status %d: got status %d and message %q, want status %d and message %q", tc.status, response.Code, body["error"], tc.status, tc.message)
				}
			})
			t.Run("page", func(t *testing.T) {
				response := httptest.NewRecorder()
				if err := httpx.RespondWithErrorPage(response, renderer, tc.status, title, message); err != nil {
					t.Fatalf("status %d: render error page: %v", tc.status, err)
				}
				body := response.Body.String()
				if response.Code != tc.status || !strings.Contains(body, tc.title) || !strings.Contains(body, tc.message) {
					t.Errorf("status %d: got status %d and body %q, want status %d with title %q and message %q", tc.status, response.Code, body, tc.status, tc.title, tc.message)
				}
				if tc.status >= 500 && (strings.Contains(body, title) || strings.Contains(body, message)) {
					t.Errorf("status %d: page exposed diagnostic title or message: %q", tc.status, body)
				}
			})
		})
	}
}
