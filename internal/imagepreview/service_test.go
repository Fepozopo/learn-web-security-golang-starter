package imagepreview

import (
	"net/http"
	"testing"
)

func TestAllowedURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantURL string
	}{
		{name: "approved HTTPS host", rawURL: "https://storage.googleapis.com/example/image.png", wantURL: "https://storage.googleapis.com/example/image.png"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, valid := allowedURL(test.rawURL)
			if !valid || parsed.String() != test.wantURL {
				t.Fatalf("allowedURL(%q) = (%v, %t), want (%q, true)", test.rawURL, parsed, valid, test.wantURL)
			}
		})
	}
}

func TestAllowedURLRejectsDisallowedURLs(t *testing.T) {
	urls := []string{
		"://not-a-url",
		"http://storage.googleapis.com/image.png",
		"https://storage.googleapis.com.evil.example/image.png",
		"https://storage.googleapis.com:443/image.png",
		"https://user:password@storage.googleapis.com/image.png",
	}
	for _, rawURL := range urls {
		t.Run(rawURL, func(t *testing.T) {
			if _, valid := allowedURL(rawURL); valid {
				t.Errorf("allowedURL(%q) accepted a disallowed URL", rawURL)
			}
		})
	}
}

func TestFetchRejectsDisallowedURLWithPolicyMessage(t *testing.T) {
	_, err := NewService().Fetch(t.Context(), "http://storage.googleapis.com/image.png", 1024)
	imageError, ok := err.(*Error)
	if !ok || imageError.Message != "Use an HTTPS URL from an allowed image host." {
		t.Fatalf("Fetch() error = %v, want imagepreview.Error with policy message", err)
	}
}

func TestFetchReturnsRedirectWithoutReadingBody(t *testing.T) {
	service := &Service{client: redirectResponseClient{}}
	_, err := service.Fetch(t.Context(), "https://storage.googleapis.com/image.png", 1024)
	imageError, ok := err.(*Error)
	if !ok || imageError.Message != "Image URL redirects are not allowed." {
		t.Fatalf("Fetch() error = %v, want redirect rejection", err)
	}
}

type redirectResponseClient struct{}

// Do returns a redirect response whose body fails if Fetch attempts to read it.
func (redirectResponseClient) Do(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusFound,
		Header:     make(http.Header),
		Body:       unreadableBody{},
		Request:    request,
	}, nil
}

type unreadableBody struct{}

// Read panics so the redirect test fails if the response body is consumed.
func (unreadableBody) Read([]byte) (int, error) {
	panic("redirect response body was read")
}

// Close satisfies io.ReadCloser without consuming the response body.
func (unreadableBody) Close() error { return nil }
