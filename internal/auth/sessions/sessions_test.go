package sessions

import "testing"

// TestCSRFTokensMatch checks equality, length differences, and empty tokens.
func TestCSRFTokensMatch(t *testing.T) {
	for _, tc := range []struct {
		name, expected, actual string
		want                   bool
	}{
		{name: "equal", expected: "token", actual: "token", want: true},
		{name: "different same length", expected: "token", actual: "Token"},
		{name: "different lengths", expected: "token", actual: "tokens"},
		{name: "missing", expected: "token", actual: ""},
		{name: "both empty", expected: "", actual: "", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CSRFTokensMatch(tc.expected, tc.actual); got != tc.want {
				t.Errorf("CSRFTokensMatch(%q, %q) = %t; want %t", tc.expected, tc.actual, got, tc.want)
			}
		})
	}
}
