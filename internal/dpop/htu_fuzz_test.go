package dpop

import "testing"

// FuzzSameTarget checks the htu comparison on arbitrary pairs: it never
// panics, is symmetric, and a URI it takes names itself.
func FuzzSameTarget(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://issuer.example.com/token", "https://ISSUER.example.com:443/token?x#y"},
		{"https://issuer.example.com/a/../token", "https://issuer.example.com/%74oken"},
		{"http://[::1]:80/token", "http://[::1]/token"},
		{"https://issuer.example.com", "https://issuer.example.com/"},
		{"/token", "https://issuer.example.com/token"},
		{"https://%zz/", "https://x/%"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := sameTarget(a, b), sameTarget(b, a)
		if ab != ba {
			t.Fatalf("sameTarget(%q, %q) = %v, but reversed = %v", a, b, ab, ba)
		}
		if _, ok := parseHTTPURL(a); ok && !sameTarget(a, a) {
			t.Fatalf("sameTarget(%q, itself) = false", a)
		}
	})
}
