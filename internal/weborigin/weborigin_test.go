package weborigin

import (
	"net/url"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for _, origin := range []string{"https://verifier.example", "https://verifier.example:8443", "http://localhost:8080", "https://[::1]:8443", "https://xn--bcher-kva.example"} {
		if err := Check(origin); err != nil {
			t.Errorf("%q: %v", origin, err)
		}
	}
	for name, origin := range map[string]string{
		"empty":             "",
		"no scheme":         "verifier.example",
		"a trailing slash":  "https://verifier.example/",
		"a path":            "https://verifier.example/app",
		"a query":           "https://verifier.example?x=1",
		"an empty query":    "https://verifier.example?",
		"a fragment":        "https://verifier.example#x",
		"an empty fragment": "https://verifier.example#",
		"userinfo":          "https://u@verifier.example",
		"opaque":            "https:verifier.example",
		"uppercase scheme":  "HTTPS://verifier.example",
		"uppercase host":    "https://Verifier.example",
		"a Unicode host":    "https://bücher.example",
		"an empty port":     "https://verifier.example:",
		"a padded port":     "https://verifier.example:08443",
		"a default port":    "https://verifier.example:443",
		"not a URL":         "https://verifier.example:port",
	} {
		if err := Check(origin); err == nil {
			t.Errorf("%s (%q): accepted", name, origin)
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://Verifier.Example:443/": "https://verifier.example",
		"http://LOCALHOST:80":           "http://localhost",
		"https://verifier.example:8443": "https://verifier.example:8443",
		"https://verifier.example/app":  "https://verifier.example/app",
		"verifier.example":              "verifier.example",
		"https://verifier.example#":     "https://verifier.example#",
		"https://verifier.example?":     "https://verifier.example?",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckPage(t *testing.T) {
	for _, tc := range []struct {
		origin   string
		loopback bool
		ok       bool
	}{
		{"https://verifier.example", false, true},
		{"http://localhost:8080", true, true},
		{"http://127.0.0.1:8080", true, true},
		{"http://[::1]:8080", true, true},
		{"http://localhost:8080", false, false},
		{"http://verifier.example", true, false},
		{"ftp://verifier.example", true, false},
		{"https://verifier.example/", true, false},
	} {
		if err := CheckPage(tc.origin, tc.loopback); (err == nil) != tc.ok {
			t.Errorf("CheckPage(%q, %v) = %v, want ok %v", tc.origin, tc.loopback, err, tc.ok)
		}
	}
	got, err := NormalizeAll([]string{"HTTPS://Verifier.Example/", "http://localhost:80"}, true)
	if err != nil || len(got) != 2 || got[0] != "https://verifier.example" || got[1] != "http://localhost" {
		t.Errorf("NormalizeAll = %q, %v", got, err)
	}
	if got, err := NormalizeAll(nil, false); got != nil || err != nil {
		t.Errorf("NormalizeAll(nil) = %q, %v, want nil", got, err)
	}
	if _, err := NormalizeAll([]string{"https://verifier.example", "http://localhost"}, false); err == nil {
		t.Error("NormalizeAll with a loopback http origin, not allowed: accepted")
	}
}

// An origin Normalize returns that CheckPage accepts is a fixed point of
// Normalize, and names the host its input did: normalizing never turns
// one page's origin into another's.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{
		"https://Example.COM:443/", "http://127.0.0.1:80", "https://[::1]:443", "https://a.example:8443",
		"https://xn--bcher-kva.example", "https://bücher.example", "https://a.example:", "https://a.example:0443",
		"https://u@a.example", "https://a.example/%2F", "https://a.example?", "https:a.example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n := Normalize(s)
		if CheckPage(n, true) != nil {
			return
		}
		if again := Normalize(n); again != n {
			t.Fatalf("not a fixed point: %q -> %q -> %q", s, n, again)
		}
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("%q doesn't parse but normalized to the accepted %q", s, n)
		}
		v, err := url.Parse(n)
		if err != nil || !strings.EqualFold(u.Hostname(), v.Hostname()) {
			t.Fatalf("the host changed: %q -> %q", s, n)
		}
	})
}
