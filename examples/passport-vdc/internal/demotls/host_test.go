package demotls

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// TestServedHosts: a loopback or unspecified listen address is served
// by this machine's loopback names for its port, and IPv6 loopback only
// when the address isn't IPv4's; a public URL adds its host, with the
// default port when it names none.
func TestServedHosts(t *testing.T) {
	for _, tc := range []struct {
		addr string
		urls []string
		want []string
	}{
		{"127.0.0.1:7443", nil, []string{"127.0.0.1:7443", "localhost:7443"}},
		{"127.0.0.1:7443", []string{"https://127.0.0.1:7443"}, []string{"127.0.0.1:7443", "localhost:7443"}},
		{"[::1]:7443", nil, []string{"127.0.0.1:7443", "localhost:7443", "[::1]:7443"}},
		{"localhost:7443", nil, []string{"127.0.0.1:7443", "localhost:7443", "[::1]:7443"}},
		{":7443", nil, []string{"127.0.0.1:7443", "localhost:7443", "[::1]:7443"}},
		{"0.0.0.0:7443", nil, []string{"127.0.0.1:7443", "localhost:7443", "[::1]:7443"}},
		{"192.0.2.1:7443", nil, []string{"192.0.2.1:7443"}},
		{"127.0.0.1:8543", []string{"https://Issuer.Example.com"}, []string{"issuer.example.com:443", "127.0.0.1:8543", "localhost:8543"}},
		{"127.0.0.1:8543", []string{"https://issuer.example.com:8443/"}, []string{"issuer.example.com:8443", "127.0.0.1:8543", "localhost:8543"}},
	} {
		if got := ServedHosts(tc.addr, tc.urls...); !slices.Equal(got, tc.want) {
			t.Errorf("ServedHosts(%q, %q) = %q, want %q", tc.addr, tc.urls, got, tc.want)
		}
	}
}

// TestHostGuard: only a request naming a served host, in any case and
// with or without the default port, reaches the handler; any other —
// a rebound name above all — gets 421.
func TestHostGuard(t *testing.T) {
	reached := 0
	h := HostGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }),
		ServedHosts("127.0.0.1:7443", "https://wallet.example.com"))
	for host, served := range map[string]bool{
		"127.0.0.1:7443":          true,
		"localhost:7443":          true,
		"LocalHost:7443":          true,
		"wallet.example.com":      true,
		"wallet.example.com:443":  true,
		"[::1]:7443":              false,
		"attacker.example:7443":   false,
		"attacker.example":        false,
		"localhost":               false,
		"localhost.:7443":         false,
		"127.0.0.1:7444":          false,
		"wallet.example.com:7443": false,
		"":                        false,
	} {
		before := reached
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		h.ServeHTTP(rec, req)
		if got := reached > before; got != served {
			t.Errorf("Host %q: reached the handler %v, want %v", host, got, served)
		}
		if !served && rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: status %d, want 421", host, rec.Code)
		}
	}
}
