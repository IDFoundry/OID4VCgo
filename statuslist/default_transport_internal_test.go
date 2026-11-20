package statuslist

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// wrappedTransport wraps another RoundTripper, as a tracing library's
// does with http.DefaultTransport.
type wrappedTransport struct{ http.RoundTripper }

// A Fetcher without a Transport, built while the program has wrapped
// http.DefaultTransport, fetches through a transport of Go's default
// settings with its address policy, rather than panic, then and after.
func TestDefaultTransportWrapped(t *testing.T) {
	f := Fetcher{AllowLoopback: true}
	i := f.policy().index()
	original := http.DefaultTransport
	defaultTransports[i] = defaultTransportSlot{}
	t.Cleanup(func() {
		http.DefaultTransport = original
		defaultTransports[i] = defaultTransportSlot{}
	})
	http.DefaultTransport = wrappedTransport{original}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	for range 2 {
		rt, err := f.transport(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := rt.(*http.Transport); !ok {
			t.Fatalf("transport = %T, want an *http.Transport the address policy applies to", rt)
		}
		res, err := (&http.Client{Transport: rt}).Get(srv.URL)
		if err != nil {
			t.Fatalf("fetching through it: %v", err)
		}
		_ = res.Body.Close()
	}
}
