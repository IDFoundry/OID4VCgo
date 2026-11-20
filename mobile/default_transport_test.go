package mobile

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

// wrappedTransport wraps another RoundTripper, as a tracing library's
// does with http.DefaultTransport.
type wrappedTransport struct{ http.RoundTripper }

// development_roots build on http.DefaultTransport's settings even when
// the program has wrapped it, rather than panic.
func TestDevelopmentRootsWrappedDefaultTransport(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = wrappedTransport{original}
	client, err := developmentClient(ca)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("fetching with development roots: %v", err)
	}
	_ = res.Body.Close()
}
