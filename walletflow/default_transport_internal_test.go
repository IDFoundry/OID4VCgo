package walletflow

import (
	"net/http"
	"testing"
)

// wrappedTransport wraps another RoundTripper, as a tracing library's
// does with http.DefaultTransport.
type wrappedTransport struct{ http.RoundTripper }

// The development client with pins builds on http.DefaultTransport's
// settings even when the program has wrapped it, rather than panic.
func TestDevelopmentClientWrappedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = wrappedTransport{original}
	client, err := defaultHTTPClient(true, TLSPins{"issuer.example": {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := client.Transport.(*http.Transport); !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.VerifyConnection == nil {
		t.Fatalf("development client's transport = %T, want an *http.Transport checking the pins", client.Transport)
	}
}
