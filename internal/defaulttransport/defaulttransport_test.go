package defaulttransport

import (
	"net/http"
	"testing"
)

// wrapped is a RoundTripper wrapping another, as a tracing library's
// does.
type wrapped struct{ http.RoundTripper }

func TestClone(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })

	got := Clone()
	if got == nil || got == original {
		t.Fatalf("Clone of the default transport = %p, want a copy of %p", got, original)
	}
	if got.Proxy == nil || got.TLSHandshakeTimeout != original.(*http.Transport).TLSHandshakeTimeout {
		t.Fatal("Clone of the default transport lost its settings")
	}

	http.DefaultTransport = wrapped{original}
	got = Clone()
	if got == nil || got.Proxy == nil || got.DialContext == nil || got.TLSHandshakeTimeout == 0 || got.IdleConnTimeout == 0 {
		t.Fatalf("Clone of a wrapped default transport = %+v, want Go's default settings", got)
	}
}
