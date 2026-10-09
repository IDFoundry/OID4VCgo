package walletflow

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func spkiPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

var otherPin = base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))

func TestTLSPins_Validate(t *testing.T) {
	for name, pins := range map[string]TLSPins{
		"no pins":       {"issuer.example": {}},
		"not base64":    {"issuer.example": {"not base64!"}},
		"not a digest":  {"issuer.example": {base64.StdEncoding.EncodeToString([]byte("short"))}},
		"empty host":    {"": {otherPin}},
		"bare wildcard": {"*.": {otherPin}},
		"deep wildcard": {"*.*.example": {otherPin}},
		"a URL":         {"https://issuer.example": {otherPin}},
		"a port":        {"issuer.example:443": {otherPin}},
		"an IP address": {"127.0.0.1": {otherPin}},
	} {
		if err := pins.Validate(); err == nil {
			t.Errorf("%s: Validate = nil, want an error", name)
		}
	}
	if err := (TLSPins{"issuer.example": {otherPin}, "*.wallet.example": {otherPin}}).Validate(); err != nil {
		t.Errorf("Validate = %v", err)
	}
}

// A host matches its own entry, without case, or a "*." entry one label
// above it, but not the "*." entry's own name, nor two labels down.
func TestTLSPins_pinsFor(t *testing.T) {
	pins := TLSPins{"Issuer.Example": {"a"}, "*.wallet.example": {"b"}}
	for host, want := range map[string]string{
		"issuer.example":        "a",
		"ISSUER.EXAMPLE.":       "a",
		"as.wallet.example":     "b",
		"wallet.example":        "",
		"a.b.wallet.example":    "",
		"other.example":         "",
		"issuer.example.attack": "",
	} {
		got := strings.Join(pins.pinsFor(host), "")
		if got != want {
			t.Errorf("pinsFor(%q) = %q, want %q", host, got, want)
		}
	}
}

// The wallet's own client, in Development too, refuses a pinned host
// whose certificate matches none of its pins, and reaches it when one
// matches; an unpinned host is verified as before.
func TestNew_TLSPins(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())

	get := func(pins TLSPins) error {
		w, err := New(Config{Development: true, TLSPins: pins}, Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()})
		if err != nil {
			t.Fatal(err)
		}
		// The test server's certificate, trusted as a development root,
		// and example.com (a name it has) dialled to it.
		transport := w.deps.HTTP.Transport.(*http.Transport)
		transport.TLSClientConfig.RootCAs = roots
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
		}
		resp, err := w.deps.HTTP.Get("https://example.com/")
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(TLSPins{"example.com": {otherPin, spkiPin(ts.Certificate())}}); err != nil {
		t.Errorf("a matching pin: %v", err)
	}
	if err := get(TLSPins{"example.com": {otherPin}}); !errors.Is(err, ErrTLSPinMismatch) {
		t.Errorf("no matching pin: %v, want ErrTLSPinMismatch", err)
	}
	if err := get(TLSPins{"*.com": {otherPin}}); !errors.Is(err, ErrTLSPinMismatch) {
		t.Errorf("no matching pin, by *.: %v, want ErrTLSPinMismatch", err)
	}
	if err := get(TLSPins{"issuer.example": {otherPin}}); err != nil {
		t.Errorf("an unpinned host: %v", err)
	}
}

func TestNew_TLSPinsRefused(t *testing.T) {
	deps := Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()}
	if _, err := New(Config{Development: true, TLSPins: TLSPins{"issuer.example": {"x"}}}, deps); err == nil {
		t.Error("New took a malformed pin")
	}
	deps.HTTP = http.DefaultClient
	if _, err := New(Config{Development: true, TLSPins: TLSPins{"issuer.example": {otherPin}}}, deps); err == nil {
		t.Error("New took pins it can't apply to Dependencies.HTTP")
	}
}
