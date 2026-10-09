package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// tls_pins: a request to a pinned host fails as tls_pin unless its
// certificate has one of the pins, on the development client too; the
// configuration's pins are checked as the wallet is made.
func TestTLSPins(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	good := base64.StdEncoding.EncodeToString(sum[:])
	other := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))

	// The development client, pinned, reaching the server as example.com,
	// a name its certificate has: a handshake to an IP address names no
	// host to pin.
	get := func(pins walletflow.TLSPins) error {
		dev, err := developmentClient(ca)
		if err != nil {
			t.Fatal(err)
		}
		client, err := withPins(dev, pins)
		if err != nil {
			t.Fatal(err)
		}
		client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
		resp, err := client.Get("https://example.com/")
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(walletflow.TLSPins{"example.com": {other, good}}); err != nil {
		t.Errorf("a matching pin: %v", err)
	}
	err := get(walletflow.TLSPins{"example.com": {other}})
	if c := classify(err); err == nil || !strings.HasPrefix(c.Error(), "["+CodeTLSPin+"]") {
		t.Errorf("no matching pin: %v, classified %v, want tls_pin", err, c)
	}

	newWallet := func(pins string) error {
		_, err := NewWallet(`{"client_id":"c","redirect_uri":"c:/cb","development":true,"development_roots":`+quote(ca)+`,"tls_pins":`+pins+`}`,
			&goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil)
		return err
	}
	for _, pins := range []string{`{"issuer.example":[]}`, `{"issuer.example":["x"]}`, `{"127.0.0.1":["` + good + `"]}`} {
		if err := newWallet(pins); err == nil || !strings.HasPrefix(err.Error(), "["+CodeInvalidInput+"] tls_pins") {
			t.Errorf("tls_pins %s: %v, want invalid_input", pins, err)
		}
	}
	if err := newWallet(`{"issuer.example":["` + good + `"],"*.wallet.example":["` + other + `"]}`); err != nil {
		t.Errorf("valid tls_pins: %v", err)
	}
	// Without development_roots, walletflow pins its own client.
	if _, err := NewWallet(`{"client_id":"c","redirect_uri":"c:/cb","development":true,"tls_pins":{"issuer.example":["`+good+`"]}}`,
		&goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil); err != nil {
		t.Errorf("tls_pins without development_roots: %v", err)
	}
}
