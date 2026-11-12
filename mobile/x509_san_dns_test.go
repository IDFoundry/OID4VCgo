package mobile

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// accept_x509_san_dns reaches walletflow.Config.AcceptX509SANDNS, is off
// unless set, and is invalid_input without verifier_roots.
func TestWalletflowConfig_AcceptX509SANDNS(t *testing.T) {
	ca, _ := testcert.CA(t, "x509_san_dns verifier CA")
	roots := pemOf("CERTIFICATE", ca.Raw)
	for name, tc := range map[string]struct {
		cfg  map[string]any
		want bool
	}{
		"unset":     {map[string]any{"development": true, "verifier_roots": roots}, false},
		"opted in":  {map[string]any{"development": true, "verifier_roots": roots, "accept_x509_san_dns": true}, true},
		"opted out": {map[string]any{"development": true, "verifier_roots": roots, "accept_x509_san_dns": false}, false},
	} {
		raw, err := json.Marshal(tc.cfg)
		if err != nil {
			t.Fatal(err)
		}
		var cfg config
		if err := decodeConfig(string(raw), &cfg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		wcfg, err := walletConfig(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if wcfg.AcceptX509SANDNS != tc.want {
			t.Errorf("%s: AcceptX509SANDNS = %v, want %v", name, wcfg.AcceptX509SANDNS, tc.want)
		}
		if _, err := NewWallet(string(raw), &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil); err != nil {
			t.Errorf("%s: NewWallet: %v", name, err)
		}
	}

	_, err := NewWallet(`{"development":true,"accept_x509_san_dns":true}`, &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil)
	var e *Error
	const want = "accept_x509_san_dns needs verifier_roots: an x509_san_dns name is the Verifier's only through a chain to them"
	if !errors.As(err, &e) || e.Code != CodeInvalidInput || e.Message != want {
		t.Errorf("accept_x509_san_dns without verifier_roots: %v, want %s: %s", err, CodeInvalidInput, want)
	}
}
