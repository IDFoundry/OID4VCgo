package mobile

import (
	"crypto/ecdsa"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// development_roots: trusted besides the system's CAs, and only in
// development.
func TestDevelopmentRoots(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	client, err := developmentClient(ca)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("a development root wasn't trusted: %v", err)
	}
	_ = resp.Body.Close()
	if _, err := http.Get(srv.URL); err == nil {
		t.Fatal("the test server's certificate is trusted without it")
	}
	if _, err := developmentClient("not PEM"); err == nil {
		t.Fatal("accepted roots that aren't PEM")
	}

	for _, tc := range []struct{ config, want string }{
		{`{"client_id":"c","redirect_uri":"c:/cb","development_roots":` + quote(ca) + `}`, "development_roots needs development"},
		{`{"client_id":"c","redirect_uri":"c:/cb","development":true,"development_roots":"x"}`, "development_roots"},
	} {
		_, err := NewWallet(tc.config, &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "["+CodeInvalidInput+"]") {
			t.Errorf("NewWallet(%s) = %v, want invalid_input naming %q", tc.config, err, tc.want)
		}
	}
	if _, err := NewWallet(`{"client_id":"c","redirect_uri":"c:/cb","development":true,"development_roots":`+quote(ca)+`}`,
		&goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil); err != nil {
		t.Fatalf("a development wallet with development_roots: %v", err)
	}
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, "\n", `\n`) + `"` }
