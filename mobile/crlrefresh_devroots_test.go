package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// selfSignedTLS is a self-signed TLS server certificate for 127.0.0.1,
// not a CA's, as a development service's (the passport-vdc demo's) is.
func selfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "development service"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// RefreshCRLs trusts development_roots, as the wallet's other requests
// do in development: an https distribution point whose certificate only
// they hold is fetched with them, and isn't without them; outside
// development they're refused, for a Wallet and a ProximityReader
// alike.
func TestRefreshCRLs_DevelopmentRoots(t *testing.T) {
	ca, caKey := testcert.CA(t, "refresh CA")
	list := testcert.CRL(t, ca, caKey)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(list.Raw) }))
	cert := selfSignedTLS(t)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsRoot := pemOf("CERTIFICATE", cert.Certificate[0])
	issuer := pemOf("CERTIFICATE", ca.Raw)
	points := []map[string]string{{"url": srv.URL + "/ca.crl", "issuer": issuer}}

	wallet := func(development bool, roots string) (*Wallet, error) {
		cfg := map[string]any{
			"development": development, "verifier_roots": issuer, "revocation": []string{"verifier"},
			"crl_distribution_points": points, "crl_require_https": true,
		}
		if roots != "" {
			cfg["development_roots"] = roots
		}
		text, _ := json.Marshal(cfg)
		return NewWallet(string(text), &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil)
	}
	reader := func(development bool, roots string) (*ProximityReader, error) {
		cfg := map[string]any{
			"development": development, "issuer_roots": issuer, "revocation": []string{"issuer", "status"},
			"crl_distribution_points": points, "crl_require_https": true,
			"any_issuer_for_any_type": true, "status": "decline",
		}
		if roots != "" {
			cfg["development_roots"] = roots
		}
		text, _ := json.Marshal(cfg)
		return NewProximityReader(string(text), nil)
	}
	type refresher interface {
		RefreshCRLs(*Operation) (string, error)
	}
	refresh := func(name string, r refresher) crlRefreshResult {
		t.Helper()
		out, err := r.RefreshCRLs(nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return refreshResult(t, out).Results[0]
	}

	for _, kind := range []string{"wallet", "reader"} {
		build := func(development bool, roots string) (refresher, error) {
			if kind == "wallet" {
				return wallet(development, roots)
			}
			return reader(development, roots)
		}
		with, err := build(true, tlsRoot)
		if err != nil {
			t.Fatalf("%s with development_roots: %v", kind, err)
		}
		if res := refresh(kind+" with development_roots", with); res.Outcome != crlUpdated {
			t.Errorf("%s with development_roots: %+v, want the list fetched", kind, res)
		}
		without, err := build(true, "")
		if err != nil {
			t.Fatalf("%s without development_roots: %v", kind, err)
		}
		if res := refresh(kind+" without development_roots", without); res.Outcome != crlFailed || !strings.Contains(res.Error, "certificate") {
			t.Errorf("%s without development_roots: %+v, want the TLS certificate refused", kind, res)
		}
		if _, err := build(false, tlsRoot); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "development_roots") {
			t.Errorf("%s in production with development_roots: %v, want invalid_input naming it", kind, err)
		}
		if _, err := build(true, "not PEM"); code(err) != CodeInvalidInput {
			t.Errorf("%s with malformed development_roots: %v, want invalid_input", kind, err)
		}
	}
}
