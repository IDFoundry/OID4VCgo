package main

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
)

// TestCRLServer: the plain-http listener serves each CA's CRL at the
// path its https URL does, signed by that CA, and nothing else.
func TestCRLServer(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	srv := httptest.NewServer(crlServer(env.Issuer, env.Verifier).Handler)
	t.Cleanup(srv.Close)
	for path, ca := range map[string]*x509.Certificate{
		issuerapp.CRLPath:            env.Issuer.IssuerCACertificate(),
		verifierapp.VerifierCRLPath:  env.Verifier.VerifierCACertificate(),
		verifierapp.ReaderCRLPath:    env.Verifier.ReaderCACertificate(),
		verifierapp.RegistrarCRLPath: env.Verifier.RegistrarCACertificate(),
	} {
		resp, err := http.Get(srv.URL + path) //nolint:noctx // a test
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %v", path, resp.StatusCode, err)
		}
		list, err := x509.ParseRevocationList(body)
		if err != nil || list.CheckSignatureFrom(ca) != nil {
			t.Errorf("%s: not %q's CRL (%v)", path, ca.Subject.CommonName, err)
		}
	}
	resp, err := http.Get(srv.URL + "/demo/") //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the CRL listener served /demo/: %d", resp.StatusCode)
	}
}
