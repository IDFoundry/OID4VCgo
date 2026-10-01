package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// TestX5CVerifierRoots_LeafProfile: a Verifier's leaf must be an
// end-entity certificate allowed to sign, and LeafPolicy can narrow the
// Verifiers trusted further.
func TestX5CVerifierRoots_LeafProfile(t *testing.T) {
	ca, caKey := testcert.CA(t, "Verifier CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(tmpl *x509.Certificate) []byte {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SerialNumber, tmpl.Subject = big.NewInt(3), pkix.Name{CommonName: "verifier.example.com"}
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	plain, _ := testcert.Leaf(t, "verifier.example.com", ca, caKey)
	signing := issue(&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature})
	subCA := issue(&x509.Certificate{IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature})
	encipherOnly := issue(&x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment})

	trust := wallet.X5CVerifierRoots{Roots: roots}
	for name, der := range map[string][]byte{"no key usage": plain.Raw, "digitalSignature": signing} {
		if _, err := trust.VerifyVerifierChain([][]byte{der}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, der := range map[string][]byte{"CA certificate": subCA, "keyEncipherment only": encipherOnly} {
		if _, err := trust.VerifyVerifierChain([][]byte{der}); err == nil {
			t.Errorf("%s: trusted as a Verifier", name)
		}
	}

	if _, err := trust.VerifyVerifierChain([][]byte{signing, ca.Raw}); err == nil {
		t.Error("a chain including its trust anchor was trusted")
	}

	errNotAVerifier := errors.New("not a verifier certificate")
	trust.LeafPolicy = func(*x509.Certificate, [][]*x509.Certificate) error { return errNotAVerifier }
	if _, err := trust.VerifyVerifierChain([][]byte{signing}); !errors.Is(err, errNotAVerifier) {
		t.Errorf("LeafPolicy refusal = %v, want it passed through", err)
	}
}
