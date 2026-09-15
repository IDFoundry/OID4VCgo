package verifier_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/verifier"
)

// testSignerAndCert builds a fresh P-256 key and a self-signed leaf
// certificate for it — enough to exercise BuildAuthorizationRequest's
// own x509_hash/x5c mechanics. (HAIP's own "MUST NOT be self-signed"
// is a Wallet-side validation rule this package doesn't implement yet
// — see the package doc comment — so a self-signed cert is fine here.)
func testSignerAndCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verifier test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return key, cert
}

func testResponseURI(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func validConfig(t *testing.T) (verifier.Config, verifier.Dependencies) {
	t.Helper()
	key, cert := testSignerAndCert(t)
	return verifier.Config{
			ClientCertificate:  cert,
			ResponseURI:        testResponseURI(t),
			SigningAlg:         jose.ES256,
			EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		}, verifier.Dependencies{
			Signer: key,
			Random: rand.Reader,
		}
}
