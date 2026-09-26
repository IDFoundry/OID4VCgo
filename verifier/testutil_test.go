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

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
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

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
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
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{
		Signer: key,
		Random: rand.Reader,
	}
}

// newTestVerifierWithConfig builds a *verifier.Verifier from a fresh
// validConfig, returning cfg/deps alongside it for tests that also
// need to inspect the Config/Dependencies used to build it (e.g.
// verifying the resulting Request Object's own signature).
func newTestVerifierWithConfig(t *testing.T) (verifier.Config, verifier.Dependencies, *verifier.Verifier) {
	t.Helper()
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cfg, deps, v
}

// newTestVerifier is newTestVerifierWithConfig for tests that only
// need the *verifier.Verifier itself.
func newTestVerifier(t *testing.T) *verifier.Verifier {
	t.Helper()
	_, _, v := newTestVerifierWithConfig(t)
	return v
}
