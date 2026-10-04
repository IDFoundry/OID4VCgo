package walletflow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/registration"
)

// TestSignedBySelf: a registration whose signing certificate has the
// Verifier's own request-signing key is the Verifier vouching for
// itself.
func TestSignedBySelf(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verifier := &x509.Certificate{PublicKey: &key.PublicKey}
	if !signedBySelf(registration.Registration{RegistrarCertificate: &x509.Certificate{PublicKey: &key.PublicKey}}, verifier) {
		t.Error("a registration signed with the Verifier's key wasn't caught")
	}
	if signedBySelf(registration.Registration{RegistrarCertificate: &x509.Certificate{PublicKey: &other.PublicKey}}, verifier) {
		t.Error("a registrar's own key was taken for the Verifier's")
	}
	if signedBySelf(registration.Registration{}, verifier) || signedBySelf(registration.Registration{RegistrarCertificate: verifier}, nil) {
		t.Error("a missing certificate counted as self-signed")
	}
}
