// Package testverifier builds a ready-to-use *verifier.Verifier for
// tests (and fuzz targets, which build their own seed corpus outside
// any *testing.T-scoped test function) that need one — never for
// production use. A regular (not _test.go) package specifically so
// more than one package's own tests can share it — the same reason
// internal/testcert/internal/testmdoc exist.
package testverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// New builds a *verifier.Verifier backed by a fresh, throwaway P-256
// signer and self-signed certificate — enough to build and parse real
// signed Request Objects and direct_post.jwt responses. t is
// testing.TB, not *testing.T, so a FuzzXxx target's own *testing.F can
// call this too (both implement testing.TB).
func New(t testing.TB) *verifier.Verifier {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testverifier: generate key: %v", err)
	}
	cert := testcert.SelfSigned(t, "testverifier", &key.PublicKey, key)
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		t.Fatalf("testverifier: ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  cert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{}},
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	if err != nil {
		t.Fatalf("testverifier: verifier.New: %v", err)
	}
	return v
}
