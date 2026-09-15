package wallet_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/verifier"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// fixedVerifierIssuerKeyResolver always resolves to the one issuer key
// a test signed with — the same role fixedSDJWTVCIssuerKeyResolver
// plays in verifier's own test suite; redefined here since it's an
// unexported type in that package's own _test.go.
type fixedVerifierIssuerKeyResolver struct {
	pub crypto.PublicKey
	alg jose.Alg
}

func (r fixedVerifierIssuerKeyResolver) ResolveIssuerKey(context.Context, map[string]any, map[string]any) (crypto.PublicKey, jose.Alg, error) {
	return r.pub, r.alg, nil
}

func testVerifierSignerAndCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verifier round trip test"},
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

// TestWalletVerifierPresentationRoundTrip drives OID4VP end to end
// between this repo's own two independently-built halves: a real
// verifier.Verifier builds and signs an Authorization Request, a real
// wallet.HeldCredential (a freshly issued "dc+sd-jwt" credential) is
// matched against its own dcql_query and presented via
// wallet.PresentCredentials, the resulting vp_token is encrypted into
// a direct_post.jwt response body exactly as a real Wallet would
// (internal/jwe.Encrypt against the Verifier's own advertised
// response-encryption key), and verifier.Verifier parses/decrypts and
// verifies it — the same "real round trip, not a simulation"
// discipline TestWalletIssuerRoundTrip already holds OID4VCI to,
// extended to OID4VP.
func TestWalletVerifierPresentationRoundTrip(t *testing.T) {
	verifierKey, verifierCert := testVerifierSignerAndCert(t)
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  verifierCert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
	}, verifier.Dependencies{Signer: verifierKey, Random: rand.Reader})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	query := testPresentationQuery(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	fixture := newHeldSDJWTVC(t)
	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:       query,
		Credentials: []wallet.HeldCredential{fixture.held},
		Audience:    built.ClientID,
		Nonce:       built.Nonce,
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}

	responseBody, err := json.Marshal(map[string]any{"vp_token": vpToken})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	responseJWE, err := jwe.Encrypt(&built.ResponseDecryptionKey.PublicKey, jwe.A128GCM, responseBody, jwe.EncryptOptions{})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	parsed, err := v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey)
	if err != nil {
		t.Fatalf("ParseDirectPostJWTResponse: %v", err)
	}

	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      parsed,
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedVerifierIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(result.Credentials))
	}
	if result.Credentials[0].CredentialQueryID != "identity_credential" {
		t.Errorf("CredentialQueryID = %q", result.Credentials[0].CredentialQueryID)
	}
	if result.Credentials[0].Claims["given_name"] != "Alice" {
		t.Errorf("Claims[given_name] = %v, want Alice", result.Credentials[0].Claims["given_name"])
	}
	if result.Credentials[0].Claims["vct"] != testPresentationVCT {
		t.Errorf("Claims[vct] = %v, want %q", result.Credentials[0].Claims["vct"], testPresentationVCT)
	}
}
