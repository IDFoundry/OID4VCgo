package wallet_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/internal/testcert"
	"github.com/idfoundry/oid4vcigo/internal/testmdoc"
	"github.com/idfoundry/oid4vcigo/internal/testverify"
	"github.com/idfoundry/oid4vcigo/verifier"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// issuerKeyResolverFunc adapts a plain function to
// verifier.SDJWTVCIssuerKeyResolver — the http.HandlerFunc idiom,
// enough for a test standing in for whatever real trust policy a
// deployment would apply.
type issuerKeyResolverFunc func(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, jose.Alg, error)

func (f issuerKeyResolverFunc) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, jose.Alg, error) {
	return f(ctx, header, payload)
}

// mdocIssuerKeyResolverFunc adapts a plain function to
// verifier.MdocIssuerKeyResolver — the same func-type-adapter idiom as
// issuerKeyResolverFunc, above.
type mdocIssuerKeyResolverFunc func(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, cose.Alg, error)

func (f mdocIssuerKeyResolverFunc) ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, cose.Alg, error) {
	return f(ctx, x5chain, docType)
}

// newRoundTripVerifier builds a real *verifier.Verifier with a fresh
// self-signed certificate — the setup both round trip tests below
// need, varying only in which dcql.Query/HeldCredential format they
// exercise afterward.
func newRoundTripVerifier(t *testing.T) (*verifier.Verifier, fapi.URL) {
	t.Helper()
	verifierKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate verifier key: %v", err)
	}
	verifierCert := testcert.SelfSigned(t, "verifier round trip test", &verifierKey.PublicKey, verifierKey)
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
	return v, responseURI
}

// presentAndParse marshals vpToken into a direct_post.jwt/dc_api.jwt
// response body, encrypts it against decryptionKey's own public key
// exactly as a real Wallet would (internal/jwe.Encrypt), and
// parses/decrypts it back via v — the shared middle section every
// verifier round trip test in this file needs between building its
// own vp_token and calling VerifyResponse on the result.
func presentAndParse(t *testing.T, v *verifier.Verifier, vpToken map[string][]string, decryptionKey *ecdsa.PrivateKey) verifier.ParsedResponse {
	t.Helper()
	responseBody, err := json.Marshal(map[string]any{"vp_token": vpToken})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	responseJWE, err := jwe.Encrypt(&decryptionKey.PublicKey, jwe.A128GCM, responseBody, jwe.EncryptOptions{})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	parsed, err := v.ParseDirectPostJWTResponse(responseJWE, decryptionKey)
	if err != nil {
		t.Fatalf("ParseDirectPostJWTResponse: %v", err)
	}
	return parsed
}

// presentAndVerifySDJWTVC presents fixture against query
// (audience/origin — exactly one non-empty, mirroring
// wallet.PresentationRequest's own split) via PresentCredentials,
// encrypts/parses the result (presentAndParse), and verifies it via v
// with the same audience/origin — the shared tail
// TestWalletVerifierPresentationRoundTrip and
// TestWalletVerifierDCAPIPresentationRoundTrip both need, differing
// only in which flow they exercise.
func presentAndVerifySDJWTVC(t *testing.T, v *verifier.Verifier, query dcql.Query, fixture heldSDJWTVCFixture, audience, origin, nonce string, decryptionKey *ecdsa.PrivateKey) verifier.VerifiedCredential {
	t.Helper()
	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:       query,
		Credentials: []wallet.HeldCredential{fixture.held},
		Audience:    audience, Origin: origin,
		Nonce: nonce,
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	parsed := presentAndParse(t, v, vpToken, decryptionKey)

	issuerKeys := issuerKeyResolverFunc(func(context.Context, map[string]any, map[string]any) (crypto.PublicKey, jose.Alg, error) {
		return &fixture.issuerKey.PublicKey, jose.ES256, nil
	})
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      parsed,
		ExpectedNonce: nonce,
		IssuerKeys:    issuerKeys,
		Origin:        origin,
	})
	return testverify.RequireOneCredential(t, result, err, "identity_credential")
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
	v, _ := newRoundTripVerifier(t)

	query := testPresentationQuery(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	fixture := newHeldSDJWTVC(t)
	vc := presentAndVerifySDJWTVC(t, v, query, fixture, built.ClientID, "", built.Nonce, built.ResponseDecryptionKey)
	if vc.Claims["given_name"] != "Alice" {
		t.Errorf("Claims[given_name] = %v, want Alice", vc.Claims["given_name"])
	}
	if vc.Claims["vct"] != testPresentationVCT {
		t.Errorf("Claims[vct] = %v, want %q", vc.Claims["vct"], testPresentationVCT)
	}
}

// TestWalletVerifierDCAPIPresentationRoundTrip is
// TestWalletVerifierPresentationRoundTrip's own DC API counterpart:
// the same real, independently-built halves, this time exercising the
// DC API flow end to end — verifier.BuildDCAPIAuthorizationRequest,
// wallet.PresentCredentials with Origin set (binding the Key Binding
// JWT to Appendix A.4's own "origin:"-prefixed audience instead of a
// Client Identifier), and verifier.VerifyResponse with Origin set to
// match. ParseDirectPostJWTResponse needs no DC-API-specific
// counterpart — see its own doc comment for why.
func TestWalletVerifierDCAPIPresentationRoundTrip(t *testing.T) {
	v, _ := newRoundTripVerifier(t)
	origin := "https://verifier.example.com"

	query := testPresentationQuery(t)
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{origin},
	})
	if err != nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}

	fixture := newHeldSDJWTVC(t)
	vc := presentAndVerifySDJWTVC(t, v, query, fixture, "", origin, built.Nonce, built.ResponseDecryptionKey)
	if vc.Claims["given_name"] != "Alice" {
		t.Errorf("Claims[given_name] = %v, want Alice", vc.Claims["given_name"])
	}
}

// TestWalletVerifierMdocPresentationRoundTrip is
// TestWalletVerifierPresentationRoundTrip's own "mso_mdoc" counterpart:
// the same real, independently-built halves, this time exercising
// oid4vpmdoc's own shared Handover/DeviceResponse construction on both
// sides.
func TestWalletVerifierMdocPresentationRoundTrip(t *testing.T) {
	v, responseURI := newRoundTripVerifier(t)

	query := testmdoc.Query(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	thumbprint := testmdoc.ResponseEncryptionThumbprint(t, built.ResponseDecryptionKey)

	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)
	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:                           query,
		Credentials:                     []wallet.HeldCredential{held},
		Audience:                        built.ClientID,
		Nonce:                           built.Nonce,
		ResponseURI:                     responseURI.String(),
		ResponseEncryptionJWKThumbprint: thumbprint,
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	parsed := presentAndParse(t, v, vpToken, built.ResponseDecryptionKey)

	mdocIssuerKeys := mdocIssuerKeyResolverFunc(func(context.Context, [][]byte, string) (crypto.PublicKey, cose.Alg, error) {
		return &f.IssuerKey.PublicKey, cose.ES256, nil
	})
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 query,
		Response:              parsed,
		ExpectedNonce:         built.Nonce,
		MdocIssuerKeys:        mdocIssuerKeys,
		ResponseEncryptionKey: built.ResponseDecryptionKey,
	})
	vc := testverify.RequireOneCredential(t, result, err, "mdl")
	namespace, ok := vc.Claims["org.iso.18013.5.1"].(map[string]interface{})
	if !ok || namespace["given_name"] != "Alice" {
		t.Errorf("Claims[org.iso.18013.5.1] = %v", vc.Claims["org.iso.18013.5.1"])
	}
}
