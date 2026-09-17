package wallet_test

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

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// testVerifierSignerAndCert builds a fresh P-256 key and a self-signed
// leaf certificate for it — enough to build a real, signed Request
// Object via verifier.BuildAuthorizationRequest, the same shape
// verifier's own test suite uses (verifier/testutil_test.go).
func testVerifierSignerAndCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wallet authorization_request test"},
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

func newTestVerifier(t *testing.T) (*verifier.Verifier, string) {
	t.Helper()
	key, cert := testVerifierSignerAndCert(t)
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  cert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	return v, v.ClientID()
}

func testQuery(t *testing.T) dcql.Query {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return dcql.Query{
		Credentials: []dcql.CredentialQuery{
			{ID: "cred1", Format: "dc+sd-jwt", Meta: meta},
		},
	}
}

// TestParseAuthorizationRequest_RoundTripsWithVerifierBuild proves
// ParseAuthorizationRequest is a genuine, interoperable counterpart to
// verifier.BuildAuthorizationRequest — not just independently
// plausible-looking code — by building a real signed Request Object
// with one and parsing it with the other.
func TestParseAuthorizationRequest_RoundTripsWithVerifierBuild(t *testing.T) {
	v, clientID := newTestVerifier(t)
	query := testQuery(t)

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: query, State: "s1",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	got, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest: %v", err)
	}

	if got.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, clientID)
	}
	if got.Nonce != built.Nonce {
		t.Errorf("Nonce = %q, want %q", got.Nonce, built.Nonce)
	}
	if got.State != "s1" {
		t.Errorf("State = %q, want %q", got.State, "s1")
	}
	if len(got.Query.Credentials) != 1 || got.Query.Credentials[0].ID != "cred1" {
		t.Errorf("Query = %+v, want one credential query with id cred1", got.Query)
	}
	if got.ResponseEncryptionKey == nil {
		t.Error("ResponseEncryptionKey is nil")
	}
	if got.ResponseEncryptionKeyID == "" {
		t.Error("ResponseEncryptionKeyID is empty")
	}
	if got.ResponseEncryptionEnc != "A128GCM" {
		t.Errorf("ResponseEncryptionEnc = %q, want A128GCM (HAIP's own minimum, and what this Verifier advertises first)", got.ResponseEncryptionEnc)
	}
}

// TestParseAuthorizationRequest_WalletNonceEcho proves the §5.10.1
// wallet_nonce echo check both accepts a correct echo and rejects a
// missing/mismatched one.
func TestParseAuthorizationRequest_WalletNonceEcho(t *testing.T) {
	v, clientID := newTestVerifier(t)
	query := testQuery(t)

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: query, WalletNonce: "wn-1",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, WalletNonce: "wn-1",
	}); err != nil {
		t.Errorf("ParseAuthorizationRequest with correct wallet_nonce: %v", err)
	}

	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, WalletNonce: "wn-wrong",
	}); err == nil {
		t.Error("ParseAuthorizationRequest with mismatched wallet_nonce: want error, got nil")
	}
}

// TestParseAuthorizationRequest_RejectsWrongClientID proves the
// x509_hash Client Identifier check is real — a caller-supplied
// ClientID that doesn't match the signing certificate's own hash must
// be rejected, since that check is this whole scheme's trust anchor.
func TestParseAuthorizationRequest_RejectsWrongClientID(t *testing.T) {
	v, _ := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: "x509_hash:not-the-real-hash",
	}); err == nil {
		t.Error("ParseAuthorizationRequest with wrong client_id: want error, got nil")
	}
}

// TestParseAuthorizationRequestAndBuildDirectPostResponse_RoundTripsWithVerifierParse
// proves BuildDirectPostResponse is a genuine, interoperable
// counterpart to verifier.ParseDirectPostJWTResponse: build a request
// with the Verifier, parse it with the Wallet, build an (encrypted)
// response with the Wallet, and decrypt/parse it back with the
// Verifier — the full loop both conformance binaries drive live,
// exercised here without a network or the OIDF suite.
func TestParseAuthorizationRequestAndBuildDirectPostResponse_RoundTripsWithVerifierParse(t *testing.T) {
	v, clientID := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: testQuery(t), State: "s2",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest: %v", err)
	}

	vpToken := map[string][]string{"cred1": {"~fake~presentation~"}}
	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: authReq.State,
		EncryptionKey: authReq.ResponseEncryptionKey, EncryptionKeyID: authReq.ResponseEncryptionKeyID,
		EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		t.Fatalf("BuildDirectPostResponse: %v", err)
	}

	parsed, err := v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey)
	if err != nil {
		t.Fatalf("ParseDirectPostJWTResponse: %v", err)
	}
	if len(parsed.VPToken["cred1"]) != 1 || parsed.VPToken["cred1"][0] != "~fake~presentation~" {
		t.Errorf("VPToken = %+v, want {cred1: [~fake~presentation~]}", parsed.VPToken)
	}
	if parsed.State != "s2" {
		t.Errorf("State = %q, want %q", parsed.State, "s2")
	}
}

// TestBuildDirectPostResponse_RequiresVPToken proves the guard against
// an empty vp_token — a caller that found no matching credentials
// should build an error response instead (BuildDirectPostErrorResponse
// is a planned follow-on, not yet implemented), not an empty success.
func TestBuildDirectPostResponse_RequiresVPToken(t *testing.T) {
	key := testP256PublicKey(t)
	if _, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		EncryptionKey: key, EncryptionEnc: "A128GCM",
	}); err == nil {
		t.Error("BuildDirectPostResponse with empty VPToken: want error, got nil")
	}
}

func testP256PublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &key.PublicKey
}
