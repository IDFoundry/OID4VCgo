package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// testVerifierSignerAndCert builds a fresh P-256 key and a leaf
// certificate for it issued by a fresh test CA, and a VerifierTrust
// anchored at that CA — enough to build a real, signed Request Object
// via verifier.BuildAuthorizationRequest that X5CVerifierRoots accepts
// (it rejects a self-signed leaf, HAIP 1.0 §5).
func testVerifierSignerAndCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, wallet.VerifierTrust) {
	t.Helper()
	caKey, caCert := testCA(t, "wallet authorization_request test CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "wallet authorization_request test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return key, cert, wallet.X5CVerifierRoots{Roots: roots}
}

// testCA builds a fresh self-signed P-256 CA certificate.
func testCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate (CA): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate (CA): %v", err)
	}
	return key, cert
}

func newTestVerifier(t *testing.T) (*verifier.Verifier, string, wallet.VerifierTrust) {
	t.Helper()
	key, cert, trust := testVerifierSignerAndCert(t)
	v := newTestVerifierWith(t, key, cert)
	return v, v.ClientID(), trust
}

// newTestVerifierWith builds a Verifier signing with key/cert.
func newTestVerifierWith(t *testing.T, key *ecdsa.PrivateKey, cert *x509.Certificate) *verifier.Verifier {
	t.Helper()
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		Assurance:          verifier.AssuranceDevelopment,
		ClientCertificate:  cert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	return v
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
	v, clientID, trust := newTestVerifier(t)
	query := testQuery(t)

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: query, State: "s1",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	got, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: trust,
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
	v, clientID, trust := newTestVerifier(t)
	query := testQuery(t)

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: query, WalletNonce: "wn-1",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: trust, WalletNonce: "wn-1",
	}); err != nil {
		t.Errorf("ParseAuthorizationRequest with correct wallet_nonce: %v", err)
	}

	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: trust, WalletNonce: "wn-wrong",
	}); err == nil {
		t.Error("ParseAuthorizationRequest with mismatched wallet_nonce: want error, got nil")
	}
}

// TestParseAuthorizationRequest_RejectsWrongClientID proves the
// x509_hash Client Identifier check is real — a caller-supplied
// ClientID that doesn't match the signing certificate's own hash must
// be rejected, since that check is this whole scheme's trust anchor.
func TestParseAuthorizationRequest_RejectsWrongClientID(t *testing.T) {
	v, _, trust := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: "x509_hash:not-the-real-hash", VerifierTrust: trust,
	}); err == nil {
		t.Error("ParseAuthorizationRequest with wrong client_id: want error, got nil")
	}
}

// TestFetchAuthorizationRequest proves FetchAuthorizationRequest is a
// genuine GET-fetch-plus-parse: given a request_uri that serves a real
// signed Request Object (built the same way
// TestParseAuthorizationRequest_RoundTripsWithVerifierBuild does), it
// returns the same AuthorizationRequest ParseAuthorizationRequest would
// from that same body.
func TestFetchAuthorizationRequest(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: testQuery(t), State: "s1",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	w := newTestWalletTrusting(t, trust, func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "http://localhost/request/abc" {
			t.Errorf("fetched URL = %q, want the requestURI passed in", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(built.RequestObject)),
			Header:     http.Header{"Content-Type": []string{"application/oauth-authz-req+jwt"}},
		}, nil
	})

	got, err := w.FetchAuthorizationRequest(context.Background(), "http://localhost/request/abc", clientID)
	if err != nil {
		t.Fatalf("FetchAuthorizationRequest: %v", err)
	}
	if got.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, clientID)
	}
	if got.State != "s1" {
		t.Errorf("State = %q, want %q", got.State, "s1")
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
	v, clientID, trust := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: testQuery(t), State: "s2",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: trust,
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
// should build an error response instead (BuildDirectPostErrorResponse),
// not an empty success.
func TestBuildDirectPostResponse_RequiresVPToken(t *testing.T) {
	key := testP256PublicKey(t)
	if _, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		EncryptionKey: key, EncryptionEnc: "A128GCM",
	}); err == nil {
		t.Error("BuildDirectPostResponse with empty VPToken: want error, got nil")
	}
}

// TestBuildDirectPostErrorResponse_RoundTripsWithVerifierParse mirrors
// TestParseAuthorizationRequestAndBuildDirectPostResponse_RoundTripsWithVerifierParse
// for the error path: build an error response with the Wallet, decrypt
// it back with the Verifier, and confirm ParseDirectPostJWTResponse
// surfaces it as a *verifier.ResponseError with the right code/
// description/state rather than trying to read a vp_token.
func TestBuildDirectPostErrorResponse_RoundTripsWithVerifierParse(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: testQuery(t), State: "s3",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: trust,
	})
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest: %v", err)
	}

	responseJWE, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
		Error: "invalid_request", ErrorDescription: "nonce is required", State: authReq.State,
		EncryptionKey: authReq.ResponseEncryptionKey, EncryptionKeyID: authReq.ResponseEncryptionKeyID,
		EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		t.Fatalf("BuildDirectPostErrorResponse: %v", err)
	}

	_, err = v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey)
	var respErr *verifier.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatalf("ParseDirectPostJWTResponse error = %v, want a *verifier.ResponseError", err)
	}
	if respErr.Code != "invalid_request" {
		t.Errorf("Code = %q, want %q", respErr.Code, "invalid_request")
	}
	if respErr.Description != "nonce is required" {
		t.Errorf("Description = %q, want %q", respErr.Description, "nonce is required")
	}
	if respErr.State != "s3" {
		t.Errorf("State = %q, want %q", respErr.State, "s3")
	}
}

// TestBuildDirectPostErrorResponse_RequiresError proves the guard
// against an empty "error" value — mirrors
// TestBuildDirectPostResponse_RequiresVPToken for the error-response
// side.
func TestBuildDirectPostErrorResponse_RequiresError(t *testing.T) {
	key := testP256PublicKey(t)
	if _, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
		EncryptionKey: key, EncryptionEnc: "A128GCM",
	}); err == nil {
		t.Error("BuildDirectPostErrorResponse with empty Error: want error, got nil")
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

// newTestWalletTrusting is newTestWallet with Config.VerifierTrust set.
func newTestWalletTrusting(t *testing.T, trust wallet.VerifierTrust, do func(*http.Request) (*http.Response, error)) *wallet.Wallet {
	t.Helper()
	cfg := validConfig()
	cfg.VerifierTrust = trust
	w, err := wallet.New(cfg, wallet.Dependencies{HTTP: fakeHTTPClient{do: do}, Clock: wallet.ClockFunc(time.Now)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

// TestParseAuthorizationRequest_ChecksVerifierTrust covers OID4VP
// §5.9.3's trust chain validation: a Request Object signed with a
// certificate issued by the trusted CA is accepted (and its leaf
// returned); one from another CA, or with a self-signed leaf even when
// that leaf is itself a trusted root (HAIP 1.0 §5), is rejected; and a
// missing VerifierTrust is an error rather than a silent skip.
func TestParseAuthorizationRequest_ChecksVerifierTrust(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	parse := func(trust wallet.VerifierTrust) (wallet.AuthorizationRequest, error) {
		return wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: trust,
		})
	}

	got, err := parse(trust)
	if err != nil {
		t.Fatalf("trusted CA: %v", err)
	}
	if got.VerifierCertificate == nil || got.VerifierCertificate.Subject.CommonName != "wallet authorization_request test" {
		t.Errorf("VerifierCertificate = %v, want the request's signing leaf", got.VerifierCertificate)
	}

	_, _, otherTrust := testVerifierSignerAndCert(t)
	if _, err := parse(otherTrust); err == nil || !strings.Contains(err.Error(), "untrusted verifier") {
		t.Errorf("another CA: error = %v, want an untrusted verifier error", err)
	}
	if _, err := parse(nil); err == nil || !strings.Contains(err.Error(), "VerifierTrust is required") {
		t.Errorf("nil VerifierTrust: error = %v, want it to be required", err)
	}
	if _, err := parse(wallet.NoVerifierTrust{}); err != nil {
		t.Errorf("NoVerifierTrust: %v", err)
	}

	// A self-signed leaf is rejected even when it's itself a trusted root.
	selfKey, selfCert := testCA(t, "self-signed verifier")
	selfSigned := newTestVerifierWith(t, selfKey, selfCert)
	builtSelf, err := selfSigned.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest (self-signed): %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(selfCert)
	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: builtSelf.RequestObject, ClientID: selfSigned.ClientID(), VerifierTrust: wallet.X5CVerifierRoots{Roots: roots},
	}); err == nil || !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("self-signed leaf: error = %v, want it rejected as self-signed", err)
	}
}

// TestFetchAuthorizationRequest_RequiresVerifierTrust checks a Wallet
// without Config.VerifierTrust refuses to fetch a Request Object at
// all, before making any request.
func TestFetchAuthorizationRequest_RequiresVerifierTrust(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("fetched a Request Object without a VerifierTrust")
		return nil, nil
	})
	if _, err := w.FetchAuthorizationRequest(context.Background(), "http://localhost/request/abc", "x509_hash:abc"); err == nil || !strings.Contains(err.Error(), "VerifierTrust is required") {
		t.Fatalf("error = %v, want Config.VerifierTrust to be required", err)
	}
}

// TestNew_RejectsNoVerifierTrustInProduction checks the explicit
// opt-out can't be used under AssuranceProduction.
func TestNew_RejectsNoVerifierTrustInProduction(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP = false
	for _, trust := range []wallet.VerifierTrust{wallet.NoVerifierTrust{}, &wallet.NoVerifierTrust{}} {
		cfg.VerifierTrust = trust
		if _, err := wallet.New(cfg, validDependencies()); err == nil || !strings.Contains(err.Error(), "NoVerifierTrust") {
			t.Errorf("New(%T) under AssuranceProduction: error = %v, want it rejected", trust, err)
		}
	}
	cfg.VerifierTrust = wallet.X5CVerifierRoots{Roots: x509.NewCertPool()}
	if _, err := wallet.New(cfg, validDependencies()); err != nil {
		t.Errorf("New(X5CVerifierRoots) under AssuranceProduction: %v", err)
	}
}
