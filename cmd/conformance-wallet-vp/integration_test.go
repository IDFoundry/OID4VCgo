package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// verifyOutcome captures what the fake Verifier server's own
// "POST /response" handler observed, for the test's own final
// assertions.
type verifyOutcome struct {
	claims map[string]any
	err    error
}

// setupWalletUnderTest issues this binary's own fixture credential
// (the same real code path main.go uses) and returns the resulting
// *server plus the CA certificate the fake Verifier server needs to
// trust — a genuine issuing CA, not a self-signed leaf, since the
// fake Verifier below uses a real verifier.X5CIssuerKeyResolver (the
// same one a real deployment would use), which correctly rejects a
// self-signed leaf (see verifier/x5c_issuer_key_resolver.go's own doc
// comment). This proves the whole chain for real: this binary's own
// issuing side produces an x5c a real chain-validating resolver
// actually accepts, not just a resolver stubbed to trust anything.
func setupWalletUnderTest(t *testing.T) (*server, *x509.Certificate) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate credential issuer key: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	ca, caKey, _, _, err := conformancecert.GenerateCA("conformance-wallet-vp-test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	issuerCertPEM, err := conformancecert.IssueLeafCertPEM("conformance-wallet-vp-test-issuer", issuerKey, ca, caKey)
	if err != nil {
		t.Fatalf("IssueLeafCertPEM: %v", err)
	}
	cfg := Config{
		VCT:                            "urn:eudi:pid:1",
		Claims:                         map[string]any{"given_name": "Jean", "family_name": "Dupont"},
		CredentialIssuerCertificatePEM: issuerCertPEM,
	}
	cred, err := issueFixtureCredential(cfg, issuerKey, holderKey)
	if err != nil {
		t.Fatalf("issueFixtureCredential: %v", err)
	}
	return &server{cred: cred}, ca
}

// newTestQuery builds the same DCQL query shape
// cmd/conformance-verifier's own buildQuery does, for the two claims
// setupWalletUnderTest's own fixture credential carries.
func newTestQuery(t *testing.T, vct string) dcql.Query {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{vct}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "cred1", Format: "dc+sd-jwt", Meta: meta,
		Claims: []dcql.ClaimsQuery{
			{Path: dcql.Path{dcql.PathKey("given_name")}},
			{Path: dcql.Path{dcql.PathKey("family_name")}},
		},
	}}}
}

// newFakeVerifierServer builds a real verifier.Verifier plus an
// httptest.TLSServer serving its own request_uri/response_uri/
// callback endpoints — everything this binary's handleAuthorize needs
// on the other end of the wire, so the test exercises this binary's
// real HTTP client code, not a mock. issuerCA is the CA
// setupWalletUnderTest issued the fixture credential's own x5c leaf
// under — the fake Verifier's own IssuerKeys resolver
// (verifier.X5CIssuerKeyResolver) trusts it as the sole root, so
// verifying the presented credential exercises real x5c chain
// validation end to end.
func newFakeVerifierServer(t *testing.T, query dcql.Query, issuerCA *x509.Certificate) (*verifier.Verifier, *httptest.Server, verifier.BuildAuthorizationRequestResult, *verifyOutcome) {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate verifier client key: %v", err)
	}
	clientCert := testcert.SelfSigned(t, "conformance-verifier-test", &clientKey.PublicKey, clientKey)

	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	responseURI, err := fapi.ParseEndpointURL(ts.URL + "/response")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  clientCert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: clientKey, Random: rand.Reader})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(issuerCA)
	issuerKeys := verifier.X5CIssuerKeyResolver{Roots: roots}
	got := &verifyOutcome{}

	mux.HandleFunc("GET /request/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(built.RequestObject))
	})
	mux.HandleFunc("POST /response", handleFakeVerifierResponse(v, query, built, issuerKeys, ts.URL+"/callback", got))
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	return v, ts, built, got
}

// handleFakeVerifierResponse is the fake Verifier server's own
// "response_uri" handler: decrypts and cryptographically verifies
// whatever this binary's handleAuthorize POSTs, recording the outcome
// into got for the test's own final assertions.
func handleFakeVerifierResponse(v *verifier.Verifier, query dcql.Query, built verifier.BuildAuthorizationRequestResult, issuerKeys verifier.SDJWTVCIssuerKeyResolver, callbackURL string, got *verifyOutcome) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		parsed, err := v.ParseDirectPostJWTResponse(r.FormValue("response"), built.ResponseDecryptionKey)
		if err != nil {
			// Mirrors cmd/conformance-verifier's own handleResponse: a
			// legitimate *verifier.ResponseError (the Wallet successfully
			// reported it can't satisfy the request, OID4VP §8.1) still
			// gets a 200 + redirect_uri — the Verifier understood the
			// response, it just carries an error rather than a vp_token.
			// Only a genuine decode/parse failure (malformed input, not a
			// real error response) is the caller's own fault and gets a
			// 400.
			var respErr *verifier.ResponseError
			if errors.As(err, &respErr) {
				got.err = respErr
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"redirect_uri": callbackURL})
				return
			}
			got.err = err
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: query, Response: parsed, ExpectedNonce: built.Nonce,
			IssuerKeys:       issuerKeys,
			MaxKeyBindingAge: time.Hour,
		})
		if err != nil {
			got.err = err
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(result.Credentials) != 1 {
			got.err = errors.New("verifier returned an unexpected number of credentials")
			http.Error(w, "wrong credential count", http.StatusInternalServerError)
			return
		}
		got.claims = result.Credentials[0].Claims
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"redirect_uri": callbackURL})
	}
}

// TestHandleAuthorize_FullRoundTripAgainstARealVerifier is the same
// scenario this binary was manually smoke-tested against
// cmd/conformance-verifier with (see conformance/wallet-vp/README.md):
// a real verifier.Verifier builds and signs an Authorization Request,
// this binary's own handleAuthorize fetches/verifies it, presents its
// fixture credential, and the Verifier cryptographically verifies the
// resulting direct_post.jwt response end to end — not a mock on
// either side.
func TestHandleAuthorize_FullRoundTripAgainstARealVerifier(t *testing.T) {
	wallet, issuerCA := setupWalletUnderTest(t)
	query := newTestQuery(t, "urn:eudi:pid:1")
	_, ts, built, got := newFakeVerifierServer(t, query, issuerCA)

	previousHTTPClient := httpClient
	httpClient = ts.Client() // trust the httptest server's own cert for this binary's outbound calls
	t.Cleanup(func() { httpClient = previousHTTPClient })

	requestURL := ts.URL + "/authorize?" + url.Values{
		"client_id":   {built.ClientID},
		"request_uri": {ts.URL + "/request/1"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, requestURL, nil)
	rec := httptest.NewRecorder()
	wallet.handleAuthorize(rec, req)

	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("handleAuthorize: status %d: %s", rec.Code, body)
	}
	if got.err != nil {
		t.Fatalf("verifier's own VerifyResponse: %v", got.err)
	}
	if got.claims["given_name"] != "Jean" || got.claims["family_name"] != "Dupont" {
		t.Fatalf("disclosed claims = %+v, want given_name=Jean family_name=Dupont", got.claims)
	}
}

// TestHandleAuthorize_SendsErrorResponseWhenPresentationFails proves
// handleAuthorize's own error path end to end, real network and real
// crypto on both sides, mirroring
// TestHandleAuthorize_FullRoundTripAgainstARealVerifier exactly except
// for the query: asking for a vct this binary's fixture credential
// doesn't carry makes wallet.PresentCredentials fail (MatchDCQLQuery
// finds no match for a required credential query) — a failure after
// fetchAndVerifyRequestObject has already verified the Request Object
// legitimate, so respondWithError should send a real encrypted
// wallet.BuildDirectPostErrorResponse to response_uri rather than
// rejecting locally. The fake Verifier's own response_uri handler
// decrypts it exactly like a real Verifier would and surfaces it as a
// *verifier.ResponseError, proving the two sides are still
// interoperable for this path too. The expected code is
// "access_denied", not the generic "invalid_request" — a required DCQL
// query with no satisfying held credential is OID4VP §8.5/§6.4.2's own
// unsatisfiable-query case (confirmed live against a real OIDF
// conformance suite instance:
// VP1FinalWalletRequiredNonMatchingCredential.java's own
// EnsureAuthorizationEndpointErrorIsAccessDenied check).
func TestHandleAuthorize_SendsErrorResponseWhenPresentationFails(t *testing.T) {
	wallet, issuerCA := setupWalletUnderTest(t)
	query := newTestQuery(t, "urn:eudi:pid:this-vct-does-not-match-the-fixture-credential")
	_, ts, built, got := newFakeVerifierServer(t, query, issuerCA)

	previousHTTPClient := httpClient
	httpClient = ts.Client()
	t.Cleanup(func() { httpClient = previousHTTPClient })

	requestURL := ts.URL + "/authorize?" + url.Values{
		"client_id":   {built.ClientID},
		"request_uri": {ts.URL + "/request/1"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, requestURL, nil)
	rec := httptest.NewRecorder()
	wallet.handleAuthorize(rec, req)

	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("handleAuthorize: status %d: %s", rec.Code, body)
	}
	if !strings.Contains(rec.Body.String(), "Rejected") {
		t.Errorf("response body = %q, want it to mention Rejected", rec.Body.String())
	}

	var respErr *verifier.ResponseError
	if !errors.As(got.err, &respErr) {
		t.Fatalf("verifier's own ParseDirectPostJWTResponse error = %v, want a *verifier.ResponseError", got.err)
	}
	if respErr.Code != "access_denied" {
		t.Errorf("Code = %q, want %q", respErr.Code, "access_denied")
	}
	if respErr.Description == "" {
		t.Error("Description is empty, want the underlying PresentCredentials error text")
	}
}
