package wallet_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/storage"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// issuerNonceFake plays the role of the network for wallet's own Nonce
// Endpoint call, routing it to a real issuer.Issuer's own RequestNonce
// — no HTTP server, but genuinely the production code on both sides.
type issuerNonceFake struct{ iss *issuer.Issuer }

func (f issuerNonceFake) Do(req *http.Request) (*http.Response, error) {
	result, err := f.iss.RequestNonce(req.Context())
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		CNonce string `json:"c_nonce"`
	}{CNonce: result.CNonce})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": {"application/json"}},
	}, nil
}

// issuerCredentialFake plays the role of a sender-constrained
// Credential Endpoint call, routing it to a real issuer.Issuer's own
// RequestCredential. Sender-constraining itself (DPoP/mTLS) is
// fapigo/client's own job — this fake stands in for it, since proving
// that belongs to fapigo/client's own test suite, not this one; what
// this test proves is that wallet's outbound wire format is exactly
// what issuer's inbound parsing expects, and vice versa for the
// response.
type issuerCredentialFake struct {
	iss    *issuer.Issuer
	auth   issuer.AuthorizedRequest
	claims *sdjwtvc.Claims
}

func (f issuerCredentialFake) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	plaintext, wasEncrypted, err := f.iss.DecryptRequestBody(raw, req.Header.Get("Content-Type"))
	if err != nil {
		return issuerErrorResponse(err)
	}

	var wire struct {
		CredentialConfigurationID string                               `json:"credential_configuration_id"`
		Proofs                    map[string][]string                  `json:"proofs"`
		ResponseEncryption        *issuerWireResponseEncryptionRequest `json:"credential_response_encryption"`
	}
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		return nil, err
	}

	credReq := issuer.CredentialRequest{
		CredentialConfigurationID: wire.CredentialConfigurationID,
		Proofs:                    wire.Proofs,
		SDJWTClaims:               f.claims,
		RequestWasEncrypted:       wasEncrypted,
	}
	if wire.ResponseEncryption != nil {
		credReq.ResponseEncryption = &issuer.ResponseEncryptionRequest{
			JWK: wire.ResponseEncryption.JWK, Enc: jwe.Enc(wire.ResponseEncryption.Enc), Zip: jwe.Zip(wire.ResponseEncryption.Zip),
		}
	}

	result, reqErr := f.iss.RequestCredential(ctx, f.auth, credReq)
	if reqErr != nil {
		return issuerErrorResponse(reqErr)
	}

	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	encoded, contentType, err := f.iss.EncryptResponseBody(body, credReq.ResponseEncryption)
	if err != nil {
		return issuerErrorResponse(err)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(encoded)),
		Header:     http.Header{"Content-Type": {contentType}},
	}, nil
}

// issuerWireResponseEncryptionRequest mirrors the actual §8.2 wire
// shape of a Credential Request's own "credential_response_encryption"
// object — issuerCredentialFake's own stand-in for what a real HTTP
// handler's JSON decoding would produce.
type issuerWireResponseEncryptionRequest struct {
	JWK json.RawMessage `json:"jwk"`
	Enc string          `json:"enc"`
	Zip string          `json:"zip,omitempty"`
}

// dpopProtectedResourceClient is exactly the kind of thing
// (*Wallet).GenerateDPoPProof's own doc comment describes a caller
// building for an access token obtained via RequestPreAuthorizedCodeToken:
// it attaches "Authorization: DPoP <token>" and a fresh DPoP proof
// (this package's own primitive, reused rather than reimplemented) to
// every request before forwarding to inner.
type dpopProtectedResourceClient struct {
	w           *wallet.Wallet
	key         crypto.Signer
	accessToken string
	inner       wallet.ProtectedResourceClient
}

func (c dpopProtectedResourceClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	htu := *req.URL
	htu.RawQuery, htu.Fragment = "", ""
	proof, err := c.w.GenerateDPoPProof(c.key, req.Method, htu.String(), "", wallet.DPoPAccessTokenHash(c.accessToken))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "DPoP "+c.accessToken)
	req.Header.Set("DPoP", proof)
	return c.inner.Do(ctx, req)
}

// TestWalletPreAuthorizedCodeRoundTrip drives the Pre-Authorized Code
// Flow's own Token Request end-to-end (against a canned Token
// Response — this repo has no OAuth Token Endpoint of its own to
// verify a DPoP-bound access token against; that's fapigo/resource's
// job in a real deployment), then uses the resulting access token,
// via a caller-built dpopProtectedResourceClient, to complete a real
// Credential Request against a real issuer.Issuer — proving the two
// halves this package deliberately keeps separate (acquiring the
// token, and presenting it) compose correctly.
func TestWalletPreAuthorizedCodeRoundTrip(t *testing.T) {
	issuerURL, err := fapi.ParseIssuerURL("http://localhost", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	credentialEndpoint, err := fapi.ParseEndpointURL("http://localhost/credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	tokenEndpoint, err := fapi.ParseEndpointURL("http://localhost/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	issuerSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	const vct = "https://credentials.example.com/identity_credential"

	iss, err := issuer.New(issuer.Config{
		Issuer:    issuerURL,
		Endpoints: issuer.Endpoints{Credential: credentialEndpoint},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Format:                               sdjwtvc.CredentialFormat,
				Scope:                                "identity_credential",
				VCT:                                  vct,
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}, issuer.Dependencies{
		Clock:       issuer.ClockFunc(time.Now),
		Random:      rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{Signer: issuerSigner, Alg: jose.ES256},
	})
	if err != nil {
		t.Fatalf("issuer.New: %v", err)
	}

	w, err := wallet.New(wallet.Config{
		ProofSigningAlg: jose.ES256,
		Fetch:           fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second, AllowLoopbackHTTP: true},
	}, wallet.Dependencies{
		HTTP: fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
			body, err := json.Marshal(struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
			}{AccessToken: "pre-authorized-access-token", TokenType: "DPoP"})
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     http.Header{"Content-Type": {"application/json"}},
			}, nil
		}},
		Clock:  wallet.ClockFunc(time.Now),
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}

	dpopKey := testP256Key(t)
	tokenResult, err := w.RequestPreAuthorizedCodeToken(context.Background(), tokenEndpoint, wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "oaKazRN8I0IbtZ0C7JuMn5",
		DPoPKey:           dpopKey,
	})
	if err != nil {
		t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
	}
	if tokenResult.AccessToken.Reveal() != "pre-authorized-access-token" {
		t.Fatalf("AccessToken = %q", tokenResult.AccessToken.Reveal())
	}

	resource := dpopProtectedResourceClient{
		w: w, key: dpopKey, accessToken: tokenResult.AccessToken.Reveal(),
		inner: issuerCredentialFake{
			iss:    iss,
			auth:   issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}},
			claims: &sdjwtvc.Claims{VCT: vct},
		},
	}

	result, err := w.RequestCredential(context.Background(), resource, credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          issuerURL.String(),
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(result.Credentials))
	}

	payload, _, err := sdjwtvc.Verify(result.Credentials[0].Credential, &issuerSigner.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if payload["vct"] != vct {
		t.Errorf("vct = %v, want %q", payload["vct"], vct)
	}
}

// issuerDeferredCredentialFake plays the role of a sender-constrained
// Deferred Credential Endpoint call, routing it to a real
// issuer.Issuer's own RequestDeferredCredential — see
// issuerCredentialFake's own doc comment for why sender-constraining
// itself isn't what this proves.
type issuerDeferredCredentialFake struct {
	iss  *issuer.Issuer
	auth issuer.AuthorizedRequest
}

func (f issuerDeferredCredentialFake) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var wire struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}

	result, reqErr := f.iss.RequestDeferredCredential(ctx, f.auth, issuer.DeferredCredentialRequest{TransactionID: wire.TransactionID})
	if reqErr != nil {
		return issuerErrorResponse(reqErr)
	}

	rec := httptest.NewRecorder()
	result.WriteJSON(rec)
	return &http.Response{
		StatusCode: rec.Code,
		Body:       io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
		Header:     rec.Header(),
	}, nil
}

// issuerNotificationFake plays the role of a sender-constrained
// Notification Endpoint call, routing it to a real issuer.Issuer's own
// RequestNotification.
type issuerNotificationFake struct {
	iss  *issuer.Issuer
	auth issuer.AuthorizedRequest
}

func (f issuerNotificationFake) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var wire struct {
		NotificationID   string `json:"notification_id"`
		Event            string `json:"event"`
		EventDescription string `json:"event_description"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}

	reqErr := f.iss.RequestNotification(ctx, f.auth, issuer.NotificationRequest{
		NotificationID:   wire.NotificationID,
		Event:            oid4vci.NotificationEvent(wire.Event),
		EventDescription: wire.EventDescription,
	})
	if reqErr != nil {
		return issuerErrorResponse(reqErr)
	}
	return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil))}, nil
}

// issuerErrorResponse converts an *issuer.Error into the HTTP response
// a real HTTP adapter would have produced via its own WriteJSON.
func issuerErrorResponse(err error) (*http.Response, error) {
	var ierr *issuer.Error
	if !errors.As(err, &ierr) {
		return nil, err
	}
	rec := httptest.NewRecorder()
	ierr.WriteJSON(rec)
	return &http.Response{
		StatusCode: rec.Code,
		Body:       io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
		Header:     rec.Header(),
	}, nil
}

// TestWalletIssuerDeferredAndNotificationRoundTrip drives the Deferred
// Credential Endpoint's polling protocol (pending, then issued) and
// the Notification Endpoint end-to-end against a real issuer.Issuer —
// the transaction's own creation/resolution stands in for whatever
// deployment-specific business process does that for real (see
// issuer.DeferredTransactionRecord's own doc comment), exactly like
// storage.DeferredTransactionStore.Put exists for.
func TestWalletIssuerDeferredAndNotificationRoundTrip(t *testing.T) {
	issuerURL, err := fapi.ParseIssuerURL("http://localhost", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	credentialEndpoint, err := fapi.ParseEndpointURL("http://localhost/credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	deferredEndpoint, err := fapi.ParseEndpointURL("http://localhost/deferred_credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	notificationEndpoint, err := fapi.ParseEndpointURL("http://localhost/notification", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	issuerSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	deferredTransactions := storage.NewDeferredTransactionStore()
	notifications := storage.NewNotificationStore()

	iss, err := issuer.New(issuer.Config{
		Issuer: issuerURL,
		Endpoints: issuer.Endpoints{
			Credential:         credentialEndpoint,
			DeferredCredential: deferredEndpoint,
			Notification:       notificationEndpoint,
		},
		Limits: issuer.Limits{DeferredIssuancePollInterval: 30 * time.Second},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Format:                               sdjwtvc.CredentialFormat,
				Scope:                                "identity_credential",
				VCT:                                  "https://credentials.example.com/identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}, issuer.Dependencies{
		Clock:                issuer.ClockFunc(time.Now),
		Random:               rand.Reader,
		SDJWTSigner:          &issuer.SDJWTSigner{Signer: issuerSigner, Alg: jose.ES256},
		DeferredTransactions: deferredTransactions,
		Notifications:        notifications,
	})
	if err != nil {
		t.Fatalf("issuer.New: %v", err)
	}

	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}

	auth := issuer.AuthorizedRequest{ClientID: "client-a"}
	if err := deferredTransactions.Put(context.Background(), "txn-1", issuer.DeferredTransactionRecord{
		ClientID: "client-a", Status: issuer.DeferredTransactionPending,
	}); err != nil {
		t.Fatalf("Put (pending): %v", err)
	}

	pending, err := w.RequestDeferredCredential(context.Background(), issuerDeferredCredentialFake{iss: iss, auth: auth},
		deferredEndpoint, wallet.DeferredCredentialRequest{TransactionID: "txn-1"})
	if err != nil {
		t.Fatalf("RequestDeferredCredential (pending): %v", err)
	}
	if len(pending.Credentials) != 0 || pending.TransactionID != "txn-1" || pending.Interval != 30*time.Second {
		t.Fatalf("pending result = %+v, want still-pending with a 30s interval", pending)
	}

	if err := deferredTransactions.Put(context.Background(), "txn-1", issuer.DeferredTransactionRecord{
		ClientID: "client-a", Status: issuer.DeferredTransactionIssued,
		Credentials:    []oid4vci.IssuedCredential{{Credential: "signed-credential"}},
		NotificationID: "notif-1",
	}); err != nil {
		t.Fatalf("Put (issued): %v", err)
	}
	if err := notifications.Issue(context.Background(), "notif-1", issuer.NotificationRecord{ClientID: "client-a"}); err != nil {
		t.Fatalf("Issue notification: %v", err)
	}

	issued, err := w.RequestDeferredCredential(context.Background(), issuerDeferredCredentialFake{iss: iss, auth: auth},
		deferredEndpoint, wallet.DeferredCredentialRequest{TransactionID: "txn-1"})
	if err != nil {
		t.Fatalf("RequestDeferredCredential (issued): %v", err)
	}
	if len(issued.Credentials) != 1 || issued.Credentials[0].Credential != "signed-credential" {
		t.Fatalf("issued result = %+v", issued)
	}
	if issued.NotificationID != "notif-1" {
		t.Fatalf("NotificationID = %q, want notif-1", issued.NotificationID)
	}

	if err := w.RequestNotification(context.Background(), issuerNotificationFake{iss: iss, auth: auth}, notificationEndpoint, wallet.NotificationRequest{
		NotificationID: issued.NotificationID,
		Event:          oid4vci.NotificationEventCredentialAccepted,
	}); err != nil {
		t.Fatalf("RequestNotification: %v", err)
	}
}

// walletIssuerRoundTripVCT is the SD-JWT VC vct every
// walletIssuerRoundTripFixture-based test issues against.
const walletIssuerRoundTripVCT = "https://credentials.example.com/identity_credential"

// walletIssuerRoundTripFixture is a real issuer.Issuer wired to a real
// wallet.Wallet over in-memory endpoints, with a c_nonce already drawn
// — the setup TestWalletIssuerRoundTrip and
// TestWalletIssuerAttestationProofRoundTrip both need, parameterized
// only by which proof type "IdentityCredential" accepts and any extra
// issuer.Dependencies (e.g. AttestationVerifier) that proof type
// requires.
type walletIssuerRoundTripFixture struct {
	iss                *issuer.Issuer
	w                  *wallet.Wallet
	issuerURL          fapi.URL
	credentialEndpoint fapi.URL
	issuerSigner       *ecdsa.PrivateKey
	cNonce             string
}

func newWalletIssuerRoundTripFixture(
	t *testing.T, proofType string, ptc issuer.ProofTypeConfiguration, extraDeps issuer.Dependencies,
	mutateConfig ...func(*issuer.Config),
) walletIssuerRoundTripFixture {
	t.Helper()
	issuerURL, err := fapi.ParseIssuerURL("http://localhost", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	credentialEndpoint, err := fapi.ParseEndpointURL("http://localhost/credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	nonceEndpoint, err := fapi.ParseEndpointURL("http://localhost/nonce", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	issuerSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}

	deps := extraDeps
	deps.Nonces = storage.NewNonceStore()
	deps.Clock = issuer.ClockFunc(time.Now)
	deps.Random = rand.Reader
	deps.SDJWTSigner = &issuer.SDJWTSigner{Signer: issuerSigner, Alg: jose.ES256}

	cfg := issuer.Config{
		Issuer: issuerURL,
		Endpoints: issuer.Endpoints{
			Credential: credentialEndpoint,
			Nonce:      nonceEndpoint,
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Format:                               sdjwtvc.CredentialFormat,
				Scope:                                "identity_credential",
				VCT:                                  walletIssuerRoundTripVCT,
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported:                  map[string]issuer.ProofTypeConfiguration{proofType: ptc},
			},
		},
	}
	for _, mutate := range mutateConfig {
		mutate(&cfg)
	}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("issuer.New: %v", err)
	}

	w, err := wallet.New(wallet.Config{
		ProofSigningAlg: jose.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second, AllowLoopbackHTTP: true,
		},
	}, wallet.Dependencies{
		HTTP:  issuerNonceFake{iss: iss},
		Clock: wallet.ClockFunc(time.Now),
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}

	nonceResult, err := w.RequestNonce(context.Background(), nonceEndpoint)
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	if nonceResult.CNonce == "" {
		t.Fatalf("CNonce is empty")
	}

	return walletIssuerRoundTripFixture{
		iss: iss, w: w, issuerURL: issuerURL, credentialEndpoint: credentialEndpoint,
		issuerSigner: issuerSigner, cNonce: nonceResult.CNonce,
	}
}

// verifyIssuedSDJWT checks result carries exactly one Credential and
// that it verifies as an SD-JWT VC signed by f's own issuer key with
// the expected vct — the common final assertion both
// walletIssuerRoundTripFixture-based tests share.
func (f walletIssuerRoundTripFixture) verifyIssuedSDJWT(t *testing.T, result wallet.CredentialResult) {
	t.Helper()
	if len(result.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(result.Credentials))
	}
	payload, _, err := sdjwtvc.Verify(result.Credentials[0].Credential, &f.issuerSigner.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if payload["vct"] != walletIssuerRoundTripVCT {
		t.Errorf("vct = %v, want %q", payload["vct"], walletIssuerRoundTripVCT)
	}
}

// TestWalletIssuerRoundTrip drives a full immediate-issuance flow
// end-to-end — wallet requests a nonce, generates a real jwt-type key
// proof, POSTs a real Credential Request, and parses a real Credential
// Response, all verified by a real issuer.Issuer — to keep wallet's
// own wire format from silently drifting out of sync with what issuer
// actually accepts, and vice versa.
func TestWalletIssuerRoundTrip(t *testing.T) {
	f := newWalletIssuerRoundTripFixture(t, oid4vci.ProofTypeJWT,
		issuer.ProofTypeConfiguration{ProofSigningAlgValuesSupported: []string{"ES256"}}, issuer.Dependencies{})

	resource := issuerCredentialFake{
		iss:    f.iss,
		auth:   issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}},
		claims: &sdjwtvc.Claims{VCT: walletIssuerRoundTripVCT},
	}
	result, err := f.w.RequestCredential(context.Background(), resource, f.credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          f.issuerURL.String(),
		Nonce:                     f.cNonce,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	f.verifyIssuedSDJWT(t, result)
}

// fixedProofBindingKeyResolver plays the role of an issuer's trust
// policy for a jwt-type proof's kid/x5c header
// (issuer.ProofBindingKeyResolver): it always resolves to the one
// binding key this test's proof is actually signed by, standing in for
// whatever real trust mechanism (DID resolution, an x5c chain's own
// trust anchor) a deployment would use.
type fixedProofBindingKeyResolver struct{ pub crypto.PublicKey }

func (r fixedProofBindingKeyResolver) ResolveProofBindingKey(context.Context, map[string]any) (crypto.PublicKey, error) {
	return r.pub, nil
}

// TestWalletIssuerKidProofRoundTrip exercises a kid-conveyed jwt-type
// proof end to end: wallet.GenerateProofWithKeyID signs a proof
// pointing at a kid instead of embedding a jwk, wallet.RequestCredential
// submits it via CredentialRequest.JWTProofs, and a real issuer.Issuer
// resolves the binding key via issuer.ProofBindingKeyResolver before
// issuing — proving wallet's kid-conveyed proof is exactly what
// issuer's own inbound parsing (resolveProofBindingKey) expects.
func TestWalletIssuerKidProofRoundTrip(t *testing.T) {
	bindingKey := testP256Key(t)
	f := newWalletIssuerRoundTripFixture(t, oid4vci.ProofTypeJWT,
		issuer.ProofTypeConfiguration{ProofSigningAlgValuesSupported: []string{"ES256"}}, issuer.Dependencies{
			ProofBindingKeys: fixedProofBindingKeyResolver{pub: &bindingKey.PublicKey},
		})

	kidProof, err := f.w.GenerateProofWithKeyID(bindingKey, "did:example:wallet#key-1", f.issuerURL.String(), f.cNonce)
	if err != nil {
		t.Fatalf("GenerateProofWithKeyID: %v", err)
	}

	resource := issuerCredentialFake{
		iss:    f.iss,
		auth:   issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}},
		claims: &sdjwtvc.Claims{VCT: walletIssuerRoundTripVCT},
	}
	result, err := f.w.RequestCredential(context.Background(), resource, f.credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		JWTProofs:                 []string{kidProof},
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	f.verifyIssuedSDJWT(t, result)
}

// fixedAttestationVerifier plays the role of an issuer's trust policy
// for the attestation proof type (issuer.AttestationVerifier): it
// always resolves to the one attestation-authority key this test
// signs with, standing in for whatever real trust mechanism (x5c
// chain validation, kid lookup, trust_chain resolution) a deployment
// would use.
type fixedAttestationVerifier struct {
	pub crypto.PublicKey
	alg jose.Alg
}

func (f fixedAttestationVerifier) ResolveAttestationKey(context.Context, attestation.KeyAttestation) (crypto.PublicKey, jose.Alg, error) {
	return f.pub, f.alg, nil
}

// TestWalletIssuerAttestationProofRoundTrip exercises the attestation
// proof type (Appendix F.3) end to end: wallet.GenerateAttestationProof
// builds a Key Attestation JWT with the issuer's own fresh c_nonce
// baked in, wallet.RequestCredential submits it as
// CredentialRequest.Attestation, and a real issuer.Issuer resolves and
// verifies it via issuer.AttestationVerifier before issuing — proving
// wallet's attestation proof type wire format is exactly what issuer's
// own inbound parsing (resolveAttestationProofKeys) expects.
func TestWalletIssuerAttestationProofRoundTrip(t *testing.T) {
	attestationSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attestation authority key: %v", err)
	}
	f := newWalletIssuerRoundTripFixture(t, oid4vci.ProofTypeAttestation,
		issuer.ProofTypeConfiguration{ProofSigningAlgValuesSupported: []string{"ES256"}}, issuer.Dependencies{
			AttestationVerifier: fixedAttestationVerifier{pub: &attestationSigner.PublicKey, alg: jose.ES256},
		})

	attestationJWT, err := f.w.GenerateAttestationProof(attestationSigner, jose.ES256, attestation.Header{}, attestation.Claims{
		AttestedKeys: []json.RawMessage{testAttestedKeyJWK(t)},
	}, f.cNonce)
	if err != nil {
		t.Fatalf("GenerateAttestationProof: %v", err)
	}

	resource := issuerCredentialFake{
		iss:    f.iss,
		auth:   issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}},
		claims: &sdjwtvc.Claims{VCT: walletIssuerRoundTripVCT},
	}
	result, err := f.w.RequestCredential(context.Background(), resource, f.credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Attestation:               attestationJWT,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	f.verifyIssuedSDJWT(t, result)
}

// TestWalletIssuerEncryptedRoundTrip drives a full §10-encrypted
// Credential Request/Response exchange end to end against a real
// issuer.Issuer, both sides using their own production encryption
// code (wallet's RequestEncryption/ResponseEncryption via
// issuerCredentialFake's own calls to the real
// DecryptRequestBody/EncryptResponseBody, not a test-only simulation)
// — proving the two independently-built halves (this package's
// Phase 3, issuer's own Phase 2) actually interoperate.
func TestWalletIssuerEncryptedRoundTrip(t *testing.T) {
	requestDecryptionKey := testP256Key(t)
	f := newWalletIssuerRoundTripFixture(t, oid4vci.ProofTypeJWT,
		issuer.ProofTypeConfiguration{ProofSigningAlgValuesSupported: []string{"ES256"}}, issuer.Dependencies{},
		func(cfg *issuer.Config) {
			cfg.RequestEncryption = &issuer.RequestEncryptionSupport{
				Keys:               []issuer.RequestDecryptionKey{{KeyID: "req-1", PrivateKey: requestDecryptionKey}},
				EncValuesSupported: []jwe.Enc{jwe.A128GCM},
			}
			cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{
				EncValuesSupported: []jwe.Enc{jwe.A128GCM},
			}
		})

	md := f.iss.Metadata()
	if md.CredentialRequestEncryption == nil || len(md.CredentialRequestEncryption.JWKS) != 1 {
		t.Fatalf("CredentialRequestEncryption metadata missing or malformed: %+v", md.CredentialRequestEncryption)
	}
	recipientJWK, err := json.Marshal(md.CredentialRequestEncryption.JWKS[0])
	if err != nil {
		t.Fatalf("json.Marshal recipient jwk: %v", err)
	}

	resource := issuerCredentialFake{
		iss:    f.iss,
		auth:   issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}},
		claims: &sdjwtvc.Claims{VCT: walletIssuerRoundTripVCT},
	}
	result, err := f.w.RequestCredential(context.Background(), resource, f.credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          f.issuerURL.String(),
		Nonce:                     f.cNonce,
		RequestEncryption: &wallet.RequestEncryption{
			RecipientJWK: recipientJWK,
			Enc:          jwe.A128GCM,
		},
		ResponseEncryption: &wallet.ResponseEncryption{Enc: jwe.A128GCM},
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	f.verifyIssuedSDJWT(t, result)
}
