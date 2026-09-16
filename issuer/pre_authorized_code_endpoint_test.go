package issuer_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// fakePreAuthorizedCodeStore is an in-memory issuer.PreAuthorizedCodeStore
// for tests.
type fakePreAuthorizedCodeStore struct {
	mu     sync.Mutex
	issued map[string]issuer.PreAuthorizedCodeRecord
}

func newFakePreAuthorizedCodeStore() *fakePreAuthorizedCodeStore {
	return &fakePreAuthorizedCodeStore{issued: map[string]issuer.PreAuthorizedCodeRecord{}}
}

func (f *fakePreAuthorizedCodeStore) Issue(_ context.Context, code string, record issuer.PreAuthorizedCodeRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[code] = record
	return nil
}

func (f *fakePreAuthorizedCodeStore) Consume(_ context.Context, code string) (issuer.PreAuthorizedCodeRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.issued[code]
	delete(f.issued, code)
	if !ok {
		return issuer.PreAuthorizedCodeRecord{}, errPreAuthorizedCodeNotFound
	}
	return record, nil
}

const errPreAuthorizedCodeNotFound = fakeErr("unknown or already-consumed pre-authorized_code")

// fakeDPoPReplayChecker is an in-memory issuer.DPoPReplayChecker for
// tests.
type fakeDPoPReplayChecker struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newFakeDPoPReplayChecker() *fakeDPoPReplayChecker {
	return &fakeDPoPReplayChecker{seen: map[string]bool{}}
}

func (f *fakeDPoPReplayChecker) UseOnce(_ context.Context, jti string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[jti] {
		return fakeErr("jti already used")
	}
	f.seen[jti] = true
	return nil
}

// fakeDPoPNonceStore is an in-memory issuer.DPoPNonceStore for tests.
type fakeDPoPNonceStore struct {
	mu       sync.Mutex
	issued   map[string]time.Time
	consumed map[string]bool
}

func newFakeDPoPNonceStore() *fakeDPoPNonceStore {
	return &fakeDPoPNonceStore{issued: map[string]time.Time{}, consumed: map[string]bool{}}
}

func (f *fakeDPoPNonceStore) Issue(_ context.Context, in issuer.DPoPNonceIssuance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[in.Nonce] = in.ExpiresAt
	return nil
}

func (f *fakeDPoPNonceStore) Consume(_ context.Context, c issuer.DPoPNonceConsumption) (issuer.DPoPNonceRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.issued[c.Nonce]
	if !ok || f.consumed[c.Nonce] {
		return issuer.DPoPNonceRecord{}, errDPoPNonceNotFound
	}
	f.consumed[c.Nonce] = true
	return issuer.DPoPNonceRecord{ExpiresAt: exp}, nil
}

const errDPoPNonceNotFound = fakeErr("dpop nonce not found or already consumed")

// fakeAccessTokenIssuer is an in-memory issuer.AccessTokenIssuer for
// tests, recording the last AccessTokenParams it was called with.
type fakeAccessTokenIssuer struct {
	err        error
	lastParams issuer.AccessTokenParams
}

func (f *fakeAccessTokenIssuer) IssueAccessToken(_ context.Context, p issuer.AccessTokenParams) (string, string, error) {
	f.lastParams = p
	if f.err != nil {
		return "", "", f.err
	}
	return "fake-access-token", "fake-key", nil
}

func testTokenEndpointURL(t *testing.T) fapi.URL {
	t.Helper()
	return mustEndpointURL(t, "https://issuer.example.com/token")
}

// testWalletForDPoP builds a real *wallet.Wallet whose only job in
// these tests is producing real DPoP proofs via GenerateDPoPProof —
// exactly the reuse case that method's own doc comment names.
func testWalletForDPoP(t *testing.T, now time.Time) *wallet.Wallet {
	t.Helper()
	w, err := wallet.New(wallet.Config{
		ProofSigningAlg: jose.ES256,
		Fetch:           fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second},
	}, wallet.Dependencies{
		HTTP:   http.DefaultClient,
		Clock:  wallet.ClockFunc(func() time.Time { return now }),
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}
	return w
}

// preAuthorizedCodeFixture is a real *issuer.Issuer configured for the
// Pre-Authorized Code Flow, plus the fakes ExchangePreAuthorizedCode's
// own Dependencies need.
type preAuthorizedCodeFixture struct {
	iss    *issuer.Issuer
	codes  *fakePreAuthorizedCodeStore
	replay *fakeDPoPReplayChecker
	tokens *fakeAccessTokenIssuer
	now    time.Time
}

func newPreAuthorizedCodeFixture(t *testing.T) preAuthorizedCodeFixture {
	t.Helper()
	return newPreAuthorizedCodeFixtureWith(t, nil)
}

// newPreAuthorizedCodeFixtureWith is newPreAuthorizedCodeFixture's own
// customization point: configure, if non-nil, can set additional
// Config/Dependencies fields (e.g. DPoP nonce-challenge support) before
// New is called.
func newPreAuthorizedCodeFixtureWith(t *testing.T, configure func(cfg *issuer.Config, deps *issuer.Dependencies)) preAuthorizedCodeFixture {
	t.Helper()
	now := time.Now()
	codes := newFakePreAuthorizedCodeStore()
	replay := newFakeDPoPReplayChecker()
	tokens := &fakeAccessTokenIssuer{}

	cfg := validConfig(t)
	cfg.Limits.AccessTokenLifetime = 5 * time.Minute
	cfg.Limits.MaxDPoPProofAge = time.Minute

	deps := validDependencies(t)
	deps.Clock = fixedClock{now: now}
	deps.PreAuthorizedCodes = codes
	deps.DPoPReplay = replay
	deps.AccessTokens = tokens

	if configure != nil {
		configure(&cfg, &deps)
	}

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return preAuthorizedCodeFixture{iss: iss, codes: codes, replay: replay, tokens: tokens, now: now}
}

// issue persists record under code, failing the test on error — every
// case below issues a record it expects to be found (or deliberately
// skips this call to exercise the unknown-code path).
func (f preAuthorizedCodeFixture) issue(t *testing.T, code string, record issuer.PreAuthorizedCodeRecord) {
	t.Helper()
	if err := f.codes.Issue(context.Background(), code, record); err != nil {
		t.Fatalf("Issue: %v", err)
	}
}

// validProof builds a real DPoP proof, targeting testTokenEndpointURL,
// via a throwaway *wallet.Wallet — the same reuse GenerateDPoPProof's
// own doc comment names.
func (f preAuthorizedCodeFixture) validProof(t *testing.T) string {
	t.Helper()
	return f.validProofWithNonce(t, "")
}

// validProofWithNonce is validProof's own twin, setting the proof's own
// "nonce" claim — what a Wallet does on retry after a DPoP
// nonce-challenge (RFC 9449 §9's own client-side half).
func (f preAuthorizedCodeFixture) validProofWithNonce(t *testing.T, nonce string) string {
	t.Helper()
	w := testWalletForDPoP(t, f.now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", testTokenEndpointURL(t).String(), nonce, "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	return proof
}

// requireIssuerErrorCode fails the test unless err is an *issuer.Error
// carrying exactly code.
func requireIssuerErrorCode(t *testing.T, err error, code issuer.ErrorCode) {
	t.Helper()
	var ierr *issuer.Error
	if !errors.As(err, &ierr) {
		t.Fatalf("error = %v, want *issuer.Error", err)
	}
	if ierr.Code() != code {
		t.Errorf("Code = %q, want %q", ierr.Code(), code)
	}
}

func TestExchangePreAuthorizedCode_Success(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})
	proof := f.validProof(t)

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: proof, TokenEndpoint: testTokenEndpointURL(t),
	})
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
	if result.AccessToken != "fake-access-token" {
		t.Errorf("AccessToken = %q", result.AccessToken)
	}
	if result.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want DPoP", result.TokenType)
	}
	if result.ExpiresIn != 5*time.Minute {
		t.Errorf("ExpiresIn = %v, want 5m", result.ExpiresIn)
	}
	if len(f.tokens.lastParams.Scope) != 1 || f.tokens.lastParams.Scope[0] != "identity_credential" {
		t.Errorf("AccessTokenParams.Scope = %v", f.tokens.lastParams.Scope)
	}
	if f.tokens.lastParams.Thumbprint == "" {
		t.Errorf("AccessTokenParams.Thumbprint is empty")
	}

	// Single-use: a second exchange with the same code fails.
	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: proof, TokenEndpoint: testTokenEndpointURL(t),
	}); err == nil {
		t.Fatalf("second ExchangePreAuthorizedCode = nil error, want error")
	}
}

// TestExchangePreAuthorizedCode_MintsAuthorizationDetails checks that
// PreAuthorizedCodeRecord.CredentialConfigurationIDs mints one
// AuthorizationDetail per entry, that it comes back both directly on
// the result (for WriteJSON to echo in the Token Response, §6.2) and
// embedded in the issued access token's own claims (for a later
// RequestCredential call to recover via AuthorizedRequest.AuthorizationDetails).
func TestExchangePreAuthorizedCode_MintsAuthorizationDetails(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, CredentialConfigurationIDs: []string{"IdentityCredential"},
		ExpiresAt: f.now.Add(time.Minute),
	})
	proof := f.validProof(t)

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: proof, TokenEndpoint: testTokenEndpointURL(t),
	})
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
	if len(result.AuthorizationDetails) != 1 {
		t.Fatalf("AuthorizationDetails = %v, want 1 entry", result.AuthorizationDetails)
	}
	ad := result.AuthorizationDetails[0]
	if ad.Type != "openid_credential" {
		t.Errorf("Type = %q, want openid_credential", ad.Type)
	}
	if ad.CredentialConfigurationID != "IdentityCredential" {
		t.Errorf("CredentialConfigurationID = %q, want IdentityCredential", ad.CredentialConfigurationID)
	}
	if len(ad.CredentialIdentifiers) != 1 || ad.CredentialIdentifiers[0] == "" {
		t.Fatalf("CredentialIdentifiers = %v, want exactly one non-empty entry", ad.CredentialIdentifiers)
	}

	raw, ok := f.tokens.lastParams.Claims["authorization_details"]
	if !ok {
		t.Fatalf("AccessTokenParams.Claims is missing authorization_details: %v", f.tokens.lastParams.Claims)
	}
	var fromClaims []issuer.AuthorizationDetail
	if err := json.Unmarshal(raw, &fromClaims); err != nil {
		t.Fatalf("unmarshal authorization_details claim: %v", err)
	}
	if len(fromClaims) != 1 || fromClaims[0].CredentialConfigurationID != "IdentityCredential" {
		t.Errorf("authorization_details claim = %v", fromClaims)
	}
}

// TestExchangePreAuthorizedCode_OmitsAuthorizationDetailsWhenUnconfigured
// checks that leaving CredentialConfigurationIDs empty (the default)
// behaves exactly as it did before this field existed: no
// AuthorizationDetails on the result, and no authorization_details
// claim on the issued access token.
func TestExchangePreAuthorizedCode_OmitsAuthorizationDetailsWhenUnconfigured(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	})
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
	if len(result.AuthorizationDetails) != 0 {
		t.Errorf("AuthorizationDetails = %v, want empty", result.AuthorizationDetails)
	}
	if _, ok := f.tokens.lastParams.Claims["authorization_details"]; ok {
		t.Errorf("AccessTokenParams.Claims has authorization_details: %v", f.tokens.lastParams.Claims)
	}
}

// TestExchangePreAuthorizedCode_RejectsUnsupportedCredentialConfigurationID
// checks that a PreAuthorizedCodeRecord naming a
// credential_configuration_id this issuer doesn't actually support
// fails outright, as a plain (non-*issuer.Error) error — a deployment
// bug, not anything the Wallet did wrong.
func TestExchangePreAuthorizedCode_RejectsUnsupportedCredentialConfigurationID(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, CredentialConfigurationIDs: []string{"NoSuchConfig"},
		ExpiresAt: f.now.Add(time.Minute),
	})

	_, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	})
	if err == nil {
		t.Fatalf("ExchangePreAuthorizedCode = nil error, want error")
	}
	var ierr *issuer.Error
	if errors.As(err, &ierr) {
		t.Errorf("error = %v, want a plain error, not *issuer.Error", err)
	}
}

// TestExchangePreAuthorizedCodeResult_WriteJSON_IncludesAuthorizationDetails
// checks WriteJSON's own body directly, independent of the full
// ExchangePreAuthorizedCode flow.
func TestExchangePreAuthorizedCodeResult_WriteJSON_IncludesAuthorizationDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	issuer.ExchangePreAuthorizedCodeResult{
		AccessToken: "tok", TokenType: "DPoP", ExpiresIn: time.Minute,
		AuthorizationDetails: []issuer.AuthorizationDetail{
			{Type: "openid_credential", CredentialConfigurationID: "IdentityCredential", CredentialIdentifiers: []string{"id-1"}},
		},
	}.WriteJSON(rec)

	var body struct {
		AuthorizationDetails []issuer.AuthorizationDetail `json:"authorization_details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if len(body.AuthorizationDetails) != 1 || body.AuthorizationDetails[0].CredentialConfigurationID != "IdentityCredential" {
		t.Errorf("authorization_details = %v", body.AuthorizationDetails)
	}
}

func TestExchangePreAuthorizedCode_AcceptsMatchingTxCode(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, TxCode: "493536", ExpiresAt: f.now.Add(time.Minute),
	})

	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", TxCode: "493536", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	}); err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
}

// TestExchangePreAuthorizedCode_Rejects table-drives every rejection
// path that surfaces as an *issuer.Error with a specific ErrorCode —
// wrong tx_code, an expired or unknown code, and an invalid DPoP
// proof.
func TestExchangePreAuthorizedCode_Rejects(t *testing.T) {
	cases := map[string]struct {
		setup    func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest
		wantCode issuer.ErrorCode
	}{
		"wrong tx_code": {
			wantCode: issuer.ErrorInvalidGrant,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
					Scopes: []string{"identity_credential"}, TxCode: "493536", ExpiresAt: f.now.Add(time.Minute),
				})
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "code-1", TxCode: "wrong", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
				}
			},
		},
		"expired code": {
			wantCode: issuer.ErrorInvalidGrant,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
					Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(-time.Minute),
				})
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
				}
			},
		},
		"unknown code": {
			wantCode: issuer.ErrorInvalidGrant,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "unknown-code", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
				}
			},
		},
		"invalid DPoP proof": {
			wantCode: issuer.ErrorInvalidTokenRequest,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
					Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
				})
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "code-1", DPoPProof: "not-a-proof", TokenEndpoint: testTokenEndpointURL(t),
				}
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPreAuthorizedCodeFixture(t)
			req := tc.setup(t, f)
			_, err := f.iss.ExchangePreAuthorizedCode(context.Background(), req)
			requireIssuerErrorCode(t, err, tc.wantCode)
		})
	}
}

// TestExchangePreAuthorizedCode_RejectsMissingFields table-drives the
// remaining rejection paths, each a plain (non-*issuer.Error) error:
// missing required request fields, and the grant not being configured
// at all.
func TestExchangePreAuthorizedCode_RejectsMissingFields(t *testing.T) {
	cases := map[string]func(t *testing.T) (*issuer.Issuer, issuer.ExchangePreAuthorizedCodeRequest){
		"missing pre-authorized_code": func(t *testing.T) (*issuer.Issuer, issuer.ExchangePreAuthorizedCodeRequest) {
			f := newPreAuthorizedCodeFixture(t)
			return f.iss, issuer.ExchangePreAuthorizedCodeRequest{DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t)}
		},
		"missing DPoP proof": func(t *testing.T) (*issuer.Issuer, issuer.ExchangePreAuthorizedCodeRequest) {
			f := newPreAuthorizedCodeFixture(t)
			f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
				Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
			})
			return f.iss, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-1", TokenEndpoint: testTokenEndpointURL(t)}
		},
		"grant not configured": func(t *testing.T) (*issuer.Issuer, issuer.ExchangePreAuthorizedCodeRequest) {
			iss, err := issuer.New(validConfig(t), validDependencies(t))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			return iss, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-1", DPoPProof: "irrelevant", TokenEndpoint: testTokenEndpointURL(t)}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			iss, req := setup(t)
			if _, err := iss.ExchangePreAuthorizedCode(context.Background(), req); err == nil {
				t.Fatalf("ExchangePreAuthorizedCode(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsInvalidPreAuthorizedCodeDependencies(t *testing.T) {
	cases := map[string]func(*issuer.Config, *issuer.Dependencies){
		"missing access_token_lifetime": func(cfg *issuer.Config, d *issuer.Dependencies) {
			cfg.Limits.MaxDPoPProofAge = time.Minute
			d.PreAuthorizedCodes, d.DPoPReplay, d.AccessTokens = newFakePreAuthorizedCodeStore(), newFakeDPoPReplayChecker(), &fakeAccessTokenIssuer{}
		},
		"missing max_dpop_proof_age": func(cfg *issuer.Config, d *issuer.Dependencies) {
			cfg.Limits.AccessTokenLifetime = 5 * time.Minute
			d.PreAuthorizedCodes, d.DPoPReplay, d.AccessTokens = newFakePreAuthorizedCodeStore(), newFakeDPoPReplayChecker(), &fakeAccessTokenIssuer{}
		},
		"missing dpop_replay": func(cfg *issuer.Config, d *issuer.Dependencies) {
			cfg.Limits.AccessTokenLifetime, cfg.Limits.MaxDPoPProofAge = 5*time.Minute, time.Minute
			d.PreAuthorizedCodes, d.AccessTokens = newFakePreAuthorizedCodeStore(), &fakeAccessTokenIssuer{}
		},
		"missing access_tokens": func(cfg *issuer.Config, d *issuer.Dependencies) {
			cfg.Limits.AccessTokenLifetime, cfg.Limits.MaxDPoPProofAge = 5*time.Minute, time.Minute
			d.PreAuthorizedCodes, d.DPoPReplay = newFakePreAuthorizedCodeStore(), newFakeDPoPReplayChecker()
		},
		"dpop nonces without lifetime": func(cfg *issuer.Config, d *issuer.Dependencies) {
			cfg.Limits.AccessTokenLifetime, cfg.Limits.MaxDPoPProofAge = 5*time.Minute, time.Minute
			d.PreAuthorizedCodes, d.DPoPReplay, d.AccessTokens = newFakePreAuthorizedCodeStore(), newFakeDPoPReplayChecker(), &fakeAccessTokenIssuer{}
			d.DPoPNonces = newFakeDPoPNonceStore()
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			deps := validDependencies(t)
			mutate(&cfg, &deps)
			if _, err := issuer.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewAcceptsValidPreAuthorizedCodeDependencies(t *testing.T) {
	cfg := validConfig(t)
	cfg.Limits.AccessTokenLifetime = 5 * time.Minute
	cfg.Limits.MaxDPoPProofAge = time.Minute
	deps := validDependencies(t)
	deps.PreAuthorizedCodes = newFakePreAuthorizedCodeStore()
	deps.DPoPReplay = newFakeDPoPReplayChecker()
	deps.AccessTokens = &fakeAccessTokenIssuer{}
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewAcceptsValidDPoPNonceDependencies(t *testing.T) {
	cfg := validConfig(t)
	cfg.Limits.AccessTokenLifetime = 5 * time.Minute
	cfg.Limits.MaxDPoPProofAge = time.Minute
	cfg.Limits.DPoPNonceLifetime = time.Minute
	deps := validDependencies(t)
	deps.PreAuthorizedCodes = newFakePreAuthorizedCodeStore()
	deps.DPoPReplay = newFakeDPoPReplayChecker()
	deps.AccessTokens = &fakeAccessTokenIssuer{}
	deps.DPoPNonces = newFakeDPoPNonceStore()
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// newPreAuthorizedCodeFixtureWithDPoPNonces is
// newPreAuthorizedCodeFixtureWith's own DPoP-nonce-challenge preset —
// every test below shares this setup.
func newPreAuthorizedCodeFixtureWithDPoPNonces(t *testing.T) (preAuthorizedCodeFixture, *fakeDPoPNonceStore) {
	t.Helper()
	nonces := newFakeDPoPNonceStore()
	f := newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.Limits.DPoPNonceLifetime = time.Minute
		deps.DPoPNonces = nonces
	})
	return f, nonces
}

// TestExchangePreAuthorizedCode_ChallengesMissingNonceThenSucceedsOnRetryWithoutLosingTheCode
// is the critical regression test for this feature: a first attempt
// presenting no nonce at all must be challenged (RFC 9449 §8) without
// ever consuming the single-use pre-authorized_code — otherwise the
// Wallet's second, correctly-nonced attempt (it had no way to know the
// nonce on the first try) would fail with "already used" instead of
// succeeding.
func TestExchangePreAuthorizedCode_ChallengesMissingNonceThenSucceedsOnRetryWithoutLosingTheCode(t *testing.T) {
	f, _ := newPreAuthorizedCodeFixtureWithDPoPNonces(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	_, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	})
	requireIssuerErrorCode(t, err, issuer.ErrorUseDPoPNonce)
	var ierr *issuer.Error
	if !errors.As(err, &ierr) || ierr.Nonce() == "" {
		t.Fatalf("error = %v, want a non-empty Nonce()", err)
	}

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProofWithNonce(t, ierr.Nonce()), TokenEndpoint: testTokenEndpointURL(t),
	})
	if err != nil {
		t.Fatalf("retry ExchangePreAuthorizedCode: %v", err)
	}
	if result.AccessToken != "fake-access-token" {
		t.Errorf("AccessToken = %q", result.AccessToken)
	}
	if result.NextDPoPNonce == "" {
		t.Errorf("NextDPoPNonce is empty, want a proactively issued replacement")
	}
}

func TestExchangePreAuthorizedCode_ChallengesUnknownNonce(t *testing.T) {
	f, _ := newPreAuthorizedCodeFixtureWithDPoPNonces(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	_, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProofWithNonce(t, "never-issued"), TokenEndpoint: testTokenEndpointURL(t),
	})
	requireIssuerErrorCode(t, err, issuer.ErrorUseDPoPNonce)
}

func TestExchangePreAuthorizedCode_ChallengesExpiredNonce(t *testing.T) {
	f, nonces := newPreAuthorizedCodeFixtureWithDPoPNonces(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})
	if err := nonces.Issue(context.Background(), issuer.DPoPNonceIssuance{
		Nonce: "expired-nonce", ExpiresAt: f.now.Add(-time.Second),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProofWithNonce(t, "expired-nonce"), TokenEndpoint: testTokenEndpointURL(t),
	})
	requireIssuerErrorCode(t, err, issuer.ErrorUseDPoPNonce)
}

// TestExchangePreAuthorizedCode_NextDPoPNonceEmptyWhenDisabled checks
// that nonce-challenge support stays fully opt-in: with
// Dependencies.DPoPNonces unset (the default fixture), a successful
// exchange never sets NextDPoPNonce, and no nonce is required at all.
func TestExchangePreAuthorizedCode_NextDPoPNonceEmptyWhenDisabled(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	})
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
	if result.NextDPoPNonce != "" {
		t.Errorf("NextDPoPNonce = %q, want empty", result.NextDPoPNonce)
	}
}

// TestExchangePreAuthorizedCodeResult_WriteJSON_SetsDPoPNonceHeader
// checks WriteJSON's own header behavior directly, independent of the
// full ExchangePreAuthorizedCode flow.
func TestExchangePreAuthorizedCodeResult_WriteJSON_SetsDPoPNonceHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	issuer.ExchangePreAuthorizedCodeResult{
		AccessToken: "tok", TokenType: "DPoP", ExpiresIn: time.Minute, NextDPoPNonce: "fresh-nonce",
	}.WriteJSON(rec)
	if got := rec.Header().Get("DPoP-Nonce"); got != "fresh-nonce" {
		t.Errorf("DPoP-Nonce header = %q, want %q", got, "fresh-nonce")
	}
}

// TestError_WriteJSON_SetsDPoPNonceHeaderForUseDPoPNonce checks that a
// use_dpop_nonce challenge's own WriteJSON sets the DPoP-Nonce header
// (RFC 9449 §8) — exercised indirectly through
// ExchangePreAuthorizedCode's own error return, since *issuer.Error's
// nonce field has no exported constructor.
func TestError_WriteJSON_SetsDPoPNonceHeaderForUseDPoPNonce(t *testing.T) {
	f, _ := newPreAuthorizedCodeFixtureWithDPoPNonces(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	_, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	})
	var ierr *issuer.Error
	if !errors.As(err, &ierr) {
		t.Fatalf("error = %v, want *issuer.Error", err)
	}

	rec := httptest.NewRecorder()
	ierr.WriteJSON(rec)
	if got := rec.Header().Get("DPoP-Nonce"); got == "" || got != ierr.Nonce() {
		t.Errorf("DPoP-Nonce header = %q, want %q", got, ierr.Nonce())
	}
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
