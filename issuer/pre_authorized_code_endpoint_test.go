package issuer_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// fakePreAuthorizedCodeStore is an in-memory issuer.PreAuthorizedCodeStore
// for tests.
type fakePreAuthorizedCodeStore struct {
	mu       sync.Mutex
	issued   map[string]issuer.PreAuthorizedCodeRecord
	attempts map[string]int
}

func newFakePreAuthorizedCodeStore() *fakePreAuthorizedCodeStore {
	return &fakePreAuthorizedCodeStore{
		issued:   map[string]issuer.PreAuthorizedCodeRecord{},
		attempts: map[string]int{},
	}
}

func (f *fakePreAuthorizedCodeStore) Issue(_ context.Context, code string, record issuer.PreAuthorizedCodeRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[code] = record
	return nil
}

func (f *fakePreAuthorizedCodeStore) Consume(_ context.Context, code, wantTxCodeHash string, maxAttempts int, accept func(issuer.PreAuthorizedCodeRecord) error) (issuer.PreAuthorizedCodeRecord, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.issued[code]
	if !ok {
		return issuer.PreAuthorizedCodeRecord{}, 0, errPreAuthorizedCodeNotFound
	}
	switch {
	case record.TxCodeHash == "" && wantTxCodeHash != "":
		return issuer.PreAuthorizedCodeRecord{}, 0, issuer.ErrTxCodeUnexpected
	case record.TxCodeHash != "" && wantTxCodeHash == "" && (maxAttempts <= 0 || f.attempts[code] < maxAttempts):
		return issuer.PreAuthorizedCodeRecord{}, 0, issuer.ErrTxCodeRequired
	}
	if record.TxCodeHash != "" && maxAttempts > 0 && f.attempts[code] >= maxAttempts {
		delete(f.issued, code)
		return issuer.PreAuthorizedCodeRecord{}, 0, issuer.ErrTooManyTxCodeAttempts
	}
	if record.TxCodeHash != "" && wantTxCodeHash != record.TxCodeHash {
		f.attempts[code]++
		if maxAttempts > 0 && f.attempts[code] >= maxAttempts {
			delete(f.issued, code)
		}
		return issuer.PreAuthorizedCodeRecord{}, f.attempts[code], issuer.ErrWrongTxCode
	}
	if accept != nil {
		if err := accept(record); err != nil {
			return issuer.PreAuthorizedCodeRecord{}, 0, err
		}
	}
	delete(f.issued, code)
	delete(f.attempts, code)
	return record, 0, nil
}

func (f *fakePreAuthorizedCodeStore) Invalidate(_ context.Context, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.issued, code)
	delete(f.attempts, code)
	return nil
}

var errPreAuthorizedCodeNotFound = fmt.Errorf("fake: %w", issuer.ErrPreAuthorizedCodeUnknown)

// fakeAccessTokenIssuer is an in-memory issuer.AccessTokenIssuer for
// tests, recording the last AccessTokenParams it was called with.
type fakeAccessTokenIssuer struct {
	mu         sync.Mutex
	err        error
	lastParams issuer.AccessTokenParams
}

func (f *fakeAccessTokenIssuer) IssueAccessToken(_ context.Context, p issuer.AccessTokenParams) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastParams = p
	if f.err != nil {
		return "", "", f.err
	}
	return "fake-access-token", "fake-key", nil
}

// anonymousTokenRequest is what the Authorization Server verified about
// an anonymous pre-authorized_code Token Request
// (fapigo/server.Server.VerifyTokenRequestDPoP): its DPoP key, with no
// client.
func anonymousTokenRequest() *issuer.VerifiedTokenRequest {
	return &issuer.VerifiedTokenRequest{DPoPThumbprint: "test-dpop-jkt"}
}

// preAuthorizedCodeFixture is a real *issuer.Issuer configured for the
// Pre-Authorized Code Flow, plus the fakes ExchangePreAuthorizedCode's
// own Dependencies need.
type preAuthorizedCodeFixture struct {
	iss    *issuer.Issuer
	codes  *fakePreAuthorizedCodeStore
	tokens *fakeAccessTokenIssuer
	now    time.Time
}

func newPreAuthorizedCodeFixture(t *testing.T) preAuthorizedCodeFixture {
	t.Helper()
	return newPreAuthorizedCodeFixtureWith(t, nil)
}

// newPreAuthorizedCodeFixtureWith is newPreAuthorizedCodeFixture's own
// customization point: configure, if non-nil, can set additional
// Config/Dependencies fields before
// New is called.
func newPreAuthorizedCodeFixtureWith(t *testing.T, configure func(cfg *issuer.Config, deps *issuer.Dependencies)) preAuthorizedCodeFixture {
	t.Helper()
	now := time.Now()
	codes := newFakePreAuthorizedCodeStore()
	tokens := &fakeAccessTokenIssuer{}

	cfg := validConfig(t)
	cfg.Limits.AccessTokenLifetime = 5 * time.Minute
	cfg.Limits.MaxTxCodeAttempts = 3

	deps := validDependencies(t)
	deps.Clock = fixedClock{now: now}
	deps.PreAuthorizedCodes = codes
	deps.AccessTokens = tokens

	if configure != nil {
		configure(&cfg, &deps)
	}

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return preAuthorizedCodeFixture{iss: iss, codes: codes, tokens: tokens, now: now}
}

// issue persists record under code, failing the test on error — every
// case below issues a record it expects to be found (or deliberately
// skips this call to exercise the unknown-code path).
func (f preAuthorizedCodeFixture) issue(t *testing.T, code string, record issuer.PreAuthorizedCodeRecord) {
	t.Helper()
	f.issueWithTxCode(t, code, "", record)
}

// issueWithTxCode is issue for a code whose holder must enter txCode.
func (f preAuthorizedCodeFixture) issueWithTxCode(t *testing.T, code, txCode string, record issuer.PreAuthorizedCodeRecord) {
	t.Helper()
	if err := f.iss.IssuePreAuthorizedCode(context.Background(), code, txCode, record); err != nil {
		t.Fatalf("IssuePreAuthorizedCode: %v", err)
	}
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

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
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
	if f.tokens.lastParams.Subject != "" {
		t.Errorf("AccessTokenParams.Subject = %q, want empty for a record with no Subject", f.tokens.lastParams.Subject)
	}

	// Single-use: a second exchange with the same code fails.
	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
	}); err == nil {
		t.Fatalf("second ExchangePreAuthorizedCode = nil error, want error")
	}
}

// TestExchangePreAuthorizedCode_PassesSubjectThrough checks that a
// record's Subject reaches AccessTokenParams unmodified — the only link
// from a redeemed pre-authorized_code to whatever the caller verified
// before making the offer.
func TestExchangePreAuthorizedCode_PassesSubjectThrough(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
		Subject: "txn-8fd2",
	})
	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
	})
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
	if got := f.tokens.lastParams.Subject; got != "txn-8fd2" {
		t.Errorf("AccessTokenParams.Subject = %q, want %q", got, "txn-8fd2")
	}
	// What a refresh token for the grant would be issued for.
	if result.Subject != "txn-8fd2" || len(result.Scope) != 1 || result.Scope[0] != "identity_credential" {
		t.Errorf("result Subject %q, Scope %v; want the record's", result.Subject, result.Scope)
	}
}

// A refresh token the caller sets is the Token Response's
// refresh_token; none is written when it's unset.
func TestExchangePreAuthorizedCodeResult_WriteJSON_RefreshToken(t *testing.T) {
	for _, tc := range []struct{ token, want string }{{"rt-1", "rt-1"}, {"", ""}} {
		rec := httptest.NewRecorder()
		issuer.ExchangePreAuthorizedCodeResult{
			AccessToken: "tok", TokenType: "DPoP", ExpiresIn: time.Minute, RefreshToken: fapi.NewSecret(tc.token),
		}.WriteJSON(rec)
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if cc, pragma := rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"); cc != "no-store" || pragma != "no-cache" {
			t.Errorf("Cache-Control = %q, Pragma = %q, want no-store and no-cache (RFC 6749 §5.1)", cc, pragma)
		}
		got, present := body["refresh_token"]
		if tc.want == "" && present || tc.want != "" && got != tc.want {
			t.Errorf("refresh token %q: body = %s", tc.token, rec.Body.String())
		}
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

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
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
	var fromClaims []oid4vci.AuthorizationDetail
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
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
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
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
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
		AuthorizationDetails: []oid4vci.AuthorizationDetail{
			{Type: "openid_credential", CredentialConfigurationID: "IdentityCredential", CredentialIdentifiers: []string{"id-1"}},
		},
	}.WriteJSON(rec)

	var body struct {
		AuthorizationDetails []oid4vci.AuthorizationDetail `json:"authorization_details"`
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
	f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", TxCode: "493536", Verified: anonymousTokenRequest(),
	}); err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
}

// TestExchangePreAuthorizedCode_WrongTxCodeThenSucceedsOnRetryWithoutLosingTheCode
// is the end-to-end regression test (mirroring
// TestExchangePreAuthorizedCode_ChallengesMissingNonceThenSucceedsOnRetryWithoutLosingTheCode's
// own "retry without losing the code" shape) for a real bug found in
// a repo-wide security review: PreAuthorizedCodeStore.Consume used to
// invalidate the code unconditionally, before checking TxCode — a
// single mistyped PIN permanently destroyed the code with no retry
// path. A wrong guess must now leave the code usable for a correct
// retry.
func TestExchangePreAuthorizedCode_WrongTxCodeThenSucceedsOnRetryWithoutLosingTheCode(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	_, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", TxCode: "wrong", Verified: anonymousTokenRequest(),
	})
	requireIssuerErrorCode(t, err, issuer.ErrorInvalidGrant)

	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", TxCode: "493536", Verified: anonymousTokenRequest(),
	}); err != nil {
		t.Fatalf("retry ExchangePreAuthorizedCode with the correct tx_code: %v", err)
	}
}

// submitWrongTxCodeAttempts calls ExchangePreAuthorizedCode against
// code with a wrong tx_code n times, returning the last error — shared
// by the two lockout tests below, which each need to submit exactly
// one attempt under Config.Limits.MaxTxCodeAttempts (still retryable)
// or exactly at it (invalidating) before checking what happens next.
func submitWrongTxCodeAttempts(t *testing.T, f preAuthorizedCodeFixture, code string, n int) error {
	t.Helper()
	var err error
	for i := 0; i < n; i++ {
		_, err = f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: code, TxCode: "wrong", Verified: anonymousTokenRequest(),
		})
	}
	return err
}

// TestExchangePreAuthorizedCode_TooManyWrongTxCodeAttemptsInvalidatesCode
// is the end-to-end regression test for the tx_code guessing risk a
// repo-wide security review found: since a wrong tx_code deliberately
// never invalidates the code on its own (see the "retry without
// losing the code" test above), nothing else bounded how many guesses
// an attacker holding a leaked pre-authorized_code got. Once
// wrongAttempts reaches Config.Limits.MaxTxCodeAttempts (3 in this
// fixture — see newPreAuthorizedCodeFixtureWith), the code must be
// permanently invalidated — even a subsequent correct guess fails.
func TestExchangePreAuthorizedCode_TooManyWrongTxCodeAttemptsInvalidatesCode(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})
	err := submitWrongTxCodeAttempts(t, f, "code-1", 3)
	requireIssuerErrorCode(t, err, issuer.ErrorInvalidGrant)

	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", TxCode: "493536", Verified: anonymousTokenRequest(),
	}); err == nil {
		t.Fatalf("ExchangePreAuthorizedCode with the correct tx_code after too many wrong attempts = nil error, want error (code should be invalidated)")
	}
}

// TestExchangePreAuthorizedCode_StaysUnderTheAttemptLimitRemainsRetryable
// exercises the boundary from the other side: with
// Config.Limits.MaxTxCodeAttempts set to 3, exactly 2 wrong guesses
// must NOT invalidate the code — only the 3rd does (see the test
// above).
func TestExchangePreAuthorizedCode_StaysUnderTheAttemptLimitRemainsRetryable(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})
	err := submitWrongTxCodeAttempts(t, f, "code-1", 2)
	requireIssuerErrorCode(t, err, issuer.ErrorInvalidGrant)

	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", TxCode: "493536", Verified: anonymousTokenRequest(),
	}); err != nil {
		t.Fatalf("ExchangePreAuthorizedCode with the correct tx_code after 2 wrong attempts (under the limit of 3): %v", err)
	}
}

// TestExchangePreAuthorizedCode_Rejects table-drives every rejection
// path that surfaces as an *issuer.Error with a specific ErrorCode —
// wrong tx_code, and an expired or unknown code.
func TestExchangePreAuthorizedCode_Rejects(t *testing.T) {
	cases := map[string]struct {
		setup    func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest
		wantCode issuer.ErrorCode
	}{
		"wrong tx_code": {
			wantCode: issuer.ErrorInvalidGrant,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{
					Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
				})
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "code-1", TxCode: "wrong", Verified: anonymousTokenRequest(),
				}
			},
		},
		"missing tx_code": {
			wantCode: issuer.ErrorInvalidTokenRequest,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{
					Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
				})
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
				}
			},
		},
		"unexpected tx_code": {
			wantCode: issuer.ErrorInvalidTokenRequest,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
					Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
				})
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "code-1", TxCode: "493536", Verified: anonymousTokenRequest(),
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
					PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
				}
			},
		},
		"unknown code": {
			wantCode: issuer.ErrorInvalidGrant,
			setup: func(t *testing.T, f preAuthorizedCodeFixture) issuer.ExchangePreAuthorizedCodeRequest {
				return issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "unknown-code", Verified: anonymousTokenRequest(),
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
			return f.iss, issuer.ExchangePreAuthorizedCodeRequest{Verified: anonymousTokenRequest()}
		},
		"missing Verified": func(t *testing.T) (*issuer.Issuer, issuer.ExchangePreAuthorizedCodeRequest) {
			f := newPreAuthorizedCodeFixture(t)
			f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
				Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
			})
			return f.iss, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-1"}
		},
		"grant not configured": func(t *testing.T) (*issuer.Issuer, issuer.ExchangePreAuthorizedCodeRequest) {
			iss, err := issuer.New(validConfig(t), validDependencies(t))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			return iss, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest()}
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
			cfg.Limits.MaxTxCodeAttempts = 3
			d.PreAuthorizedCodes, d.AccessTokens = newFakePreAuthorizedCodeStore(), &fakeAccessTokenIssuer{}
		},
		"missing max_tx_code_attempts": func(cfg *issuer.Config, d *issuer.Dependencies) {
			cfg.Limits.AccessTokenLifetime = 5 * time.Minute
			d.PreAuthorizedCodes, d.AccessTokens = newFakePreAuthorizedCodeStore(), &fakeAccessTokenIssuer{}
		},
		"missing access_tokens": func(cfg *issuer.Config, d *issuer.Dependencies) {
			cfg.Limits.AccessTokenLifetime, cfg.Limits.MaxTxCodeAttempts = 5*time.Minute, 3
			d.PreAuthorizedCodes = newFakePreAuthorizedCodeStore()
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
	cfg.Limits.MaxTxCodeAttempts = 3
	deps := validDependencies(t)
	deps.PreAuthorizedCodes = newFakePreAuthorizedCodeStore()
	deps.AccessTokens = &fakeAccessTokenIssuer{}
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// TestExchangePreAuthorizedCode_NextDPoPNonceEmptyWhenDisabled checks
// that an Authorization Server using no DPoP nonces (no
// VerifiedTokenRequest.NextDPoPNonce) gets a Token Response without
// one.
func TestExchangePreAuthorizedCode_NextDPoPNonceEmptyWhenDisabled(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})

	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
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
