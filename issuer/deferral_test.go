package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// deferralFixture is a credentialEndpointFixture that can defer: a
// Deferred Credential Endpoint, a store and a notification store.
type deferralFixture struct {
	credentialEndpointFixture
	store *fakeDeferredTransactionStore
	clock *mutableClock
}

type mutableClock struct{ now time.Time }

func (c *mutableClock) Now() time.Time { return c.now }

func newDeferralFixture(t *testing.T) deferralFixture {
	t.Helper()
	store, clock := newFakeDeferredTransactionStore(), &mutableClock{now: time.Now()}
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.Endpoints.DeferredCredential = mustEndpointURL(t, testDeferredCredentialEndpoint)
		cfg.Endpoints.Notification = mustEndpointURL(t, testNotificationEndpoint)
		cfg.Limits.DeferredIssuancePollInterval = 5 * time.Second
		cfg.Limits.DeferredTransactionLifetime = time.Hour
		deps.DeferredTransactions, deps.Notifications = store, newFakeNotificationStore()
		deps.Clock = clock
		clock.now = deps.Clock.Now()
	})
	return deferralFixture{credentialEndpointFixture: f, store: store, clock: clock}
}

var deferralAuth = issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Subject: "holder-1", Scopes: []string{"identity_credential"}}

// deferOne defers a one-credential SD-JWT VC request, returning its
// transaction_id and the Wallet key its proof is bound to.
func (f deferralFixture) deferOne(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	walletKey := testP256Key(t)
	resp, err := f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, walletKey, testIssuer, f.issueNonce(t))}},
		Defer:                     &issuer.Deferral{Reference: "kyc-42"},
	})
	if err != nil {
		t.Fatalf("RequestCredential (deferred): %v", err)
	}
	if resp.TransactionID == "" || resp.Interval != 5 || len(resp.Credentials) != 0 {
		t.Fatalf("response = %+v, want a transaction_id, interval 5 and no credentials", resp)
	}
	return resp.TransactionID, walletKey
}

func TestDeferral_IssueLater(t *testing.T) {
	f := newDeferralFixture(t)
	ctx := context.Background()
	txID, walletKey := f.deferOne(t)

	record, err := f.store.Get(ctx, txID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != issuer.DeferredTransactionPending || record.ClientID != "test-client" || record.Subject != "holder-1" || record.Reference != "kyc-42" ||
		record.CredentialConfigurationID != testSDJWTConfigID || len(record.BindingKeys) != 1 || !record.ExpiresAt.Equal(f.clock.now.Add(time.Hour)) {
		t.Fatalf("record = %+v", record)
	}
	if _, err := f.nonces.Consume(ctx, issuer.NonceConsumption{Nonce: "test-nonce"}); err == nil {
		t.Error("the proof's nonce wasn't consumed when the request was deferred")
	}

	poll := func() (issuer.DeferredCredentialResult, error) {
		return f.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: txID})
	}
	if res, err := poll(); err != nil || res.TransactionID != txID || len(res.Credentials) != 0 {
		t.Fatalf("poll while pending = %+v, %v", res, err)
	}

	if err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
		t.Fatalf("IssueDeferredCredential: %v", err)
	}
	if err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); !errors.Is(err, issuer.ErrDeferredTransactionResolved) {
		t.Errorf("second IssueDeferredCredential = %v, want ErrDeferredTransactionResolved", err)
	}
	res, err := poll()
	if err != nil || len(res.Credentials) != 1 || res.NotificationID == "" {
		t.Fatalf("poll after issuance = %+v, %v", res, err)
	}
	payload, _, err := sdjwtvc.Verify(res.Credentials[0].Credential, &f.sdjwtSigner.Signer.(*ecdsa.PrivateKey).PublicKey, jose.ES256,
		sdjwtvc.VerifyOptions{RequireKeyBinding: sdjwtvc.KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	cnf, _ := payload["cnf"].(map[string]any)
	jwkMap, _ := cnf["jwk"].(map[string]any)
	if x, _ := jwkMap["x"].(string); x == "" || x != jwkX(t, &walletKey.PublicKey) {
		t.Errorf("credential bound to %v, want the proof's key", cnf)
	}
	if _, err := poll(); err == nil {
		t.Error("the transaction's credentials were served twice")
	}
}

func jwkX(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(jwkJSON(t, pub), &m); err != nil {
		t.Fatal(err)
	}
	x, _ := m["x"].(string)
	return x
}

func TestDeferral_DenyAndExpire(t *testing.T) {
	f := newDeferralFixture(t)
	ctx := context.Background()

	denied, _ := f.deferOne(t)
	if err := f.iss.DenyDeferredCredential(ctx, denied); err != nil {
		t.Fatalf("DenyDeferredCredential: %v", err)
	}
	_, err := f.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: denied})
	assertIssuerError(t, err, issuer.ErrorCredentialRequestDenied)
	if err := f.iss.DenyDeferredCredential(ctx, denied); !errors.Is(err, issuer.ErrDeferredTransactionResolved) {
		t.Errorf("second deny = %v, want ErrDeferredTransactionResolved", err)
	}

	expired := newDeferralFixture(t)
	txID, _ := expired.deferOne(t)
	expired.clock.now = expired.clock.now.Add(2 * time.Hour)
	_, err = expired.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: txID})
	assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
	if err := expired.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); !errors.Is(err, issuer.ErrDeferredTransactionResolved) {
		t.Errorf("IssueDeferredCredential after expiry = %v, want ErrDeferredTransactionResolved", err)
	}
	if err := expired.iss.IssueDeferredCredential(ctx, "unknown", issuer.DeferredIssuance{}); err == nil {
		t.Error("IssueDeferredCredential accepted an unknown transaction")
	}
}

func TestDeferral_NeedsADeferredEndpoint(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		Defer:                     &issuer.Deferral{},
	})
	if err == nil {
		t.Fatal("an issuer without a Deferred Credential Endpoint deferred a request")
	}
	if _, err := f.nonces.Consume(context.Background(), issuer.NonceConsumption{Nonce: "test-nonce"}); err != nil {
		t.Errorf("the nonce was consumed by a request that couldn't be deferred: %v", err)
	}
	if err := f.iss.DenyDeferredCredential(context.Background(), "x"); err == nil {
		t.Error("DenyDeferredCredential worked without a store")
	}
}

// TestDeferral_Handlers: CredentialHandler answers a deferral with 202,
// and DeferredCredentialHandler's Resolve issues on the first poll —
// only for the polling client's own transaction.
func TestDeferral_Handlers(t *testing.T) {
	f := newDeferralFixture(t)
	h, err := f.iss.CredentialHandler(issuer.CredentialHandlerConfig{
		URL: mustURL(t, testCredentialEndpoint), Tokens: &fakeTokens{grant: issuer.Grant{Authorized: deferralAuth}},
		Prepare: func(_ context.Context, _ issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			req.Defer = &issuer.Deferral{}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := postCredentialRequest(t, h, sdjwtCredentialRequestBody(t, f.credentialEndpointFixture))
	var deferred struct {
		TransactionID string `json:"transaction_id"`
		Interval      int64  `json:"interval"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &deferred); err != nil || w.Code != http.StatusAccepted || deferred.TransactionID == "" || deferred.Interval != 5 {
		t.Fatalf("deferred response = %d %s", w.Code, w.Body)
	}

	resolved := 0
	deferredHandler := func(clientID, subject string) http.Handler {
		t.Helper()
		dh, err := f.iss.DeferredCredentialHandler(issuer.DeferredCredentialHandlerConfig{
			ProtectedEndpointConfig: protectedEndpoint(t, &fakeTokens{grant: issuer.Grant{Subject: subject,
				Authorized: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID(clientID), Subject: subject}}}),
			Resolve: func(ctx context.Context, _ issuer.Grant, txID string, _ issuer.DeferredTransactionRecord) error {
				resolved++
				return f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return dh
	}
	body := `{"transaction_id":"` + deferred.TransactionID + `"}`
	if w := postCredentialRequest(t, deferredHandler("another-client", "holder-1"), body); w.Code != http.StatusBadRequest || resolved != 0 {
		t.Errorf("another client's poll = %d, Resolve called %d times; want 400 and no Resolve", w.Code, resolved)
	}
	if w := postCredentialRequest(t, deferredHandler("test-client", "holder-2"), body); w.Code != http.StatusBadRequest || resolved != 0 {
		t.Errorf("another subject's poll = %d, Resolve called %d times; want 400 and no Resolve", w.Code, resolved)
	}
	w = postCredentialRequest(t, deferredHandler("test-client", "holder-1"), body)
	var issued oid4vci.CredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || w.Code != http.StatusOK || len(issued.Credentials) != 1 || resolved != 1 {
		t.Errorf("first poll = %d %s (Resolve %d); want 200 with the credential", w.Code, w.Body, resolved)
	}
}

// TestDeferral_BindsSubject: a transaction answers only the access
// token subject that created it — a client_id alone is shared by every
// install of a Wallet — and a request can't defer without a subject.
func TestDeferral_BindsSubject(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		client        issuer.ClientIdentity
		otherClientOK bool
	}{
		"known client": {client: issuer.KnownClientID("test-client")},
		// With no client to compare, the subject alone decides.
		"no client": {client: issuer.NoClientIdentity{}, otherClientOK: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeferralFixture(t)
			owner := issuer.AuthorizedRequest{ClientIdentity: tc.client, Subject: "holder-1", Scopes: deferralAuth.Scopes}
			resp, err := f.iss.RequestCredential(ctx, owner, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
				Defer:                     &issuer.Deferral{},
			})
			if err != nil {
				t.Fatalf("RequestCredential (deferred): %v", err)
			}
			if err := f.iss.IssueDeferredCredential(ctx, resp.TransactionID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
				t.Fatal(err)
			}
			poll := func(auth issuer.AuthorizedRequest) error {
				_, err := f.iss.RequestDeferredCredential(ctx, auth, issuer.DeferredCredentialRequest{TransactionID: resp.TransactionID})
				return err
			}
			assertIssuerError(t, poll(issuer.AuthorizedRequest{ClientIdentity: tc.client, Subject: "holder-2"}), issuer.ErrorInvalidTransactionID)
			assertIssuerError(t, poll(issuer.AuthorizedRequest{ClientIdentity: tc.client}), issuer.ErrorInvalidTransactionID)
			err = poll(issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("another-client"), Subject: "holder-1"})
			if tc.otherClientOK {
				if err != nil {
					t.Fatalf("the owning subject's poll from another client = %v", err)
				}
				return
			}
			assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
			if err := poll(owner); err != nil {
				t.Fatalf("the owner's poll = %v", err)
			}
		})
	}

	f := newDeferralFixture(t)
	noSubject := issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: deferralAuth.Scopes}
	if _, err := f.iss.RequestCredential(ctx, noSubject, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		Defer:                     &issuer.Deferral{},
	}); err == nil {
		t.Fatal("a request without a Subject was deferred")
	}
	if _, err := f.nonces.Consume(ctx, issuer.NonceConsumption{Nonce: "test-nonce"}); err != nil {
		t.Errorf("the nonce was consumed by a request that couldn't be deferred: %v", err)
	}
}

// TestDeferral_IssuedStaysCollectable: issuing restarts the
// transaction's lifetime, so a credential issued just before the
// original expiry can still be collected.
func TestDeferral_IssuedStaysCollectable(t *testing.T) {
	f := newDeferralFixture(t)
	ctx := context.Background()
	txID, _ := f.deferOne(t)
	f.clock.now = f.clock.now.Add(59 * time.Minute)
	if err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
		t.Fatal(err)
	}
	f.clock.now = f.clock.now.Add(30 * time.Minute)
	if res, err := f.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: txID}); err != nil || len(res.Credentials) != 1 {
		t.Fatalf("poll after a late issuance = %+v, %v", res, err)
	}
}

// TestDeferral_ResolveLosesRace: when a concurrent poll resolves the
// transaction first, Resolve's ErrDeferredTransactionResolved isn't a
// 500 — the poll is answered from the store.
func TestDeferral_ResolveLosesRace(t *testing.T) {
	f := newDeferralFixture(t)
	txID, _ := f.deferOne(t)
	dh, err := f.iss.DeferredCredentialHandler(issuer.DeferredCredentialHandlerConfig{
		ProtectedEndpointConfig: protectedEndpoint(t, &fakeTokens{grant: issuer.Grant{Subject: deferralAuth.Subject, Authorized: deferralAuth}}),
		Resolve: func(ctx context.Context, _ issuer.Grant, txID string, _ issuer.DeferredTransactionRecord) error {
			// The concurrent poll that wins.
			if err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
				return err
			}
			return f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := postCredentialRequest(t, dh, `{"transaction_id":"`+txID+`"}`)
	var issued oid4vci.CredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || w.Code != http.StatusOK || len(issued.Credentials) != 1 {
		t.Errorf("poll that lost the race = %d %s; want 200 with the credential", w.Code, w.Body)
	}
}

// TestDeferral_IntervalRoundsUp: a poll interval with a fraction of a
// second is sent as the next whole second, never truncated.
func TestDeferral_IntervalRoundsUp(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.Endpoints.DeferredCredential = mustEndpointURL(t, testDeferredCredentialEndpoint)
		cfg.Limits.DeferredIssuancePollInterval = 1500 * time.Millisecond
		cfg.Limits.DeferredTransactionLifetime = time.Hour
		deps.DeferredTransactions = newFakeDeferredTransactionStore()
	})
	resp, err := f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		Defer:                     &issuer.Deferral{},
	})
	if err != nil || resp.Interval != 2 {
		t.Fatalf("response = %+v, %v; want interval 2", resp, err)
	}
}

// TestDeferral_ResolveAfterValidation: a poll the Deferred Credential
// Endpoint refuses never reaches Resolve, so a malformed request can't
// make the deployment issue.
func TestDeferral_ResolveAfterValidation(t *testing.T) {
	f := newDeferralFixture(t)
	txID, _ := f.deferOne(t)
	resolved := 0
	dh, err := f.iss.DeferredCredentialHandler(issuer.DeferredCredentialHandlerConfig{
		ProtectedEndpointConfig: protectedEndpoint(t, &fakeTokens{grant: issuer.Grant{Subject: deferralAuth.Subject, Authorized: deferralAuth}}),
		Resolve: func(context.Context, issuer.Grant, string, issuer.DeferredTransactionRecord) error {
			resolved++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"transaction_id":                 txID,
		"credential_response_encryption": map[string]any{"jwk": testWalletJWK(t), "enc": "A128GCM"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Asking for an encrypted response in an unencrypted request (§9.1).
	if w := postCredentialRequest(t, dh, string(body)); w.Code != http.StatusBadRequest || resolved != 0 {
		t.Errorf("malformed poll = %d %s, Resolve called %d times; want 400 and no Resolve", w.Code, w.Body, resolved)
	}
}
