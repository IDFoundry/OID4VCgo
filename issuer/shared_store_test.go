package issuer_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

const (
	tenantA = "https://a.example.com"
	tenantB = "https://b.example.com"
)

// tenantIssuer is a development Issuer for the Credential Issuer
// issuerURL, its dependencies adjusted by mutate.
func tenantIssuer(t *testing.T, issuerURL string, mutate func(*issuer.Dependencies)) *issuer.Issuer {
	t.Helper()
	cfg := validConfig(t)
	cfg.Issuer = mustIssuerURL(t, issuerURL)
	cfg.Limits.AccessTokenLifetime = 5 * time.Minute
	cfg.Limits.MaxTxCodeAttempts = 3
	cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
	deps := validDependencies(t)
	mutate(&deps)
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New(%s): %v", issuerURL, err)
	}
	return iss
}

// Credential Issuers sharing a PreAuthorizedCodeStore each redeem only
// the codes they issued: B refuses A's code as unknown, without
// spending it or counting a wrong tx_code against it, and A redeems it
// afterwards.
func TestSharedPreAuthorizedCodeStoreKeepsIssuersApart(t *testing.T) {
	shared := storage.NewPreAuthorizedCodeStore()
	tokensA, tokensB := &fakeAccessTokenIssuer{}, &fakeAccessTokenIssuer{}
	build := func(url string, tokens *fakeAccessTokenIssuer) *issuer.Issuer {
		return tenantIssuer(t, url, func(deps *issuer.Dependencies) {
			deps.PreAuthorizedCodes = shared
			deps.AccessTokens = tokens
		})
	}
	a, b := build(tenantA, tokensA), build(tenantB, tokensB)
	ctx := context.Background()

	offer, err := a.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"},
		Subject: "tenant-a-user-42", TxCode: "482193", Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("A.CreatePreAuthorizedOffer: %v", err)
	}
	code := offer.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode
	redeem := func(iss *issuer.Issuer, txCode string) error {
		_, err := iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: code, TxCode: txCode,
			Verified: &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"},
		})
		return err
	}

	// Wrong guesses at B, up to A's limit, count nothing against A's code.
	for range 3 {
		assertIssuerError(t, redeem(b, "000000"), issuer.ErrorInvalidGrant)
	}
	assertIssuerError(t, redeem(b, "482193"), issuer.ErrorInvalidGrant)
	if err := redeem(a, "482193"); err != nil {
		t.Fatalf("A's own redemption after B's attempts: %v", err)
	}
}

// Credential Issuers sharing a NotificationStore each accept only their
// own notification_ids: B answers A's as unknown, and its handler isn't
// called.
func TestSharedNotificationStoreKeepsIssuersApart(t *testing.T) {
	notes := storage.NewNotificationStore()
	ha, hb := &fakeNotificationHandler{}, &fakeNotificationHandler{}
	build := func(url string, handler *fakeNotificationHandler) *issuer.Issuer {
		return tenantIssuer(t, url, func(deps *issuer.Dependencies) {
			deps.Notifications = notes
			deps.NotificationHandler = handler
		})
	}
	a, b := build(tenantA, ha), build(tenantB, hb)
	ctx := context.Background()
	auth := issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("wallet-solution"), Subject: "u1", Scopes: []string{"identity_credential"}}
	id, err := a.IssueNotificationID(ctx, auth)
	if err != nil {
		t.Fatalf("A.IssueNotificationID: %v", err)
	}
	req := issuer.NotificationRequest{NotificationID: id, Event: oid4vci.NotificationEventCredentialDeleted}
	assertIssuerError(t, b.RequestNotification(ctx, auth, req), issuer.ErrorInvalidNotificationID)
	if len(hb.calls) != 0 {
		t.Errorf("B's handler received A's notification: %+v", hb.calls)
	}
	if err := a.RequestNotification(ctx, auth, req); err != nil || len(ha.calls) != 1 {
		t.Errorf("A.RequestNotification: %v, %d handler calls; want accepted once", err, len(ha.calls))
	}
}

// Credential Issuers sharing a DeferredTransactionStore and a
// NonceStore each see only their own transactions and c_nonces: B can't
// issue, deny or serve A's transaction, or accept A's c_nonce, and A
// still can.
func TestSharedDeferredAndNonceStoresKeepIssuersApart(t *testing.T) {
	deferred := storage.NewDeferredTransactionStore()
	nonces := storage.NewNonceStore()
	build := func(url string) *issuer.Issuer {
		return tenantIssuer(t, url, func(deps *issuer.Dependencies) {
			deps.DeferredTransactions = deferred
			deps.Nonces = nonces
		})
	}
	a, b := build(tenantA), build(tenantB)
	ctx := context.Background()
	auth := issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("wallet-solution"), Subject: "user-42", Scopes: []string{"identity_credential"}}
	request := func(iss *issuer.Issuer, aud, nonce string) (oid4vci.CredentialResponse, error) {
		return iss.RequestCredential(ctx, auth, issuer.CredentialRequest{
			CredentialConfigurationID: "IdentityCredential",
			Proofs:                    map[string][]string{"jwt": {buildJWTProof(t, testP256Key(t), aud, nonce)}},
			Defer:                     &issuer.Deferral{},
		})
	}
	nonceA := func() string {
		n, err := a.RequestNonce(ctx)
		if err != nil {
			t.Fatalf("A.RequestNonce: %v", err)
		}
		return n.CNonce
	}

	resp, err := request(a, tenantA, nonceA())
	if err != nil {
		t.Fatalf("A.RequestCredential: %v", err)
	}
	txn := resp.TransactionID

	if err := b.IssueDeferredCredential(ctx, txn, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
		t.Errorf("B.IssueDeferredCredential(A's transaction) = %v, want ErrDeferredTransactionUnknown", err)
	}
	if err := b.DenyDeferredCredential(ctx, txn); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
		t.Errorf("B.DenyDeferredCredential(A's transaction) = %v, want ErrDeferredTransactionUnknown", err)
	}
	if err := a.IssueDeferredCredential(ctx, txn, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
		t.Fatalf("A.IssueDeferredCredential: %v", err)
	}
	_, err = b.RequestDeferredCredential(ctx, auth, issuer.DeferredCredentialRequest{TransactionID: txn})
	assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
	got, err := a.RequestDeferredCredential(ctx, auth, issuer.DeferredCredentialRequest{TransactionID: txn})
	if err != nil || len(got.Credentials) != 1 {
		t.Errorf("A.RequestDeferredCredential after B's poll: %d credentials, %v; want A's credential", len(got.Credentials), err)
	}

	// A's c_nonce is unknown at B, and stays A's to use.
	n := nonceA()
	_, err = request(b, tenantB, n)
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	if _, err := request(a, tenantA, n); err != nil {
		t.Errorf("A.RequestCredential with its c_nonce after B refused it: %v", err)
	}
}

// ownerDroppingPreAuthorizedCodes and ownerDroppingNotifications are
// stores that lose a record's Owner, as one that doesn't persist every
// field would.
type ownerDroppingPreAuthorizedCodes struct{ *fakePreAuthorizedCodeStore }

func (s ownerDroppingPreAuthorizedCodes) Issue(ctx context.Context, key string, record issuer.PreAuthorizedCodeRecord) error {
	record.Owner = ""
	return s.fakePreAuthorizedCodeStore.Issue(ctx, key, record)
}

type ownerDroppingNotifications struct{ *fakeNotificationStore }

func (s ownerDroppingNotifications) Issue(ctx context.Context, id string, record issuer.NotificationRecord) error {
	record.Owner = ""
	return s.fakeNotificationStore.Issue(ctx, id, record)
}

// Under production, a store that loses a record's Owner is refused when
// the record is saved — a pre-authorized offer isn't made, and its code
// is left unredeemable — rather than on every later request for it.
func TestProductionRefusesStoreThatDropsOwner(t *testing.T) {
	ctx := context.Background()
	t.Run("PreAuthorizedCodeStore", func(t *testing.T) {
		cfg, deps := preAuthorizedCodeProductionConfig(t)
		codes := newFakePreAuthorizedCodeStore()
		deps.PreAuthorizedCodes = assuredPreAuthorizedCodeStore{ownerDroppingPreAuthorizedCodes{codes}, issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
		iss, err := issuer.New(cfg, deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
			CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"},
			Subject: "holder-1", TxCode: "482193", Lifetime: time.Minute,
		})
		if err == nil || !strings.Contains(err.Error(), "didn't keep the record's Owner") {
			t.Fatalf("CreatePreAuthorizedOffer with a store that drops Owner = %v, want refused", err)
		}
		codes.mu.Lock()
		defer codes.mu.Unlock()
		if len(codes.issued) != 0 {
			t.Errorf("%d codes left in the store, want the refused one invalidated", len(codes.issued))
		}
	})
	t.Run("NotificationStore", func(t *testing.T) {
		cfg, deps := preAuthorizedCodeProductionConfig(t)
		deps.Notifications = assuredNotificationStore{ownerDroppingNotifications{newFakeNotificationStore()}, issuer.StoreCapabilities{Durable: true}}
		iss, err := issuer.New(cfg, deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = iss.IssueNotificationID(ctx, issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")})
		if err == nil || !strings.Contains(err.Error(), "didn't keep the record's Owner") {
			t.Fatalf("IssueNotificationID with a store that drops Owner = %v, want refused", err)
		}
	})
}

// A record with no Owner is honoured only under development, where a
// store needn't keep it; under production it's unknown.
func TestOwnerlessRecordIsUnknownUnderProduction(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	notes := newFakeNotificationStore()
	deps.Notifications = assuredNotificationStore{notes, issuer.StoreCapabilities{Durable: true}}
	transactions := newFakeDeferredTransactionStore()
	deps.DeferredTransactions = assuredDeferredTransactionStore{transactions, issuer.StoreCapabilities{Durable: true, AtomicConsume: true}}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	notes.put("notif-1", issuer.NotificationRecord{ClientID: "client-a"})
	transactions.put("txn-1", issuer.DeferredTransactionRecord{ClientID: "client-a", Status: issuer.DeferredTransactionIssued})
	ctx := context.Background()
	auth := issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")}

	err = iss.RequestNotification(ctx, auth, issuer.NotificationRequest{NotificationID: "notif-1", Event: oid4vci.NotificationEventCredentialAccepted})
	assertIssuerError(t, err, issuer.ErrorInvalidNotificationID)
	_, err = iss.RequestDeferredCredential(ctx, auth, issuer.DeferredCredentialRequest{TransactionID: "txn-1"})
	assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
	if err := iss.DenyDeferredCredential(ctx, "txn-1"); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
		t.Errorf("DenyDeferredCredential of an owner-less transaction = %v, want ErrDeferredTransactionUnknown", err)
	}
}
