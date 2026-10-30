package issuer_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// errStoreDown is what the outage stores below fail with: a backend
// that couldn't answer, not an unknown record.
var errStoreDown = errors.New("db: connection refused")

type downNonceStore struct{ issuer.NonceStore }

func (downNonceStore) Consume(context.Context, issuer.NonceConsumption) (issuer.NonceRecord, error) {
	return issuer.NonceRecord{}, context.DeadlineExceeded
}

type downPreAuthorizedCodeStore struct{ issuer.PreAuthorizedCodeStore }

func (downPreAuthorizedCodeStore) Consume(context.Context, string, string, int, func(issuer.PreAuthorizedCodeRecord) error) (issuer.PreAuthorizedCodeRecord, int, error) {
	return issuer.PreAuthorizedCodeRecord{}, 0, errStoreDown
}

// requireServerError fails the test unless err is a plain error, which
// WriteError answers with a 500, wrapping want.
func requireServerError(t *testing.T, err, want error) {
	t.Helper()
	var ierr *issuer.Error
	if errors.As(err, &ierr) {
		t.Fatalf("error = %d %s (%v), want a plain error (a 500): the store couldn't answer", ierr.HTTPStatus(), ierr.Code(), err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want it to wrap %v", err, want)
	}
}

// A store that couldn't answer is the issuer's failure, not the
// Wallet's: none of these is reported as an unknown code, nonce,
// transaction or notification_id (a holder told the PIN is wrong during
// an outage, or a Wallet dropping a code as used).
func TestStoreOutageIsAServerError(t *testing.T) {
	t.Run("NonceStore", func(t *testing.T) {
		f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
			deps.Nonces = downNonceStore{deps.Nonces}
		})
		_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, "any-nonce"))
		requireServerError(t, err, context.DeadlineExceeded)
	})

	t.Run("PreAuthorizedCodeStore", func(t *testing.T) {
		f := newVerifiedPreAuthorizedCodeFixture(t, func(s *fakePreAuthorizedCodeStore) issuer.PreAuthorizedCodeStore {
			return downPreAuthorizedCodeStore{s}
		})
		_, err := redeemVerified(f, "code", "123456", nil)
		requireServerError(t, err, errStoreDown)
	})

	deferred := func(t *testing.T, store *fakeDeferredTransactionStore) error {
		t.Helper()
		deps := validDependencies(t)
		deps.DeferredTransactions = store
		iss := newTestIssuer(t, validConfig(t), deps)
		_, err := iss.RequestDeferredCredential(context.Background(),
			issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")},
			issuer.DeferredCredentialRequest{TransactionID: "txn-1"})
		return err
	}
	t.Run("DeferredTransactionStore.Get", func(t *testing.T) {
		store := newFakeDeferredTransactionStore()
		store.getErr = context.Canceled
		requireServerError(t, deferred(t, store), context.Canceled)
	})
	t.Run("DeferredTransactionStore.Invalidate", func(t *testing.T) {
		store := newFakeDeferredTransactionStore()
		store.put("txn-1", issuer.DeferredTransactionRecord{ClientID: "client-a", Status: issuer.DeferredTransactionIssued})
		store.invalidErr = errStoreDown
		requireServerError(t, deferred(t, store), errStoreDown)
	})

	t.Run("NotificationStore", func(t *testing.T) {
		store := newFakeNotificationStore()
		store.getErr = errStoreDown
		deps := validDependencies(t)
		deps.Notifications = store
		iss := newTestIssuer(t, validConfig(t), deps)
		err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")},
			issuer.NotificationRequest{NotificationID: "notif-1", Event: oid4vci.NotificationEventCredentialAccepted})
		requireServerError(t, err, errStoreDown)
	})
}

// An unknown record, the stores' own sentinel, is still the Wallet's
// error: the 400 each endpoint defines for it.
func TestStoreUnknownRecordIsAClientError(t *testing.T) {
	t.Run("NonceStore", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, "never-issued"))
		assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	})
	t.Run("PreAuthorizedCodeStore", func(t *testing.T) {
		f := newVerifiedPreAuthorizedCodeFixture(t, nil)
		_, err := redeemVerified(f, "never-issued", "", nil)
		assertIssuerError(t, err, issuer.ErrorInvalidGrant)
	})
	t.Run("DeferredTransactionStore", func(t *testing.T) {
		deps := validDependencies(t)
		deps.DeferredTransactions = newFakeDeferredTransactionStore()
		iss := newTestIssuer(t, validConfig(t), deps)
		_, err := iss.RequestDeferredCredential(context.Background(),
			issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")},
			issuer.DeferredCredentialRequest{TransactionID: "never-issued"})
		assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
	})
	t.Run("NotificationStore", func(t *testing.T) {
		deps := validDependencies(t)
		deps.Notifications = newFakeNotificationStore()
		iss := newTestIssuer(t, validConfig(t), deps)
		err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")},
			issuer.NotificationRequest{NotificationID: "never-issued", Event: oid4vci.NotificationEventCredentialAccepted})
		assertIssuerError(t, err, issuer.ErrorInvalidNotificationID)
	})
}
