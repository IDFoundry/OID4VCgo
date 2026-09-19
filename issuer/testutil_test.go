package issuer_test

import (
	"context"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// fakeNonceStore is an in-memory issuer.NonceStore for tests.
type fakeNonceStore struct {
	mu         sync.Mutex
	issued     map[string]time.Time
	consumed   map[string]bool
	issueErr   error
	consumeErr error
}

func newFakeNonceStore() *fakeNonceStore {
	return &fakeNonceStore{issued: make(map[string]time.Time), consumed: make(map[string]bool)}
}

func (f *fakeNonceStore) Issue(_ context.Context, in issuer.NonceIssuance) error {
	if f.issueErr != nil {
		return f.issueErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[in.Nonce] = in.ExpiresAt
	return nil
}

func (f *fakeNonceStore) Consume(_ context.Context, c issuer.NonceConsumption) (issuer.NonceRecord, error) {
	if f.consumeErr != nil {
		return issuer.NonceRecord{}, f.consumeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.issued[c.Nonce]
	if !ok || f.consumed[c.Nonce] {
		return issuer.NonceRecord{}, errNonceNotFound
	}
	f.consumed[c.Nonce] = true
	return issuer.NonceRecord{ExpiresAt: exp}, nil
}

// fakeCredentialOfferStore is an in-memory issuer.CredentialOfferStore
// for tests.
type fakeCredentialOfferStore struct {
	mu       sync.Mutex
	records  map[string]issuer.CredentialOfferRecord
	storeErr error
	getErr   error
}

func newFakeCredentialOfferStore() *fakeCredentialOfferStore {
	return &fakeCredentialOfferStore{records: make(map[string]issuer.CredentialOfferRecord)}
}

func (f *fakeCredentialOfferStore) Store(_ context.Context, record issuer.CredentialOfferRecord) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[record.Reference] = record
	return nil
}

func (f *fakeCredentialOfferStore) Get(_ context.Context, reference string) (issuer.CredentialOfferRecord, error) {
	if f.getErr != nil {
		return issuer.CredentialOfferRecord{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.records[reference]
	if !ok {
		return issuer.CredentialOfferRecord{}, errCredentialOfferNotFound
	}
	return record, nil
}

// fakeDeferredTransactionStore is an in-memory
// issuer.DeferredTransactionStore for tests.
type fakeDeferredTransactionStore struct {
	mu          sync.Mutex
	records     map[string]issuer.DeferredTransactionRecord
	invalidated map[string]bool
	getErr      error
	invalidErr  error
}

func newFakeDeferredTransactionStore() *fakeDeferredTransactionStore {
	return &fakeDeferredTransactionStore{
		records:     make(map[string]issuer.DeferredTransactionRecord),
		invalidated: make(map[string]bool),
	}
}

func (f *fakeDeferredTransactionStore) put(transactionID string, record issuer.DeferredTransactionRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[transactionID] = record
}

func (f *fakeDeferredTransactionStore) Get(_ context.Context, transactionID string) (issuer.DeferredTransactionRecord, error) {
	if f.getErr != nil {
		return issuer.DeferredTransactionRecord{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.invalidated[transactionID] {
		return issuer.DeferredTransactionRecord{}, errDeferredTransactionNotFound
	}
	record, ok := f.records[transactionID]
	if !ok {
		return issuer.DeferredTransactionRecord{}, errDeferredTransactionNotFound
	}
	return record, nil
}

func (f *fakeDeferredTransactionStore) Invalidate(_ context.Context, transactionID string) error {
	if f.invalidErr != nil {
		return f.invalidErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated[transactionID] = true
	return nil
}

// fakeNotificationStore is an in-memory issuer.NotificationStore for
// tests.
type fakeNotificationStore struct {
	mu       sync.Mutex
	records  map[string]issuer.NotificationRecord
	issueErr error
	getErr   error
}

func newFakeNotificationStore() *fakeNotificationStore {
	return &fakeNotificationStore{records: make(map[string]issuer.NotificationRecord)}
}

func (f *fakeNotificationStore) put(notificationID string, record issuer.NotificationRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[notificationID] = record
}

func (f *fakeNotificationStore) Issue(_ context.Context, notificationID string, record issuer.NotificationRecord) error {
	if f.issueErr != nil {
		return f.issueErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[notificationID] = record
	return nil
}

func (f *fakeNotificationStore) Get(_ context.Context, notificationID string) (issuer.NotificationRecord, error) {
	if f.getErr != nil {
		return issuer.NotificationRecord{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.records[notificationID]
	if !ok {
		return issuer.NotificationRecord{}, errNotificationNotFound
	}
	return record, nil
}

// fakeNotificationHandler is an in-memory issuer.NotificationHandler
// for tests, recording every call it receives.
type fakeNotificationHandler struct {
	mu    sync.Mutex
	calls []notificationHandlerCall
	err   error
}

type notificationHandlerCall struct {
	NotificationID string
	Event          oid4vci.NotificationEvent
	Description    string
}

func (f *fakeNotificationHandler) HandleNotification(_ context.Context, notificationID string, event oid4vci.NotificationEvent, description string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, notificationHandlerCall{NotificationID: notificationID, Event: event, Description: description})
	return f.err
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

const errNonceNotFound = fakeErr("nonce not found or already consumed")
const errCredentialOfferNotFound = fakeErr("credential offer not found")
const errDeferredTransactionNotFound = fakeErr("deferred transaction not found")
const errNotificationNotFound = fakeErr("notification not found")

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// errReader always fails, for exercising RequestNonce's random-source
// error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errReadFailed }

const errReadFailed = fakeErr("simulated read failure")

// fakeAuditSink is an in-memory issuer.AuditSink for tests, recording
// every event it was called with.
type fakeAuditSink struct {
	mu     sync.Mutex
	events []issuer.AuditEvent
}

func newFakeAuditSink() *fakeAuditSink {
	return &fakeAuditSink{}
}

func (f *fakeAuditSink) Record(_ context.Context, event issuer.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return nil
}

func (f *fakeAuditSink) recorded() []issuer.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]issuer.AuditEvent(nil), f.events...)
}
