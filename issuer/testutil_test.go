package issuer_test

import (
	"context"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcigo/issuer"
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

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

const errNonceNotFound = fakeErr("nonce not found or already consumed")

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// errReader always fails, for exercising RequestNonce's random-source
// error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errReadFailed }

const errReadFailed = fakeErr("simulated read failure")
