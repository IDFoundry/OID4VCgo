package wallet_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// infiniteBody is an io.ReadCloser that never runs out of bytes — a
// stand-in for a malicious or compromised Issuer streaming an
// unbounded response body. A caller that reads it without its own
// size ceiling would never return; this is the concrete way to prove
// io.LimitReader is actually being applied at each read site below,
// not just present in the source.
type infiniteBody struct{}

func (infiniteBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func (infiniteBody) Close() error { return nil }

// requireReturnsWithin runs fn in a goroutine and fails t if it
// doesn't return within d — the only reliable way to prove a read
// that should be size-bounded actually is, since an unbounded read of
// infiniteBody would otherwise hang the test process rather than
// fail cleanly.
func requireReturnsWithin(t *testing.T, d time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("did not return within %s — response body read is not bounded", d)
		return nil
	}
}

// newInfiniteBodyResource is a fakeProtectedResourceClient whose every
// response has status 200 and an infiniteBody — the shared fixture
// both BoundsResponseSize tests below need to exercise their own
// call's read ceiling.
func newInfiniteBodyResource() *fakeProtectedResourceClient {
	return &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       infiniteBody{},
			}, nil
		},
	}
}

func TestRequestDeferredCredential_BoundsResponseSize(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := newInfiniteBodyResource()

	err = requireReturnsWithin(t, 5*time.Second, func() error {
		_, err := w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{
			TransactionID: "txn-1",
		})
		return err
	})
	if err == nil {
		t.Fatalf("RequestDeferredCredential = nil error, want a decode error from a body truncated at maxCredentialResponseBytes")
	}
}

func TestRequestNotification_BoundsResponseSize(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := newInfiniteBodyResource()

	err = requireReturnsWithin(t, 5*time.Second, func() error {
		return w.RequestNotification(context.Background(), resource, testNotificationEndpointForWallet(t), wallet.NotificationRequest{
			NotificationID: "notif-1", Event: oid4vci.NotificationEventCredentialAccepted,
		})
	})
	// A 200 with a truncated body is still a success status for
	// RequestNotification (it never parses the body on success) — this
	// test's own point is only that it returns at all within the
	// deadline, proving the read itself is bounded; it deliberately
	// doesn't assert on err's value.
	_ = err
}
