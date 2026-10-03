package walletflow_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// faults fails POSTs to chosen paths: with a transport error, or with an
// HTTP answer, a given number of times.
type faults struct {
	inner http.RoundTripper
	mu    sync.Mutex
	fail  map[string]int    // path → failures left
	reply map[string]string // path → JSON error body (status 400); none: a transport error
}

func (f *faults) failNext(path string, times int, errorBody string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[path] = times
	if errorBody != "" {
		f.reply[path] = errorBody
	}
}

func (f *faults) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	n := f.fail[r.URL.Path]
	if r.Method == http.MethodPost && n > 0 {
		f.fail[r.URL.Path] = n - 1
		body, ok := f.reply[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			return nil, errors.New("connection reset by peer")
		}
		return &http.Response{
			StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(body)), Request: r,
		}, nil
	}
	f.mu.Unlock()
	return f.inner.RoundTrip(r)
}

// faultyWallet is a wallet whose requests go through faults, trusting
// verifiers (nil for none), over credentials (nil for the fixture's).
func faultyWallet(t *testing.T, f fixture, verifiers testVerifier, credentials walletflow.CredentialStore) (*walletflow.Wallet, *faults) {
	t.Helper()
	ft := &faults{inner: f.env.HTTP.Transport, fail: map[string]int{}, reply: map[string]string{}}
	if credentials == nil {
		credentials = f.store
	}
	cfg := walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots, Development: true,
	}
	if verifiers.Verifier != nil {
		cfg.VerifierTrust = verifiers.Trust
	}
	w, err := walletflow.New(cfg, walletflow.Dependencies{
		Keys: f.keys, Credentials: credentials, Provider: f.env.Provider,
		HTTP: &http.Client{Transport: ft, Timeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	return w, ft
}

// A Respond whose sending failed in transit may have reached the
// Verifier: it isn't sent again, and the presentation is answered.
func TestRespond_DeliveryUnknown(t *testing.T) {
	f, v, _ := presentationFixture(t)
	w, ft := faultyWallet(t, f, v, nil)
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	ft.failNext("/response", 1, "")
	if _, err := p.Respond(ctx, nil); !errors.Is(err, walletflow.ErrDeliveryUnknown) {
		t.Fatalf("Respond, failing in transit = %v, want ErrDeliveryUnknown", err)
	}
	if _, err := p.Respond(ctx, nil); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Respond again = %v, want ErrWrongStep", err)
	}
	if _, err := p.Decline(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Decline after = %v, want ErrWrongStep", err)
	}
}

// A Decline whose sending failed in transit is sent again, as is; the
// holder can't Respond after declining.
func TestDecline_ResendsAfterATransportFailure(t *testing.T) {
	f, v, _ := presentationFixture(t)
	w, ft := faultyWallet(t, f, v, nil)
	ctx := context.Background()
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	ft.failNext("/response", 1, "")
	if _, err := p.Decline(ctx); err == nil || errors.Is(err, walletflow.ErrWrongStep) {
		t.Fatalf("Decline, failing in transit = %v", err)
	}
	if _, err := p.Respond(ctx, nil); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Respond after declining = %v, want ErrWrongStep", err)
	}
	if _, err := p.Decline(ctx); err != nil {
		t.Fatalf("Decline again: %v", err)
	}
	if _, err := p.Decline(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Decline once delivered = %v, want ErrWrongStep", err)
	}
}

// A token request that fails after the redirect consumed the
// authorization starts the authorization over.
func TestCompleteAuthorization_StartsOverAfterATokenFailure(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	w, ft := faultyWallet(t, f, testVerifier{}, nil)
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := f.env.Approve(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}
	ft.failNext("/token", 1, "")
	if err := s.CompleteAuthorization(ctx, redirect); err == nil {
		t.Fatal("CompleteAuthorization with the token request failing succeeded")
	}
	if err := s.CompleteAuthorization(ctx, redirect); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("the same redirect again = %v, want ErrWrongStep", err)
	}
	authorize(t, f, s)
	if result, err := s.RequestCredentials(ctx); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
}

// One credential the issuer refuses doesn't hold up the others.
func TestRequestCredentials_OneRefusalDoesntBlockTheRest(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	w, ft := faultyWallet(t, f, testVerifier{}, nil)
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	ft.failNext("/credential", 1, `{"error":"invalid_credential_request"}`)
	result, err := s.RequestCredentials(ctx)
	if err != nil {
		t.Fatalf("RequestCredentials: %v", err)
	}
	if len(result.Credentials) != 1 || len(result.Failed) != 1 || result.Failed[0].Err == nil {
		t.Fatalf("result = %+v; want one credential and one failed", result)
	}
	if f.keys.Len() != 3 {
		t.Errorf("keys held = %d, want the instance, DPoP and one holder key", f.keys.Len())
	}
}

// flakyStore fails its next Put.
type flakyStore struct {
	*walletflow.MemoryCredentialStore
	mu   sync.Mutex
	fail bool
}

func (s *flakyStore) Put(ctx context.Context, c walletflow.StoredCredential) error {
	s.mu.Lock()
	fail := s.fail
	s.fail = false
	s.mu.Unlock()
	if fail {
		return errors.New("disk full")
	}
	return s.MemoryCredentialStore.Put(ctx, c)
}

// A deferred credential the issuer handed over isn't lost when storing
// it fails: the next Poll stores it, without asking the issuer again.
func TestDeferred_KeepsAnIssuedCredentialWhenStoringFails(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{Defer: true})
	store := &flakyStore{MemoryCredentialStore: walletflow.NewMemoryCredentialStore()}
	w, ft := faultyWallet(t, f, testVerifier{}, store)
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Deferred) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	d := result.Deferred[0]
	f.env.Decide(true)
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
	if _, err := d.Poll(ctx); err == nil || d.Done() {
		t.Fatalf("Poll with the store failing = %v, done %v", err, d.Done())
	}
	// The issuer isn't asked again: a failure there would show.
	ft.failNext("/deferred_credential", 1, "")
	stored, err := d.Poll(ctx)
	if err != nil || stored == nil {
		t.Fatalf("Poll again = %v, %v", stored, err)
	}
}
