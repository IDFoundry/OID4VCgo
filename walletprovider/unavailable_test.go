package walletprovider_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// kindUndecided is evidence undecidedVerifier can't decide on.
const kindUndecided = "undecided"

// undecidedVerifier stands in for a verifier that can't decide for now,
// as androidkey's can't without Google's status list.
type undecidedVerifier struct{}

func (undecidedVerifier) Kind() string { return kindUndecided }

func (undecidedVerifier) Verify(context.Context, walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	return walletprovider.VerifiedEvidence{}, fmt.Errorf("%w: the status list can't be fetched", walletprovider.ErrUnavailable)
}

// kindRetryLater is evidence retryLaterVerifier can't decide on.
const kindRetryLater = "retry-later"

// retryLaterVerifier can't decide for now, and says when it may:
// its error has a RetryAfter method, as androidkey.StatusSource's has.
type retryLaterVerifier struct{ after time.Duration }

func (retryLaterVerifier) Kind() string { return kindRetryLater }

func (v retryLaterVerifier) Verify(context.Context, walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	return walletprovider.VerifiedEvidence{}, fmt.Errorf("%w: %w", walletprovider.ErrUnavailable, retryLaterError(v))
}

type retryLaterError struct{ after time.Duration }

func (retryLaterError) Error() string               { return "the status list can't be fetched" }
func (e retryLaterError) RetryAfter() time.Duration { return e.after }

// postRegistration posts a registration with evidence of kind to ts, a
// provider's server, c its client, returning the response's status,
// error code and Retry-After.
func postRegistration(t *testing.T, ts *httptest.Server, c *walletprovider.Client, kind string) (int, string, string) {
	t.Helper()
	regKey, err := jwk.Marshal(&newKey(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := c.Challenge(context.Background(), walletprovider.PurposeRegistration)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"challenge": ch.Value, "registration_key": regKey,
		"evidence": map[string]string{"kind": kind, "data": "eA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Post(ts.URL+walletprovider.InstancesPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var refusal struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refusal); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, refusal.Error, resp.Header.Get("Retry-After")
}

// TestRegisterUnavailable: evidence a verifier can't decide on for now
// isn't rejected: the registration fails as the provider's own
// failure, answered 503 server_error with a Retry-After.
func TestRegisterUnavailable(t *testing.T) {
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Evidence = append(d.Evidence, undecidedVerifier{})
	})
	ts, c := h.server("")
	key := newKey(t)
	ch := h.challenge(walletprovider.PurposeRegistration)
	_, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: walletprovider.Evidence{Kind: kindUndecided, Data: []byte("x")},
	})
	if !errors.Is(err, walletprovider.ErrUnavailable) || errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("Register = %v, want ErrUnavailable, not a rejection", err)
	}

	if status, code, retry := postRegistration(t, ts, c, kindUndecided); status != http.StatusServiceUnavailable || code != "server_error" || retry != "30" {
		t.Fatalf("HTTP %d %q, Retry-After %q; want 503 server_error with Retry-After 30", status, code, retry)
	}
}

// TestUnavailableRetryAfter: a 503's Retry-After is what the error says
// of when to retry, rounded up to whole seconds, when it says so.
func TestUnavailableRetryAfter(t *testing.T) {
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Evidence = append(d.Evidence, retryLaterVerifier{after: 41*time.Second + time.Millisecond})
	})
	ts, c := h.server("")
	if status, _, retry := postRegistration(t, ts, c, kindRetryLater); status != http.StatusServiceUnavailable || retry != "42" {
		t.Fatalf("HTTP %d, Retry-After %q; want 503 with Retry-After 42", status, retry)
	}
}

// TestRecheckUnavailable: a recheck that can't decide for now fails the
// request with ErrUnavailable, unreported and leaving the instance and
// its statuses as they are, and so does holder key evidence that can't
// be decided on, rather than an attestation leaving the key out.
func TestRecheckUnavailable(t *testing.T) {
	v, log := &recheckingVerifier{}, &refusalLog{}
	h := recheckHarness(t, v, log, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Evidence = append(d.Evidence, undecidedVerifier{})
	})
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	v.refuse(fmt.Errorf("%w: the status list can't be fetched", walletprovider.ErrUnavailable))
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrUnavailable) {
		t.Fatalf("Wallet Attestation = %v, want ErrUnavailable", err)
	}
	h.expectState(in.ID, walletprovider.StateActive, "")
	h.expectStatus(statuslist.StatusValid, key)
	log.expect(t, 0, h.stored(in.ID), nil)

	v.refuse(nil)
	holders := []*ecdsa.PrivateKey{newKey(t), newKey(t)}
	if _, err := h.keyAttestation(in.ID, &key.PublicKey, holders, kindStrongBox, kindUndecided); !errors.Is(err, walletprovider.ErrUnavailable) {
		t.Fatalf("Key Attestation with undecided evidence = %v, want ErrUnavailable", err)
	}
}
