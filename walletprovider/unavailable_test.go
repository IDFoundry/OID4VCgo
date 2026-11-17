package walletprovider_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

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

	regKey, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ch2, err := c.Challenge(context.Background(), walletprovider.PurposeRegistration)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"challenge": ch2.Value, "registration_key": regKey,
		"evidence": map[string]string{"kind": kindUndecided, "data": "eA"},
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
	if resp.StatusCode != http.StatusServiceUnavailable || refusal.Error != "server_error" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("HTTP %d %q, Retry-After %q; want 503 server_error with a Retry-After", resp.StatusCode, refusal.Error, resp.Header.Get("Retry-After"))
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
