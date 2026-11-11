package walletprovider_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// recheckingVerifier is the harness's Android verifier as an
// EvidenceRechecker: it reports facts, and refuses an instance with err
// when it's set.
type recheckingVerifier struct {
	androidVerifier
	mu      sync.Mutex
	err     error
	checked int
}

var testFacts = []byte(`{"serial":"2"}`)

func (v *recheckingVerifier) Verify(ctx context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	ev, err := v.androidVerifier.Verify(ctx, in)
	ev.Facts = testFacts
	return ev, err
}

func (v *recheckingVerifier) Recheck(_ context.Context, in walletprovider.Instance) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !bytes.Equal(in.EvidenceFacts, testFacts) {
		return fmt.Errorf("rechecking facts %q", in.EvidenceFacts)
	}
	v.checked++
	return v.err
}

func (v *recheckingVerifier) refuse(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.err = err
}

// TestRecheckRegistrationEvidence: the registration verifier's facts
// are kept with the instance, and an EvidenceRechecker judges them again
// before each attestation, so an instance whose evidence it now refuses
// gets none, even for a recorded instance key, and RevokeWhere can find
// it by them. A failure to check is the provider's own, not a refusal.
func TestRecheckRegistrationEvidence(t *testing.T) {
	v := &recheckingVerifier{}
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		for i, e := range d.Evidence {
			if a, ok := e.(androidVerifier); ok {
				v.androidVerifier = a
				d.Evidence[i] = v
			}
		}
	})
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	if !bytes.Equal(in.EvidenceFacts, testFacts) {
		t.Fatalf("the instance's facts = %q, want %q", in.EvidenceFacts, testFacts)
	}
	key := h.newInstanceKey(in.ID, kindStrongBox)
	holder := newKey(t)
	if _, err := h.keyAttestation(in.ID, &key.PublicKey, []*ecdsa.PrivateKey{holder}, kindStrongBox); err != nil {
		t.Fatal(err)
	}
	if v.checked != 2 {
		t.Fatalf("rechecked %d times, want 2", v.checked)
	}
	// An instance registered with other evidence isn't rechecked.
	ios, _ := h.register(kindIOS)
	h.newInstanceKey(ios.ID, kindIOS)

	for _, refusal := range []error{walletprovider.ErrEvidenceRejected, walletprovider.ErrPolicy} {
		v.refuse(fmt.Errorf("%w: the attestation key is revoked", refusal))
		if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, refusal) {
			t.Fatalf("a recorded instance key of a refused instance = %v, want %v", err, refusal)
		}
		if _, err := h.keyAttestation(in.ID, &key.PublicKey, []*ecdsa.PrivateKey{holder}, kindStrongBox); !errors.Is(err, refusal) {
			t.Fatalf("a Key Attestation for a refused instance = %v, want %v", err, refusal)
		}
	}
	v.refuse(errors.New("status list unavailable"))
	_, err := h.walletAttestation(in.ID, &key.PublicKey, "")
	if err == nil || errors.Is(err, walletprovider.ErrPolicy) || errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("a recheck that couldn't check = %v, want the provider's own failure", err)
	}

	n, err := h.p.RevokeWhere(ctx, func(in walletprovider.Instance) bool { return bytes.Equal(in.EvidenceFacts, testFacts) }, "attestation key revoked")
	if err != nil || n != 1 {
		t.Fatalf("RevokeWhere by facts = %d, %v; want 1", n, err)
	}
	h.expectState(in.ID, walletprovider.StateRevoked, "attestation key revoked")
	h.expectStatus(statuslist.StatusInvalid, key)
	h.expectState(ios.ID, walletprovider.StateActive, "")
}
