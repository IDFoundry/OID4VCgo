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

// install makes v the harness's Android verifier.
func (v *recheckingVerifier) install(_ *walletprovider.Config, d *walletprovider.Dependencies) {
	for i, e := range d.Evidence {
		if a, ok := e.(androidVerifier); ok {
			v.androidVerifier = a
			d.Evidence[i] = v
		}
	}
}

// TestRecheckRegistrationEvidence: the registration verifier's facts
// are kept with the instance, and an EvidenceRechecker judges them again
// before each attestation, so an instance whose evidence it now refuses
// gets none, even for a recorded instance key, and RevokeWhere can find
// it by them. A failure to check is the provider's own, not a refusal.
func TestRecheckRegistrationEvidence(t *testing.T) {
	v := &recheckingVerifier{}
	h := newHarness(t, v.install)
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

// refusalLog records Config.OnRecheckRefused's calls.
type refusalLog struct {
	mu    sync.Mutex
	calls []refusal
}

type refusal struct {
	in  walletprovider.Instance
	err error
}

func (l *refusalLog) record(_ context.Context, in walletprovider.Instance, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, refusal{in, err})
}

// expect checks OnRecheckRefused was called n times, the last with
// the instance as stored and an error wrapping want.
func (l *refusalLog) expect(t *testing.T, n int, stored walletprovider.Instance, want error) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.calls) != n {
		t.Fatalf("OnRecheckRefused called %d times, want %d", len(l.calls), n)
	}
	got := l.calls[n-1]
	if got.in.ID != stored.ID || got.in.State != stored.State || got.in.Reason != stored.Reason || !errors.Is(got.err, want) {
		t.Fatalf("OnRecheckRefused(%s, %s %q, %v), want (%s, %s %q, %v)", got.in.ID, got.in.State, got.in.Reason, got.err, stored.ID, stored.State, stored.Reason, want)
	}
}

// recheckHarness is a harness whose Android verifier is v, reporting
// recheck refusals to log.
func recheckHarness(t *testing.T, v *recheckingVerifier, log *refusalLog, mutate func(*walletprovider.Config, *walletprovider.Dependencies)) *harness {
	t.Helper()
	return newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		v.install(c, d)
		c.OnRecheckRefused = log.record
		if mutate != nil {
			mutate(c, d)
		}
	})
}

// stored is the instance id as stored.
func (h *harness) stored(id string) walletprovider.Instance {
	h.t.Helper()
	in, err := h.deps.Instances.Get(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return in
}

// TestRecheckRevokesOrSuspends: a recheck refusing an instance because
// its evidence's issuer revoked or suspended its attestation revokes or
// suspends the instance, so its live attestations read INVALID or
// SUSPENDED, before refusing the request; any other refusal only
// refuses. Each is reported to OnRecheckRefused with the instance as
// stored.
func TestRecheckRevokesOrSuspends(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict error // wrapped by the refusal, besides ErrEvidenceRejected
		state   walletprovider.State
		status  statuslist.StatusType
		next    error // what the instance's next request is refused with
	}{
		{"revoked", walletprovider.ErrEvidenceRevoked, walletprovider.StateRevoked, statuslist.StatusInvalid, walletprovider.ErrInstanceRevoked},
		{"suspended", walletprovider.ErrEvidenceSuspended, walletprovider.StateSuspended, statuslist.StatusSuspended, walletprovider.ErrInstanceNotActive},
		{"root removed", nil, walletprovider.StateActive, statuslist.StatusValid, walletprovider.ErrEvidenceRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, log := &recheckingVerifier{}, &refusalLog{}
			h := recheckHarness(t, v, log, nil)
			in, _ := h.register(kindStrongBox)
			key := h.newInstanceKey(in.ID, kindStrongBox)
			refused := fmt.Errorf("%w: the chain's root isn't configured", walletprovider.ErrEvidenceRejected)
			if tc.verdict != nil {
				refused = fmt.Errorf("%w: %w: certificate 1 is named", walletprovider.ErrEvidenceRejected, tc.verdict)
			}
			v.refuse(refused)
			if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, refused) {
				t.Fatalf("Wallet Attestation = %v, want %v", err, refused)
			}
			stored := h.stored(in.ID)
			if stored.State != tc.state || (tc.state != walletprovider.StateActive) != (stored.Reason != "") {
				t.Fatalf("the instance is %s (%q), want %s", stored.State, stored.Reason, tc.state)
			}
			h.expectStatus(tc.status, key)
			log.expect(t, 1, stored, refused)
			if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, tc.next) {
				t.Fatalf("the next Wallet Attestation = %v, want %v", err, tc.next)
			}
		})
	}

	// A policy refusal leaves the instance active, and a recheck that
	// couldn't check isn't reported.
	v, log := &recheckingVerifier{}, &refusalLog{}
	h := recheckHarness(t, v, log, nil)
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	v.refuse(fmt.Errorf("%w: patch level too old", walletprovider.ErrPolicy))
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("Wallet Attestation = %v, want ErrPolicy", err)
	}
	v.refuse(errors.New("status list unavailable"))
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); err == nil {
		t.Fatal("a recheck that couldn't check succeeded")
	}
	h.expectState(in.ID, walletprovider.StateActive, "")
	h.expectStatus(statuslist.StatusValid, key)
	log.expect(t, 1, h.stored(in.ID), walletprovider.ErrPolicy)
}

// TestRecheckRevokeRacingResume: a recheck's revocation that lands
// while an operator's Resume sets its statuses leaves the instance
// revoked, its keys INVALID, as Revoke does.
func TestRecheckRevokeRacingResume(t *testing.T) {
	g := &gatedKeys{entered: make(chan struct{}), release: make(chan struct{})}
	v, log := &recheckingVerifier{}, &refusalLog{}
	h := recheckHarness(t, v, log, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		g.InstanceKeyStore = d.InstanceKeys
		d.InstanceKeys = g
	})
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	if err := h.p.Suspend(ctx, in.ID, "lost"); err != nil {
		t.Fatal(err)
	}
	g.gate()
	done := make(chan error)
	// Stores the instance active, then waits to list its keys.
	go func() { done <- h.p.Resume(ctx, in.ID) }()
	<-g.entered
	v.refuse(fmt.Errorf("%w: %w: certificate 1 is REVOKED", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceRevoked))
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrEvidenceRevoked) {
		t.Fatalf("Wallet Attestation = %v, want ErrEvidenceRevoked", err)
	}
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if stored := h.stored(in.ID); stored.State != walletprovider.StateRevoked {
		t.Fatalf("the instance is %s, want revoked", stored.State)
	}
	h.expectStatus(statuslist.StatusInvalid, key)
}
