package walletprovider_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
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
	if n == 0 {
		return
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

// keyRecheckingVerifier is a recheckingVerifier that is an
// InstanceKeyRechecker too: it records the instance keys it rechecks,
// and refuses one with err when it's set.
type keyRecheckingVerifier struct {
	*recheckingVerifier
	keyErr    error
	rechecked []walletprovider.InstanceKey
}

func (v *keyRecheckingVerifier) RecheckInstanceKey(_ context.Context, in walletprovider.Instance, k walletprovider.InstanceKey) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k.InstanceID != in.ID {
		return fmt.Errorf("rechecking instance %s's key for %s", k.InstanceID, in.ID)
	}
	v.rechecked = append(v.rechecked, k)
	return v.keyErr
}

func (v *keyRecheckingVerifier) refuseKey(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keyErr = err
}

func (v *keyRecheckingVerifier) recheckedKeys() []walletprovider.InstanceKey {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.rechecked)
}

// keyRecheckHarness is a harness whose Android verifier is v,
// reporting recheck refusals to log.
func keyRecheckHarness(t *testing.T, v *keyRecheckingVerifier, log *refusalLog) *harness {
	t.Helper()
	return recheckHarness(t, v.recheckingVerifier, log, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		for i, e := range d.Evidence {
			if e == walletprovider.EvidenceVerifier(v.recheckingVerifier) {
				d.Evidence[i] = v
			}
		}
	})
}

// TestRecheckInstanceKeyEvidence: the facts the verifier reports of an
// instance key's evidence are kept with its record, and an
// InstanceKeyRechecker judges them again each time the provider relies
// on the record — a Wallet Attestation for a recorded key, and every
// Key Attestation — but not when fresh evidence records it.
func TestRecheckInstanceKeyEvidence(t *testing.T) {
	v := &keyRecheckingVerifier{recheckingVerifier: &recheckingVerifier{}}
	h := keyRecheckHarness(t, v, &refusalLog{})
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	if facts := h.instanceKey(&key.PublicKey).EvidenceFacts; !bytes.Equal(facts, testFacts) {
		t.Fatalf("the instance key's facts = %q, want %q", facts, testFacts)
	}
	if n := len(v.recheckedKeys()); n != 0 {
		t.Fatalf("recording the key rechecked %d keys, want none", n)
	}
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.keyAttestation(in.ID, &key.PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindStrongBox); err != nil {
		t.Fatal(err)
	}
	rechecked := v.recheckedKeys()
	if len(rechecked) != 2 {
		t.Fatalf("rechecked %d keys, want 2", len(rechecked))
	}
	for _, k := range rechecked {
		if k.Thumbprint != h.thumbprint(&key.PublicKey) || !bytes.Equal(k.EvidenceFacts, testFacts) {
			t.Fatalf("rechecked %s with facts %q, want the instance key's", k.Thumbprint, k.EvidenceFacts)
		}
	}
}

// TestRecheckInstanceKeyRefusals: an InstanceKeyRechecker's refusal is
// acted on as an EvidenceRechecker's is, on either request that relies
// on a recorded instance key: evidence revoked or suspended by its
// issuer revokes or suspends the whole instance, any other refusal only
// refuses, every refusal is reported to OnRecheckRefused, and a recheck
// that couldn't check fails the request as the provider's own failure,
// unreported.
func TestRecheckInstanceKeyRefusals(t *testing.T) {
	requests := map[string]func(h *harness, id string, key *ecdsa.PrivateKey) error{
		"Wallet Attestation": func(h *harness, id string, key *ecdsa.PrivateKey) error {
			_, err := h.walletAttestation(id, &key.PublicKey, "")
			return err
		},
		"Key Attestation": func(h *harness, id string, key *ecdsa.PrivateKey) error {
			_, err := h.keyAttestation(id, &key.PublicKey, []*ecdsa.PrivateKey{newKey(h.t)}, kindStrongBox)
			return err
		},
	}
	cases := []struct {
		name     string
		refusal  error
		state    walletprovider.State
		status   statuslist.StatusType
		reported bool
	}{
		{"revoked", fmt.Errorf("%w: %w: certificate 1 is named", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceRevoked), walletprovider.StateRevoked, statuslist.StatusInvalid, true},
		{"suspended", fmt.Errorf("%w: %w: certificate 1 is named", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceSuspended), walletprovider.StateSuspended, statuslist.StatusSuspended, true},
		{"policy", fmt.Errorf("%w: patch level too old", walletprovider.ErrPolicy), walletprovider.StateActive, statuslist.StatusValid, true},
		{"couldn't check", errors.New("status list unavailable"), walletprovider.StateActive, statuslist.StatusValid, false},
	}
	for name, request := range requests {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				v, log := &keyRecheckingVerifier{recheckingVerifier: &recheckingVerifier{}}, &refusalLog{}
				h := keyRecheckHarness(t, v, log)
				in, _ := h.register(kindStrongBox)
				key := h.newInstanceKey(in.ID, kindStrongBox)
				v.refuseKey(tc.refusal)
				err := request(h, in.ID, key)
				if !errors.Is(err, tc.refusal) {
					t.Fatalf("request = %v, want %v", err, tc.refusal)
				}
				if !tc.reported && (errors.Is(err, walletprovider.ErrPolicy) || errors.Is(err, walletprovider.ErrEvidenceRejected)) {
					t.Fatalf("a recheck that couldn't check = %v, want the provider's own failure", err)
				}
				stored := h.stored(in.ID)
				if stored.State != tc.state || (tc.state != walletprovider.StateActive) != (stored.Reason != "") {
					t.Fatalf("the instance is %s (%q), want %s", stored.State, stored.Reason, tc.state)
				}
				h.expectStatus(tc.status, key)
				if tc.reported {
					log.expect(t, 1, stored, tc.refusal)
				} else {
					log.expect(t, 0, stored, nil)
				}
			})
		}
	}
}
