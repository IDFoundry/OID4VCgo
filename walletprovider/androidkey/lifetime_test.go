package androidkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// refusedAs checks err is the provider's evidence_rejected refusal.
func refusedAs(t *testing.T, what string, err error) {
	t.Helper()
	var refused *walletprovider.RefusedError
	if !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
		t.Fatalf("%s: %v, want evidence_rejected", what, err)
	}
}

// onlyRefused checks every refusal OnRecheckRefused heard of, at least
// one, wraps ErrEvidenceRejected and kind, and neither revocation
// verdict, and that the instance is still active: a refusal the
// provider neither revokes nor suspends the instance for.
func (w *rkpWallet) onlyRefused(t *testing.T, kind error) {
	t.Helper()
	r := w.f.refusals()
	if len(r) == 0 {
		t.Fatal("OnRecheckRefused wasn't told")
	}
	for _, err := range r {
		if !errors.Is(err, walletprovider.ErrEvidenceRejected) || !errors.Is(err, kind) ||
			errors.Is(err, walletprovider.ErrEvidenceRevoked) || errors.Is(err, walletprovider.ErrEvidenceSuspended) {
			t.Fatalf("OnRecheckRefused got %v, want a refusal wrapping %v and no revocation verdict", err, kind)
		}
	}
	if got := w.f.state(t, w.id); got != walletprovider.StateActive {
		t.Fatalf("the instance is %s, want active", got)
	}
}

// later sets the Verifier's clock d ahead.
func (w *rkpWallet) later(d time.Duration) {
	w.v.Now = func() time.Time { return time.Now().Add(d) }
}

// TestRecheckExpiredChain: Recheck judges the saved certificates'
// validity periods by the Verifier's clock, as Verify does a chain's.
// Once an intermediate of the registration chain, or of the instance
// key's own chain, has expired, as Remote Key Provisioning's
// short-lived ones do, a renewal and a Key Attestation are refused,
// OnRecheckRefused is told, and the instance is neither revoked nor
// suspended. The wallet recovers with fresh evidence: a new instance
// key when only the old key's chain expired, a new registration when
// the registration chain did.
func TestRecheckExpiredChain(t *testing.T) {
	soon := time.Now().Add(30 * time.Minute)
	t.Run("instance key chain", func(t *testing.T) {
		w := newRKPWallet(t, rkpOpts{instanceUntil: soon})
		w.mustAttest(t, "before the chain expires")
		w.later(time.Hour)
		refusedAs(t, "renewal once the instance key's chain expired", w.renew())
		refusedAs(t, "Key Attestation once the instance key's chain expired", w.keyAttestation(t))
		w.onlyRefused(t, androidkey.ErrCertificateValidity)

		var err error
		if w.instance, err = w.attestInstanceKey(t, 401, time.Time{}); err != nil {
			t.Fatalf("a new instance key, with fresh evidence: %v", err)
		}
		w.mustAttest(t, "with the new instance key")
	})

	t.Run("registration chain", func(t *testing.T) {
		w := newRKPWallet(t, rkpOpts{registrationUntil: soon})
		w.mustAttest(t, "before the chain expires")
		w.later(time.Hour)
		refusedAs(t, "renewal once the registration chain expired", w.renew())
		refusedAs(t, "Key Attestation once the registration chain expired", w.keyAttestation(t))
		_, err := w.attestInstanceKey(t, 401, time.Time{})
		refusedAs(t, "a new instance key of the expired registration", err)
		w.onlyRefused(t, androidkey.ErrCertificateValidity)

		if w.id, w.registration, err = w.register(t, 501, time.Time{}); err != nil {
			t.Fatalf("registering again, with fresh evidence: %v", err)
		}
		if w.instance, err = w.attestInstanceKey(t, 601, time.Time{}); err != nil {
			t.Fatalf("an instance key of the new registration: %v", err)
		}
		w.mustAttest(t, "after registering again")
	})
}

// mustAttest renews the instance key's Wallet Attestation and asks for
// a Key Attestation with it, failing the test on a refusal.
func (w *rkpWallet) mustAttest(t *testing.T, when string) {
	t.Helper()
	if err := w.renew(); err != nil {
		t.Fatalf("renewal %s: %v", when, err)
	}
	if err := w.keyAttestation(t); err != nil {
		t.Fatalf("Key Attestation %s: %v", when, err)
	}
}

// legacyRecord makes w's instance's, or its instance key's, record one
// an earlier version kept: facts rewrites its EvidenceFacts, keeping
// some (keepsFacts) or none.
type legacyRecord struct {
	name        string
	instanceKey bool
	keepsFacts  bool
	facts       func(t *testing.T, facts []byte) []byte
}

// noFacts drops the facts, as v0.75.3 (instances) and v0.80.0
// (instance keys) and before kept none.
func noFacts(*testing.T, []byte) []byte { return nil }

// noValidity drops the certificates' validity periods, as v0.80.0 and
// before kept none.
func noValidity(t *testing.T, facts []byte) []byte {
	t.Helper()
	var f androidkey.Facts
	if err := json.Unmarshal(facts, &f); err != nil {
		t.Fatal(err)
	}
	if !f.ValidityRecorded() {
		t.Fatalf("the facts saved = %+v, want validity periods", f.Certificates)
	}
	for i := range f.Certificates {
		f.Certificates[i].NotBefore, f.Certificates[i].NotAfter = time.Time{}, time.Time{}
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// apply rewrites w's record as r says.
func (r legacyRecord) apply(t *testing.T, w *rkpWallet) {
	t.Helper()
	ctx := context.Background()
	if !r.instanceKey {
		in, err := w.f.instances.Get(ctx, w.id)
		if err != nil {
			t.Fatal(err)
		}
		in.EvidenceFacts = r.facts(t, in.EvidenceFacts)
		if err := w.f.instances.Update(ctx, in); err != nil {
			t.Fatal(err)
		}
		return
	}
	keys, err := w.f.keys.List(ctx, w.id, "", 2)
	if err != nil || len(keys) != 1 {
		t.Fatalf("the instance's keys = %+v, %v; want one", keys, err)
	}
	keys[0].EvidenceFacts = r.facts(t, keys[0].EvidenceFacts)
	if err := w.f.keys.Update(ctx, keys[0]); err != nil {
		t.Fatal(err)
	}
}

// revokedChain is the intermediate, of the registration chain or the
// instance key's, whose record r rewrites.
func (r legacyRecord) revokedChain(w *rkpWallet) testChain {
	if r.instanceKey {
		return w.instance
	}
	return w.registration
}

var legacyRecords = []legacyRecord{
	{"instance without facts", false, false, noFacts},
	{"instance facts without validity", false, true, noValidity},
	{"instance key without facts", true, false, noFacts},
	{"instance key facts without validity", true, true, noValidity},
}

// TestRecheckLegacyRecords: a record an earlier version kept, which
// Recheck can't fully judge — an Android instance or instance key with
// no facts, or facts without the certificates' validity periods — is
// refused by default, as a production provider must, and told to
// OnRecheckRefused, without revoking the instance. With
// AllowUncheckedLegacyEvidence (an upgrade window, or development) it's
// accepted, and what facts it has are still judged: a revoked
// intermediate still revokes the instance.
func TestRecheckLegacyRecords(t *testing.T) {
	for _, r := range legacyRecords {
		t.Run(r.name+", refused by default", func(t *testing.T) {
			w := newRKPWallet(t, rkpOpts{})
			r.apply(t, w)
			refusedAs(t, "renewal", w.renew())
			refusedAs(t, "Key Attestation", w.keyAttestation(t))
			w.onlyRefused(t, androidkey.ErrLegacyFacts)
		})

		t.Run(r.name+", allowed", func(t *testing.T) {
			w := newRKPWallet(t, rkpOpts{allowLegacy: true})
			r.apply(t, w)
			w.mustAttest(t, "of a legacy record")
			if len(w.f.refusals()) != 0 {
				t.Fatalf("OnRecheckRefused got %v", w.f.refusals())
			}
			w.v.Revocation = revokingSerial(t, serialKey(r.revokedChain(w).inter))
			err := w.renew()
			if !r.keepsFacts {
				// No facts: nothing to judge the list by.
				if err != nil {
					t.Fatalf("renewal of a record without facts once its chain is revoked: %v", err)
				}
				return
			}
			refusedAs(t, "renewal once the chain is revoked", err)
			if got := w.f.state(t, w.id); got != walletprovider.StateRevoked {
				t.Fatalf("the instance is %s, want revoked", got)
			}
		})
	}
}
