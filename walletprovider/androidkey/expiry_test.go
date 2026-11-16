package androidkey_test

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// TestRecheckExpiry: the reviewer's reproduction, inverted. A chain
// whose intermediate expires in 30 minutes verifies; an hour later a
// fresh Verify refuses it with ErrCertificateValidity, and so does
// Recheck of the Facts saved from it — a refusal, not a revocation
// verdict, and one AllowUncheckedLegacyEvidence doesn't lift, as the
// Facts hold the validity periods. Facts without them are refused with
// ErrLegacyFacts, unless allowed.
func TestRecheckExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	c := newChain(t, goodSpec(t), chainOpts{interValidity: [2]time.Time{now.Add(-time.Hour), now.Add(30 * time.Minute)}})
	v := verifierFor(t, c)
	e := androidkey.EvidenceVerifier{Verifier: v}
	ev, err := e.Verify(ctx, evidenceInput(c.der, testChallenge, &c.leafKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	in := walletprovider.Instance{ID: "i", Evidence: walletprovider.EvidenceSummary{Kind: androidkey.EvidenceKind}, EvidenceFacts: ev.Facts}
	f, _, err := androidkey.InstanceFacts(in)
	if err != nil || !f.Expiry().Equal(c.inter.NotAfter) {
		t.Fatalf("Expiry = %v, %v; want the intermediate's %v", f.Expiry(), err, c.inter.NotAfter)
	}
	if err := v.Recheck(ctx, &f); err != nil {
		t.Fatalf("Recheck before the intermediate expires = %v", err)
	}

	v.Now = func() time.Time { return now.Add(time.Hour) }
	if _, err := v.Verify(ctx, c.der, testChallenge); !errors.Is(err, androidkey.ErrCertificateValidity) {
		t.Fatalf("Verify an hour later = %v, want ErrCertificateValidity", err)
	}
	if err := v.Recheck(ctx, &f); !errors.Is(err, androidkey.ErrCertificateValidity) {
		t.Fatalf("Verifier.Recheck an hour later = %v, want ErrCertificateValidity", err)
	}
	k := walletprovider.InstanceKey{Thumbprint: "tp", InstanceID: "i", EvidenceFacts: ev.Facts}
	for _, e := range []androidkey.EvidenceVerifier{e, {Verifier: v, AllowUncheckedLegacyEvidence: true}} {
		for name, err := range map[string]error{"Recheck": e.Recheck(ctx, in), "RecheckInstanceKey": e.RecheckInstanceKey(ctx, in, k)} {
			if !errors.Is(err, walletprovider.ErrEvidenceRejected) || !errors.Is(err, androidkey.ErrCertificateValidity) ||
				errors.Is(err, walletprovider.ErrEvidenceRevoked) || errors.Is(err, walletprovider.ErrEvidenceSuspended) {
				t.Fatalf("%s an hour later (allowing legacy records: %t) = %v, want an ErrCertificateValidity refusal", name, e.AllowUncheckedLegacyEvidence, err)
			}
		}
	}

	// Without the validity periods, as v0.80.0 saved Facts: refused by
	// Verifier.Recheck and by default, accepted when allowed.
	for i := range f.Certificates {
		f.Certificates[i].NotBefore, f.Certificates[i].NotAfter = time.Time{}, time.Time{}
	}
	if f.ValidityRecorded() || !f.Expiry().IsZero() {
		t.Fatalf("Facts without validity: recorded %t, expiry %v", f.ValidityRecorded(), f.Expiry())
	}
	if err := v.Recheck(ctx, &f); !errors.Is(err, androidkey.ErrLegacyFacts) {
		t.Fatalf("Verifier.Recheck of Facts without validity = %v, want ErrLegacyFacts", err)
	}
	if in.EvidenceFacts, err = json.Marshal(f); err != nil {
		t.Fatal(err)
	}
	if err := e.Recheck(ctx, in); !errors.Is(err, walletprovider.ErrEvidenceRejected) || !errors.Is(err, androidkey.ErrLegacyFacts) {
		t.Fatalf("Recheck of Facts without validity = %v, want ErrLegacyFacts refused", err)
	}
	if err := (androidkey.EvidenceVerifier{Verifier: v, AllowUncheckedLegacyEvidence: true}).Recheck(ctx, in); err != nil {
		t.Fatalf("Recheck of Facts without validity, allowed = %v", err)
	}
}

// TestRecheckRootKeyValidity: as Verify does, Recheck judges a chain
// certificate with the configured root's key by the root's validity,
// not its own, so a chain ending at an expired copy of a root whose key
// lives on in a re-issue still rechecks; and the configured root's own
// expiry refuses it.
func TestRecheckRootKeyValidity(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	rootKey := newKey(t, elliptic.P256())
	old := issue(t, withValidity(certTemplate("Test Attestation Root", 1, true), [2]time.Time{now.Add(-time.Hour), now.Add(30 * time.Minute)}), nil, rootKey, &rootKey.PublicKey)
	reissued := issue(t, certTemplate("Test Attestation Root", 1, true), nil, rootKey, &rootKey.PublicKey)
	c := attestationCA{root: old, rootKey: rootKey}.chain(t, 5, testChallenge)
	v := &androidkey.Verifier{Roots: []*x509.Certificate{reissued}, Revocation: &androidkey.StatusList{}, Apps: []androidkey.AllowedApp{testApp}}
	r, err := v.Verify(ctx, c.der, testChallenge)
	if err != nil {
		t.Fatal(err)
	}
	f := androidkey.FactsOf(r)
	if !f.Certificates[2].RootKey || !f.Expiry().Equal(c.inter.NotAfter) {
		t.Fatalf("Facts = %+v, expiry %v; want the root's copy marked, the intermediate expiring first", f.Certificates, f.Expiry())
	}
	v.Now = func() time.Time { return now.Add(time.Hour) }
	if err := v.Recheck(ctx, &f); err != nil {
		t.Fatalf("Recheck once the chain's copy of the root expired = %v", err)
	}
	v.Now = func() time.Time { return now.Add(48 * time.Hour) }
	if err := v.Recheck(ctx, &f); !errors.Is(err, androidkey.ErrCertificateValidity) {
		t.Fatalf("Recheck once the configured root expired = %v, want ErrCertificateValidity", err)
	}
}
