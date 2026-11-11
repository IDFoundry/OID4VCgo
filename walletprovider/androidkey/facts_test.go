package androidkey_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// revokingSerial is a status list revoking the serial number serial,
// lowercase hex.
func revokingSerial(t *testing.T, serial string) *androidkey.StatusList {
	t.Helper()
	l, err := androidkey.ParseStatusList([]byte(`{"entries": {"` + serial + `": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestRecheck: EvidenceVerifier reports a chain's Facts, the provider
// keeps them with the instance, and Recheck judges them again by the
// Verifier as it is now: a certificate the status list has since
// named, or a policy since tightened, refuses the instance.
func TestRecheck(t *testing.T) {
	ctx := context.Background()
	c := newChain(t, goodSpec(t), chainOpts{})
	ev, err := androidkey.EvidenceVerifier{Verifier: verifierFor(t, c)}.Verify(ctx, evidenceInput(c.der, testChallenge, &c.leafKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	in := walletprovider.Instance{ID: "i", Evidence: walletprovider.EvidenceSummary{Kind: androidkey.EvidenceKind}, EvidenceFacts: ev.Facts}
	f, ok, err := androidkey.InstanceFacts(in)
	rootDigest := sha256.Sum256(c.root.RawSubjectPublicKeyInfo)
	switch {
	case err != nil || !ok:
		t.Fatalf("InstanceFacts = %v, %v", ok, err)
	case len(f.Certificates) != 3 || f.Certificates[0].Serial != "1" || f.Certificates[1].Serial != "2" ||
		f.Certificates[0].Issuer != c.inter.Subject.String():
		t.Fatalf("certificates = %+v", f.Certificates)
	case string(f.RootKeyDigest) != string(rootDigest[:]):
		t.Fatalf("root key digest = %x, want %x", f.RootKeyDigest, rootDigest)
	case f.App == nil || f.App.Packages[0].Name != appPackage || f.OSPatchLevel == nil || *f.OSPatchLevel != 202509 ||
		f.RootOfTrust == nil || f.RootOfTrust.VerifiedBootState != androidkey.Verified || f.AttestationVersion != 300 ||
		f.KeyMintSecurityLevel != androidkey.TrustedEnvironment:
		t.Fatalf("facts = %+v", f)
	}

	for name, tc := range map[string]struct {
		policy func(v *androidkey.Verifier)
		want   []error // nil: accepted
	}{
		"unchanged": {},
		"intermediate revoked since": {
			policy: func(v *androidkey.Verifier) { v.Revocation = revokingSerial(t, "2") },
			want:   []error{walletprovider.ErrEvidenceRejected, androidkey.ErrRevoked},
		},
		"root no longer trusted": {
			policy: func(v *androidkey.Verifier) {
				v.Roots = []*x509.Certificate{newChain(t, goodSpec(t), chainOpts{}).root}
			},
			want: []error{walletprovider.ErrEvidenceRejected, androidkey.ErrUntrustedRoot},
		},
		"patch level now too old": {
			policy: func(v *androidkey.Verifier) { v.MinOSPatchLevel = 202601 },
			want:   []error{walletprovider.ErrPolicy, androidkey.ErrPatchLevel},
		},
		"StrongBox now required": {
			policy: func(v *androidkey.Verifier) { v.RequireStrongBox = true },
			want:   []error{walletprovider.ErrPolicy, androidkey.ErrSoftwareLevel},
		},
		"signing certificate no longer allowed": {
			policy: func(v *androidkey.Verifier) {
				other := sha256.Sum256([]byte("another signing certificate"))
				v.Apps = []androidkey.AllowedApp{{Package: appPackage, SigningCertificateDigests: [][]byte{other[:]}}}
			},
			want: []error{walletprovider.ErrPolicy, androidkey.ErrAppNotAllowed},
		},
		"app version now too old": {
			policy: func(v *androidkey.Verifier) {
				v.Apps = []androidkey.AllowedApp{{Package: appPackage, SigningCertificateDigests: testApp.SigningCertificateDigests, MinVersion: 43}}
			},
			want: []error{walletprovider.ErrPolicy, androidkey.ErrAppNotAllowed},
		},
		// Not a refusal: the provider fails the request as its own
		// failure, and the wallet tries again.
		"status list unavailable": {
			policy: func(v *androidkey.Verifier) { v.Revocation = failingStatus{} },
			want:   []error{androidkey.ErrStatusUnavailable},
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := verifierFor(t, c)
			if tc.policy != nil {
				tc.policy(v)
			}
			err := androidkey.EvidenceVerifier{Verifier: v}.Recheck(ctx, in)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Recheck = %v", err)
				}
				return
			}
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Fatalf("Recheck = %v, want %v", err, want)
				}
			}
			if refusal := errors.Is(err, walletprovider.ErrPolicy) || errors.Is(err, walletprovider.ErrEvidenceRejected); refusal != (tc.want[0] != androidkey.ErrStatusUnavailable) {
				t.Fatalf("Recheck = %v: refusal %t", err, refusal)
			}
		})
	}

	// An instance without facts, from before they were kept or of
	// another Kind, can't be judged, and is accepted.
	strict := androidkey.EvidenceVerifier{Verifier: verifierFor(t, c)}
	strict.Verifier.Revocation = revokingSerial(t, "2")
	for _, other := range []walletprovider.Instance{
		{ID: "old", Evidence: walletprovider.EvidenceSummary{Kind: androidkey.EvidenceKind}},
		{ID: "ios", Evidence: walletprovider.EvidenceSummary{Kind: "apple-app-attest"}, EvidenceFacts: ev.Facts},
	} {
		if err := strict.Recheck(ctx, other); err != nil {
			t.Fatalf("Recheck(%s) = %v", other.ID, err)
		}
	}
	// Facts that don't decode are the provider's failure, not a refusal.
	in.EvidenceFacts = []byte("{")
	if err := strict.Recheck(ctx, in); err == nil || errors.Is(err, walletprovider.ErrPolicy) || errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("Recheck of malformed facts = %v", err)
	}
}
