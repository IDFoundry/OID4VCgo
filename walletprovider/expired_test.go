package walletprovider_test

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// TestRecheckExpired: a recheck refusal fresh evidence would fix
// (ErrEvidenceExpired with ErrEvidenceRejected) refuses the request
// with ErrRegistrationExpired when the registration's recheck refused
// it, and ErrInstanceKeyExpired when a recorded instance key's did,
// leaving the instance active. A revocation verdict outranks it, and
// ErrEvidenceExpired without a refusal is the provider's own failure.
func TestRecheckExpired(t *testing.T) {
	expired := fmt.Errorf("%w: %w: certificate 1 expired", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceExpired)
	revoked := fmt.Errorf("%w: %w: %w", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceRevoked, walletprovider.ErrEvidenceExpired)
	unchecked := fmt.Errorf("couldn't check: %w", walletprovider.ErrEvidenceExpired)
	cases := []struct {
		name     string
		instance bool // the registration's recheck refuses, not the key's
		refusal  error
		want     error // nil: neither expiry sentinel
		state    walletprovider.State
	}{
		{"registration expired", true, expired, walletprovider.ErrRegistrationExpired, walletprovider.StateActive},
		{"instance key expired", false, expired, walletprovider.ErrInstanceKeyExpired, walletprovider.StateActive},
		{"registration revoked and expired", true, revoked, nil, walletprovider.StateRevoked},
		{"instance key revoked and expired", false, revoked, nil, walletprovider.StateRevoked},
		{"not a refusal", true, unchecked, nil, walletprovider.StateActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &keyRecheckingVerifier{recheckingVerifier: &recheckingVerifier{}}
			h := keyRecheckHarness(t, v, &refusalLog{})
			in, _ := h.register(kindStrongBox)
			key := h.newInstanceKey(in.ID, kindStrongBox)
			if tc.instance {
				v.refuse(tc.refusal)
			} else {
				v.refuseKey(tc.refusal)
			}
			for name, err := range map[string]error{
				"Wallet Attestation": func() error { _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); return err }(),
				"Key Attestation": func() error {
					_, err := h.keyAttestation(in.ID, &key.PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindStrongBox)
					return err
				}(),
			} {
				if err == nil {
					t.Fatalf("%s succeeded", name)
				}
				for _, s := range []error{walletprovider.ErrRegistrationExpired, walletprovider.ErrInstanceKeyExpired} {
					if errors.Is(err, s) != (s == tc.want) {
						t.Fatalf("%s = %v: matches %v %t", name, err, s, errors.Is(err, s))
					}
				}
			}
			if got := h.stored(in.ID).State; got != tc.state {
				t.Fatalf("the instance is %s, want %s", got, tc.state)
			}
		})
	}
}

// TestRefusedErrorIs: a Client's RefusedError matches the sentinel its
// code names (CodeError), and no other.
func TestRefusedErrorIs(t *testing.T) {
	for code, want := range map[string]error{
		walletprovider.CodeRegistrationExpired:   walletprovider.ErrRegistrationExpired,
		walletprovider.CodeInstanceKeyExpired:    walletprovider.ErrInstanceKeyExpired,
		walletprovider.CodeInstanceKeyRegistered: walletprovider.ErrInstanceKeyRegistered,
		"evidence_rejected":                      nil,
	} {
		err := fmt.Errorf("asking: %w", &walletprovider.RefusedError{Status: 403, Code: code})
		if !errors.Is(err, walletprovider.ErrRefused) {
			t.Fatalf("%s: %v doesn't match ErrRefused", code, err)
		}
		if got := walletprovider.CodeError(code); got != want {
			t.Fatalf("CodeError(%s) = %v, want %v", code, got, want)
		}
		for _, s := range []error{walletprovider.ErrRegistrationExpired, walletprovider.ErrInstanceKeyExpired, walletprovider.ErrInstanceKeyRegistered} {
			if errors.Is(err, s) != (s == want) {
				t.Fatalf("%s: matches %v %t", code, s, errors.Is(err, s))
			}
		}
	}
}
