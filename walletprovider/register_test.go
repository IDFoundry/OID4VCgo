package walletprovider_test

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

func TestMemoryInstanceStoreContract(t *testing.T) {
	walletprovidertest.TestInstanceStoreContract(t, func(*testing.T) walletprovider.InstanceStore {
		return &walletprovider.MemoryInstanceStore{}
	})
}

func TestMemoryInstanceKeyStoreContract(t *testing.T) {
	walletprovidertest.TestInstanceKeyStoreContract(t, func(*testing.T) walletprovider.InstanceKeyStore {
		return &walletprovider.MemoryInstanceKeyStore{}
	})
}

func TestMemoryChallengeStoreContract(t *testing.T) {
	walletprovidertest.TestChallengeStoreContract(t, func(*testing.T) walletprovider.ChallengeStore {
		return &walletprovider.MemoryChallengeStore{}
	})
}

func TestRegister(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindStrongBox)
	if in.ID == "" || in.State != walletprovider.StateActive || in.Revision != 1 {
		t.Fatalf("registered %+v", in)
	}
	want := walletprovider.EvidenceSummary{
		Kind: kindStrongBox, Platform: walletprovider.PlatformAndroid,
		SecurityLevel: walletprovider.SecurityLevelStrongBox, Binding: walletprovider.KeyBindingAttested,
		AppID: androidApp, AppVersion: 10, BootState: walletprovider.BootStateVerified, DeviceLocked: true,
	}
	if in.Evidence != want {
		t.Fatalf("Evidence = %+v, want %+v", in.Evidence, want)
	}
	stored, err := h.deps.Instances.Get(context.Background(), in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.KeyThumbprint != in.KeyThumbprint || string(stored.Key) != string(in.Key) {
		t.Fatalf("stored %+v, returned %+v", stored, in)
	}
	// Registering records no instance key: the first Wallet Attestation
	// does.
	if keys, err := h.deps.InstanceKeys.List(context.Background(), in.ID, "", 10); err != nil || len(keys) != 0 {
		t.Fatalf("a new instance has instance keys %v (%v)", keys, err)
	}

	other, _ := h.register(kindStrongBox)
	if other.ID == in.ID {
		t.Fatalf("two instances share an ID: %+v, %+v", in, other)
	}
}

func TestRegisterRefuses(t *testing.T) {
	h := newHarness(t, nil)
	key := newKey(t)
	other := newKey(t)
	cases := []struct {
		name     string
		evidence func(ch string) walletprovider.Evidence
		want     error
	}{
		{"no evidence", func(string) walletprovider.Evidence { return walletprovider.Evidence{} }, walletprovider.ErrEvidenceRequired},
		{"evidence without data", func(string) walletprovider.Evidence { return walletprovider.Evidence{Kind: kindFake} }, walletprovider.ErrEvidenceRequired},
		{"unknown kind", func(ch string) walletprovider.Evidence { return evidence(t, "play-integrity", ch, &key.PublicKey) }, walletprovider.ErrEvidenceKind},
		{"evidence for another key", func(ch string) walletprovider.Evidence { return evidence(t, kindFake, ch, &other.PublicKey) }, walletprovider.ErrEvidenceRejected},
		{"evidence for another challenge", func(string) walletprovider.Evidence {
			return evidence(t, kindFake, h.challenge(walletprovider.PurposeRegistration), &key.PublicKey)
		}, walletprovider.ErrEvidenceRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := h.challenge(walletprovider.PurposeRegistration)
			_, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: tc.evidence(ch)})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Register = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("no key", func(t *testing.T) {
		ch := h.challenge(walletprovider.PurposeRegistration)
		_, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{Challenge: ch, Evidence: evidence(t, kindFake, ch, &key.PublicKey)})
		if !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("Register = %v, want ErrInvalidRequest", err)
		}
	})
}

// TestRegisterKeyOnce: a registration key registers one instance.
func TestRegisterKeyOnce(t *testing.T) {
	h := newHarness(t, nil)
	key := newKey(t)
	register := func() error {
		ch := h.challenge(walletprovider.PurposeRegistration)
		_, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{
			Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: evidence(t, kindStrongBox, ch, &key.PublicKey),
		})
		return err
	}
	if err := register(); err != nil {
		t.Fatal(err)
	}
	if err := register(); !errors.Is(err, walletprovider.ErrInstanceKeyRegistered) {
		t.Fatalf("registering the same registration key again = %v, want ErrInstanceKeyRegistered", err)
	}
}

func TestRegisterPolicy(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) {
		delete(c.Policy.Platforms, walletprovider.PlatformIOS)
	})
	for name, kind := range map[string]string{
		"app version below the minimum": kindOldApp,
		"unverified boot":               kindRooted,
		"software key on android":       kindSoftware,
		"platform not accepted":         kindIOS,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := h.tryRegister(kind); !errors.Is(err, walletprovider.ErrPolicy) {
				t.Fatalf("Register = %v, want ErrPolicy", err)
			}
		})
	}
	t.Run("no app version", func(t *testing.T) {
		h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) {
			c.Policy.Platforms[walletprovider.PlatformIOS] = walletprovider.PlatformPolicy{
				SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelSecureEnclave}, MinAppVersion: 1,
			}
		})
		if _, _, err := h.tryRegister(kindIOS); !errors.Is(err, walletprovider.ErrPolicy) {
			t.Fatalf("Register = %v, want ErrPolicy", err)
		}
	})
}

func TestChallengeSingleUse(t *testing.T) {
	h := newHarness(t, nil)
	key := newKey(t)
	ch := h.challenge(walletprovider.PurposeRegistration)
	req := walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: evidence(t, kindFake, ch, &key.PublicKey)}
	if _, err := h.p.Register(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.Register(context.Background(), req); !errors.Is(err, walletprovider.ErrChallenge) {
		t.Fatalf("Register with a used challenge = %v, want ErrChallenge", err)
	}
}

func TestChallengeRefusedAttemptBurnsIt(t *testing.T) {
	h := newHarness(t, nil)
	key := newKey(t)
	ch := h.challenge(walletprovider.PurposeRegistration)
	bad := walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: evidence(t, kindFake, ch, &newKey(t).PublicKey)}
	if _, err := h.p.Register(context.Background(), bad); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("Register = %v, want ErrEvidenceRejected", err)
	}
	good := walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: evidence(t, kindFake, ch, &key.PublicKey)}
	if _, err := h.p.Register(context.Background(), good); !errors.Is(err, walletprovider.ErrChallenge) {
		t.Fatalf("Register after a refused attempt = %v, want ErrChallenge", err)
	}
}

func TestChallengeExpiry(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) { c.ChallengeTTL = time.Minute })
	key := newKey(t)
	ch, err := h.p.Challenge(context.Background(), walletprovider.PurposeRegistration)
	if err != nil {
		t.Fatal(err)
	}
	if want := h.clock.now().Add(time.Minute); !ch.ExpiresAt.Equal(want) || ch.Purpose != walletprovider.PurposeRegistration {
		t.Fatalf("Challenge = %+v, want expiry %v", ch, want)
	}
	h.clock.advance(time.Minute)
	_, err = h.p.Register(context.Background(), walletprovider.RegisterRequest{
		Challenge: ch.Value, RegistrationKey: &key.PublicKey, Evidence: evidence(t, kindFake, ch.Value, &key.PublicKey),
	})
	if !errors.Is(err, walletprovider.ErrChallenge) {
		t.Fatalf("Register with an expired challenge = %v, want ErrChallenge", err)
	}
}

func TestChallengePurpose(t *testing.T) {
	h := newHarness(t, nil)
	key := newKey(t)
	for _, purpose := range []walletprovider.Purpose{walletprovider.PurposeInstance, walletprovider.PurposeHolder, walletprovider.PurposeRequest} {
		ch := h.challenge(purpose)
		_, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{
			Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: evidence(t, kindFake, ch, &key.PublicKey),
		})
		if !errors.Is(err, walletprovider.ErrChallenge) {
			t.Fatalf("Register with a %s challenge = %v, want ErrChallenge", purpose, err)
		}
	}
	in, _ := h.register(kindFake)
	ik := h.newInstanceKey(in.ID, kindFake)
	ch := h.challenge(walletprovider.PurposeInstance)
	_, err := h.p.KeyAttestation(context.Background(), walletprovider.KeyAttestationRequest{
		InstanceID: in.ID, InstanceKey: &ik.PublicKey, Challenge: ch, Keys: []crypto.PublicKey{&key.PublicKey},
		Evidence: []walletprovider.Evidence{evidence(t, kindFake, ch, &key.PublicKey)},
	})
	if !errors.Is(err, walletprovider.ErrChallenge) {
		t.Fatalf("KeyAttestation with an instance challenge = %v, want ErrChallenge", err)
	}
	if _, err := h.p.Challenge(context.Background(), "other"); !errors.Is(err, walletprovider.ErrInvalidRequest) {
		t.Fatalf("Challenge(unknown purpose) = %v, want ErrInvalidRequest", err)
	}
	for _, v := range []string{"", "not base64!", "c2hvcnQ"} {
		_, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{
			Challenge: v, RegistrationKey: &key.PublicKey, Evidence: evidence(t, kindFake, v, &key.PublicKey),
		})
		if !errors.Is(err, walletprovider.ErrChallenge) {
			t.Fatalf("Register with challenge %q = %v, want ErrChallenge", v, err)
		}
	}
}
