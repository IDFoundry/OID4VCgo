package appattest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// app is an iOS wallet app as the tests run it: its App Attest key and
// counter, and the registration key that signs its requests.
type app struct {
	t               *testing.T
	apple           *fakeApple
	attestKey       *ecdsa.PrivateKey
	counter         uint32
	registrationKey *ecdsa.PrivateKey
}

func (a *app) attest(challenge string, keys ...crypto.PublicKey) walletprovider.Evidence {
	hash, err := ClientDataHash(walletprovider.PurposeRegistration, challenge, keys)
	if err != nil {
		a.t.Fatal(err)
	}
	obj, key := a.apple.attest(a.t, attSpec{clientDataHash: hash, aaguid: aaguidDevelopment})
	a.attestKey = key
	return Evidence(obj)
}

func (a *app) assert(purpose walletprovider.Purpose, challenge string, keys ...crypto.PublicKey) walletprovider.Evidence {
	hash, err := ClientDataHash(purpose, challenge, keys)
	if err != nil {
		a.t.Fatal(err)
	}
	a.counter++
	return Evidence(assert(a.t, a.attestKey, testAppID, a.counter, hash))
}

// TestEvidenceVerifierProvider: an iOS wallet registers through a
// Provider's HTTP protocol with an App Attest attestation, then gets a
// Wallet Attestation for an instance key and a Key Attestation for
// holder keys, each with an assertion; replayed, misbound or stale
// assertions are refused.
func TestEvidenceVerifierProvider(t *testing.T) {
	ctx := context.Background()
	ca, caKey := testcert.CA(t, "Wallet Provider CA")
	id, err := url.Parse("https://provider.example")
	if err != nil {
		t.Fatal(err)
	}
	leafCert, signer := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Wallet Provider"}, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{id},
	}, ca, caKey)
	apple := newFakeApple(t)
	v := apple.verifier()
	v.AllowDevelopment = true
	instances := &walletprovider.MemoryInstanceStore{}
	p, err := walletprovider.New(walletprovider.Config{
		Identifier: "https://provider.example", ClientIDs: []string{"wallet"}, StatusListBaseURI: "https://provider.example/v1/status",
		StatusListSize: 1024,
		Policy: walletprovider.Policy{
			Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{walletprovider.PlatformIOS: {
				SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelSecureEnclave},
			}},
			KeyStorage: []walletprovider.KeyStorageRule{{
				Platform: walletprovider.PlatformIOS, SecurityLevel: walletprovider.SecurityLevelSecureEnclave,
				Binding: walletprovider.KeyBindingAppAssertion, KeyStorage: []attestation.AttackPotentialResistance{attestation.ISO18045High},
			}},
		},
	}, walletprovider.Dependencies{
		Signer: signer, Chain: []*x509.Certificate{leafCert},
		Instances: instances, InstanceKeys: &walletprovider.MemoryInstanceKeyStore{},
		Challenges:    &walletprovider.MemoryChallengeStore{},
		StatusIndices: &statuslist.MemoryIndexStore{}, Evidence: []walletprovider.EvidenceVerifier{EvidenceVerifier{Verifier: v}},
		Random: rand.Reader, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(p.Handler())
	defer ts.Close()
	client, err := walletprovider.NewClient(ts.URL, walletprovider.ClientOptions{HTTP: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	challenge := func(purpose walletprovider.Purpose) string {
		ch, err := client.Challenge(ctx, purpose)
		if err != nil {
			t.Fatal(err)
		}
		return ch.Value
	}
	var refused *walletprovider.RefusedError
	wantRefused := func(what string, err error, code string) {
		t.Helper()
		if !errors.As(err, &refused) || refused.Code != code {
			t.Fatalf("%s: %v, want %s", what, err, code)
		}
	}

	a := &app{t: t, apple: apple, registrationKey: newKey(t, elliptic.P256())}
	ch := challenge(walletprovider.PurposeRegistration)
	instanceID, err := client.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &a.registrationKey.PublicKey, Evidence: a.attest(ch, &a.registrationKey.PublicKey),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	in, err := instances.Get(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if in.Evidence.Platform != walletprovider.PlatformIOS || in.Evidence.AppID != testAppID || in.Evidence.Kind != EvidenceKind ||
		in.Evidence.Binding != walletprovider.KeyBindingAppAssertion || in.Counter != 0 || len(in.Credential) != credentialBytes ||
		in.CredentialID != base64.StdEncoding.EncodeToString(KeyID(&a.attestKey.PublicKey)) {
		t.Fatalf("instance %+v", in)
	}

	// The App Attest key, attested again for another registration key,
	// is the instance's: it registers no other.
	again := newKey(t, elliptic.P256())
	ch = challenge(walletprovider.PurposeRegistration)
	hash, err := ClientDataHash(walletprovider.PurposeRegistration, ch, []crypto.PublicKey{&again.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	obj, _ := apple.attest(t, attSpec{clientDataHash: hash, aaguid: aaguidDevelopment, key: a.attestKey})
	_, err = client.Register(ctx, walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &again.PublicKey, Evidence: Evidence(obj)})
	wantRefused("a registered App Attest key", err, "instance_key_registered")

	// An attestation over another key than the registration key isn't
	// evidence for it.
	other := newKey(t, elliptic.P256())
	ch = challenge(walletprovider.PurposeRegistration)
	_, err = client.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &other.PublicKey, Evidence: a.attest(ch, &a.registrationKey.PublicKey),
	})
	wantRefused("an attestation over another key", err, "evidence_rejected")

	t.Run("flow", func(t *testing.T) {
		a := &app{t: t, apple: apple, registrationKey: newKey(t, elliptic.P256())}
		ch := challenge(walletprovider.PurposeRegistration)
		instanceID, err := client.Register(ctx, walletprovider.RegisterRequest{
			Challenge: ch, RegistrationKey: &a.registrationKey.PublicKey, Evidence: a.attest(ch, &a.registrationKey.PublicKey),
		})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		instanceKey := newKey(t, elliptic.P256())
		ch = challenge(walletprovider.PurposeInstance)
		if _, err := client.WalletAttestation(ctx, a.registrationKey, walletprovider.WalletAttestationRequest{
			InstanceID: instanceID, ClientID: "wallet", InstanceKey: &instanceKey.PublicKey,
			Challenge: ch, Evidence: a.assert(walletprovider.PurposeInstance, ch, &instanceKey.PublicKey),
		}); err != nil {
			t.Fatalf("WalletAttestation: %v", err)
		}

		holder := []crypto.PublicKey{&newKey(t, elliptic.P256()).PublicKey, &newKey(t, elliptic.P256()).PublicKey}
		ch = challenge(walletprovider.PurposeHolder)
		res, err := client.KeyAttestation(ctx, a.registrationKey, walletprovider.KeyAttestationRequest{
			InstanceID: instanceID, InstanceKey: &instanceKey.PublicKey, Challenge: ch, Nonce: "c-nonce",
			Keys: holder, Evidence: []walletprovider.Evidence{a.assert(walletprovider.PurposeHolder, ch, holder...)},
		})
		if err != nil {
			t.Fatalf("KeyAttestation: %v", err)
		}
		if len(res.AttestedKeys) != 2 || len(res.KeyStorage) != 1 || res.KeyStorage[0] != attestation.ISO18045High {
			t.Fatalf("Key Attestation %+v", res)
		}
		in, err := instances.Get(ctx, instanceID)
		if err != nil || in.Counter != 2 {
			t.Fatalf("counter %d, %v; want 2", in.Counter, err)
		}

		// An assertion over the holder keys in another order is over
		// other client data.
		ch = challenge(walletprovider.PurposeHolder)
		_, err = client.KeyAttestation(ctx, a.registrationKey, walletprovider.KeyAttestationRequest{
			InstanceID: instanceID, InstanceKey: &instanceKey.PublicKey, Challenge: ch,
			Keys: holder, Evidence: []walletprovider.Evidence{a.assert(walletprovider.PurposeHolder, ch, holder[1], holder[0])},
		})
		wantRefused("keys in another order", err, "no_key_attested")

		// An assertion with a counter the provider has seen is refused.
		ch = challenge(walletprovider.PurposeHolder)
		a.counter = 1
		_, err = client.KeyAttestation(ctx, a.registrationKey, walletprovider.KeyAttestationRequest{
			InstanceID: instanceID, InstanceKey: &instanceKey.PublicKey, Challenge: ch,
			Keys: holder, Evidence: []walletprovider.Evidence{a.assert(walletprovider.PurposeHolder, ch, holder...)},
		})
		wantRefused("a stale counter", err, "no_key_attested")

		// An assertion made for an instance key isn't one for holder keys.
		a.counter = 10
		ch = challenge(walletprovider.PurposeHolder)
		_, err = client.KeyAttestation(ctx, a.registrationKey, walletprovider.KeyAttestationRequest{
			InstanceID: instanceID, InstanceKey: &instanceKey.PublicKey, Challenge: ch,
			Keys: holder[:1], Evidence: []walletprovider.Evidence{a.assert(walletprovider.PurposeInstance, ch, holder[0])},
		})
		wantRefused("another purpose", err, "no_key_attested")

		// Another App Attest key's assertion isn't the instance's.
		thief := &app{t: t, apple: apple, attestKey: newKey(t, elliptic.P256()), counter: 50}
		fresh := newKey(t, elliptic.P256())
		ch = challenge(walletprovider.PurposeInstance)
		_, err = client.WalletAttestation(ctx, a.registrationKey, walletprovider.WalletAttestationRequest{
			InstanceID: instanceID, ClientID: "wallet", InstanceKey: &fresh.PublicKey,
			Challenge: ch, Evidence: thief.assert(walletprovider.PurposeInstance, ch, &fresh.PublicKey),
		})
		wantRefused("another App Attest key", err, "evidence_rejected")
	})
}

func TestEvidenceVerifierRefuses(t *testing.T) {
	ctx := context.Background()
	apple := newFakeApple(t)
	key := newKey(t, elliptic.P256())
	attestKey := newKey(t, elliptic.P256())
	devCredential, err := encodeCredential(&attestKey.PublicKey, EnvironmentDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, 32)
	keys := []crypto.PublicKey{&key.PublicKey}
	for _, tc := range []struct {
		name   string
		e      EvidenceVerifier
		in     walletprovider.EvidenceInput
		target error
	}{
		{name: "no Verifier", e: EvidenceVerifier{}, target: ErrConfig},
		{name: "no keys", e: EvidenceVerifier{Verifier: apple.verifier()}, in: walletprovider.EvidenceInput{Challenge: challenge, Purpose: walletprovider.PurposeRegistration}, target: ErrConfig},
		{name: "an attestation after registration", e: EvidenceVerifier{Verifier: apple.verifier()},
			in: walletprovider.EvidenceInput{Challenge: challenge, Purpose: walletprovider.PurposeHolder, Keys: keys}, target: ErrConfig},
		{name: "an assertion for registration", e: EvidenceVerifier{Verifier: apple.verifier()},
			in: walletprovider.EvidenceInput{Challenge: challenge, Purpose: walletprovider.PurposeRegistration, Keys: keys, Instance: &walletprovider.Instance{}}, target: ErrConfig},
		{name: "an Android instance", e: EvidenceVerifier{Verifier: apple.verifier()},
			in: walletprovider.EvidenceInput{Challenge: challenge, Purpose: walletprovider.PurposeHolder, Keys: keys, Instance: &walletprovider.Instance{}}, target: ErrConfig},
		{name: "a development key once development isn't accepted", e: EvidenceVerifier{Verifier: apple.verifier()},
			in: walletprovider.EvidenceInput{Challenge: challenge, Purpose: walletprovider.PurposeHolder, Keys: keys, Instance: &walletprovider.Instance{Credential: devCredential}}, target: ErrEnvironment},
		{name: "a counter beyond 32 bits", e: EvidenceVerifier{Verifier: &Verifier{Apps: []string{testAppID}, AllowDevelopment: true}},
			in: walletprovider.EvidenceInput{Challenge: challenge, Purpose: walletprovider.PurposeHolder, Keys: keys, Instance: &walletprovider.Instance{Credential: devCredential, Counter: 1 << 32}}, target: ErrCounter},
		{name: "a bad attestation", e: EvidenceVerifier{Verifier: apple.verifier()},
			in: walletprovider.EvidenceInput{Evidence: Evidence([]byte{0xff}), Challenge: challenge, Purpose: walletprovider.PurposeRegistration, Keys: keys}, target: ErrMalformed},
		{name: "a bad assertion", e: EvidenceVerifier{Verifier: &Verifier{Apps: []string{testAppID}, AllowDevelopment: true}},
			in: walletprovider.EvidenceInput{Evidence: Evidence([]byte{0xff}), Challenge: challenge, Purpose: walletprovider.PurposeHolder, Keys: keys, Instance: &walletprovider.Instance{Credential: devCredential}}, target: ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.e.Verify(ctx, tc.in); !errors.Is(err, tc.target) {
				t.Fatalf("got %v, want %v", err, tc.target)
			}
		})
	}
	t.Run("a good assertion for registration", func(t *testing.T) {
		credential, err := encodeCredential(&attestKey.PublicKey, EnvironmentProduction)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := ClientDataHash(walletprovider.PurposeRegistration, base64.RawURLEncoding.EncodeToString(challenge), keys)
		if err != nil {
			t.Fatal(err)
		}
		_, err = EvidenceVerifier{Verifier: apple.verifier()}.Verify(ctx, walletprovider.EvidenceInput{
			Evidence: Evidence(assert(t, attestKey, testAppID, 1, hash)), Challenge: challenge, Purpose: walletprovider.PurposeRegistration,
			Keys: keys, Instance: &walletprovider.Instance{Credential: credential},
		})
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("got %v, want ErrConfig", err)
		}
	})
	if (EvidenceVerifier{}).Kind() != EvidenceKind {
		t.Fatal("Kind")
	}
	bad := append([]byte{credentialVersion, credentialProduction}, make([]byte, 65)...)
	if _, _, err := decodeCredential(bad); !errors.Is(err, ErrConfig) {
		t.Fatalf("a credential that's no point: %v", err)
	}
	good, err := encodeCredential(&attestKey.PublicKey, EnvironmentProduction)
	if err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string]int{"another version": 0, "another environment": 1} {
		c := slices.Clone(good)
		c[at] = credentialDevelopment + 1
		if _, _, err := decodeCredential(c); !errors.Is(err, ErrConfig) {
			t.Fatalf("a credential of %s: %v", name, err)
		}
	}
}

// TestEvidenceVerifierCounter: an assertion's counter is what the
// provider stores, however far past the instance's it is.
func TestEvidenceVerifierCounter(t *testing.T) {
	apple := newFakeApple(t)
	attestKey := newKey(t, elliptic.P256())
	credential, err := encodeCredential(&attestKey.PublicKey, EnvironmentProduction)
	if err != nil {
		t.Fatal(err)
	}
	key := newKey(t, elliptic.P256())
	keys := []crypto.PublicKey{&key.PublicKey}
	challenge := make([]byte, 32)
	hash, err := ClientDataHash(walletprovider.PurposeHolder, base64.RawURLEncoding.EncodeToString(challenge), keys)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := EvidenceVerifier{Verifier: apple.verifier()}.Verify(context.Background(), walletprovider.EvidenceInput{
		Evidence: Evidence(assert(t, attestKey, testAppID, 7, hash)), Challenge: challenge, Purpose: walletprovider.PurposeHolder,
		Keys: keys, Instance: &walletprovider.Instance{Credential: credential},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Counter == nil || *ev.Counter != 7 || ev.AppID != testAppID {
		t.Fatalf("evidence %+v, want counter 7", ev)
	}
}
