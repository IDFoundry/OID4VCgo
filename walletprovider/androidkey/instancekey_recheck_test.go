package androidkey_test

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
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// providerFixture is a walletprovider.Provider verifying Android Key
// Attestation evidence with e, served over TLS, a Client of it, and
// its stores.
type providerFixture struct {
	client    *walletprovider.Client
	instances *walletprovider.MemoryInstanceStore
	keys      *walletprovider.MemoryInstanceKeyStore
	indices   *statuslist.MemoryIndexStore

	e      walletprovider.EvidenceVerifier
	signer crypto.Signer
	chain  []*x509.Certificate

	mu      sync.Mutex
	refused []error // OnRecheckRefused's errors
}

func newProviderFixture(t *testing.T, e walletprovider.EvidenceVerifier) *providerFixture {
	t.Helper()
	ca, caKey := testcert.CA(t, "Wallet Provider CA")
	id, err := url.Parse("https://provider.example")
	if err != nil {
		t.Fatal(err)
	}
	leafCert, signer := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Wallet Provider"}, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{id},
	}, ca, caKey)
	f := &providerFixture{
		instances: &walletprovider.MemoryInstanceStore{}, keys: &walletprovider.MemoryInstanceKeyStore{}, indices: &statuslist.MemoryIndexStore{},
		e: e, signer: signer, chain: []*x509.Certificate{leafCert},
	}
	f.serve(t, 42)
	return f
}

// serve points the fixture's client at a new provider over its stores,
// its Policy's MinAppVersion minAppVersion, as a redeploy with another
// Policy does.
func (f *providerFixture) serve(t *testing.T, minAppVersion uint64) {
	t.Helper()
	p, err := walletprovider.New(walletprovider.Config{
		Identifier: "https://provider.example", ClientIDs: []string{"wallet"}, StatusListBaseURI: "https://provider.example/v1/status",
		StatusListSize: 1024,
		Policy: walletprovider.Policy{
			Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{walletprovider.PlatformAndroid: {
				SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelTEE, walletprovider.SecurityLevelStrongBox},
				MinAppVersion:  minAppVersion, RequireVerifiedBoot: true,
			}},
		},
		OnRecheckRefused: func(_ context.Context, _ walletprovider.Instance, err error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.refused = append(f.refused, err)
		},
	}, walletprovider.Dependencies{
		Signer: f.signer, Chain: f.chain,
		Instances: f.instances, InstanceKeys: f.keys,
		Challenges:    &walletprovider.MemoryChallengeStore{},
		StatusIndices: f.indices, Evidence: []walletprovider.EvidenceVerifier{f.e},
		Random: rand.Reader, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(p.Handler())
	t.Cleanup(ts.Close)
	if f.client, err = walletprovider.NewClient(ts.URL, walletprovider.ClientOptions{HTTP: ts.Client()}); err != nil {
		t.Fatal(err)
	}
}

// keyStatus is the status of the instance id's one instance key.
func (f *providerFixture) keyStatus(t *testing.T, id string) statuslist.StatusType {
	t.Helper()
	keys, err := f.keys.List(context.Background(), id, "", 2)
	if err != nil || len(keys) != 1 {
		t.Fatalf("the instance's keys: %v, %v; want one", keys, err)
	}
	status, err := f.indices.Status(context.Background(), keys[0].Status.URI, keys[0].Status.Idx)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

// challenge is a fresh challenge for purpose, and the raw bytes a
// device's chain is made over.
func (f *providerFixture) challenge(t *testing.T, purpose walletprovider.Purpose) (string, []byte) {
	t.Helper()
	ch, err := f.client.Challenge(context.Background(), purpose)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ch.Value)
	if err != nil {
		t.Fatal(err)
	}
	return ch.Value, raw
}

// refusals is OnRecheckRefused's errors so far.
func (f *providerFixture) refusals() []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]error(nil), f.refused...)
}

// state is the instance id's stored state.
func (f *providerFixture) state(t *testing.T, id string) walletprovider.State {
	t.Helper()
	in, err := f.instances.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return in.State
}

// attestationCA is one attestation root, under which device chains are
// issued with intermediates of their own, as Remote Key Provisioning
// issues a device fresh attestation keys under one Google root.
type attestationCA struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func newAttestationCA(t *testing.T) attestationCA {
	t.Helper()
	key := newKey(t, elliptic.P256())
	return attestationCA{root: issue(t, certTemplate("Test Attestation Root", 1, true), nil, key, &key.PublicKey), rootKey: key}
}

// chain issues a chain over challenge under the root, its intermediate
// with serial number serial and its leaf serial+1.
func (ca attestationCA) chain(t *testing.T, serial int64, challenge []byte) testChain {
	t.Helper()
	return ca.chainUntil(t, serial, challenge, time.Time{})
}

// chainUntil is chain, with an intermediate valid until notAfter
// (zero: certTemplate's default), as Remote Key Provisioning's
// short-lived attestation certificates are.
func (ca attestationCA) chainUntil(t *testing.T, serial int64, challenge []byte, notAfter time.Time) testChain {
	t.Helper()
	s := goodSpec(t)
	s.challenge = challenge
	interKey := newKey(t, elliptic.P256())
	interTmpl := certTemplate("Test Attestation Intermediate", serial, true)
	if !notAfter.IsZero() {
		interTmpl.NotAfter = notAfter
	}
	inter := issue(t, interTmpl, ca.root, ca.rootKey, &interKey.PublicKey)
	leafKey := newKey(t, elliptic.P256())
	leaf := issue(t, leafTemplate(s.encode(t), serial+1), inter, interKey, &leafKey.PublicKey)
	return testChain{der: [][]byte{leaf.Raw, inter.Raw, ca.root.Raw}, root: ca.root, inter: inter, interKey: interKey, leafKey: leafKey}
}

// rkpWallet is an Android wallet registered with one attestation
// key's chain and holding an instance key recorded with another's,
// both under one root, as after Remote Key Provisioning rotated the
// device's attestation key between the two.
type rkpWallet struct {
	f                      *providerFixture
	v                      *androidkey.Verifier
	ca                     attestationCA
	id                     string
	registration, instance testChain
}

// rkpOpts are an rkpWallet's options: when its registration and
// instance key chains' intermediates expire (zero: certTemplate's
// default), and whether its provider accepts legacy records.
type rkpOpts struct {
	registrationUntil, instanceUntil time.Time
	allowLegacy                      bool
}

func newRKPWallet(t *testing.T, o rkpOpts) *rkpWallet {
	t.Helper()
	w := &rkpWallet{ca: newAttestationCA(t)}
	w.v = &androidkey.Verifier{Roots: []*x509.Certificate{w.ca.root}, Revocation: &androidkey.StatusList{}, Apps: []androidkey.AllowedApp{testApp}}
	w.f = newProviderFixture(t, androidkey.EvidenceVerifier{Verifier: w.v, AllowUncheckedLegacyEvidence: o.allowLegacy})

	var err error
	if w.id, w.registration, err = w.register(t, 101, o.registrationUntil); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if w.instance, err = w.attestInstanceKey(t, 201, o.instanceUntil); err != nil {
		t.Fatalf("recording the instance key: %v", err)
	}
	return w
}

// register registers a new instance with a fresh chain, its
// intermediate serial and valid until notAfter.
func (w *rkpWallet) register(t *testing.T, serial int64, notAfter time.Time) (string, testChain, error) {
	t.Helper()
	ch, raw := w.f.challenge(t, walletprovider.PurposeRegistration)
	c := w.ca.chainUntil(t, serial, raw, notAfter)
	id, err := w.f.client.Register(context.Background(), walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &c.leafKey.PublicKey, Evidence: androidkey.Evidence(c.der),
	})
	return id, c, err
}

// attestInstanceKey asks for a Wallet Attestation for a new instance
// key, with a fresh chain, its intermediate serial and valid until
// notAfter.
func (w *rkpWallet) attestInstanceKey(t *testing.T, serial int64, notAfter time.Time) (testChain, error) {
	t.Helper()
	ch, raw := w.f.challenge(t, walletprovider.PurposeInstance)
	c := w.ca.chainUntil(t, serial, raw, notAfter)
	_, err := w.f.client.WalletAttestation(context.Background(), w.registration.leafKey, walletprovider.WalletAttestationRequest{
		InstanceID: w.id, ClientID: "wallet", InstanceKey: &c.leafKey.PublicKey,
		Challenge: ch, Evidence: androidkey.Evidence(c.der),
	})
	return c, err
}

// renew asks for a Wallet Attestation for the recorded instance key,
// without evidence.
func (w *rkpWallet) renew() error {
	_, err := w.f.client.WalletAttestation(context.Background(), w.registration.leafKey, walletprovider.WalletAttestationRequest{
		InstanceID: w.id, ClientID: "wallet", InstanceKey: &w.instance.leafKey.PublicKey,
	})
	return err
}

// renewing is rkpWallet.renew as a request of TestRecheckInstanceKeyChain.
func renewing(w *rkpWallet, _ *testing.T) error { return w.renew() }

// keyAttestation asks for a Key Attestation for a holder key, with
// fresh evidence from a third attestation key, for the issuance of the
// recorded instance key.
func (w *rkpWallet) keyAttestation(t *testing.T) error {
	t.Helper()
	ch, raw := w.f.challenge(t, walletprovider.PurposeHolder)
	holder := w.ca.chain(t, 301, raw)
	_, err := w.f.client.KeyAttestation(context.Background(), w.registration.leafKey, walletprovider.KeyAttestationRequest{
		InstanceID: w.id, InstanceKey: &w.instance.leafKey.PublicKey, Challenge: ch,
		Keys: []crypto.PublicKey{&holder.leafKey.PublicKey}, Evidence: []walletprovider.Evidence{androidkey.Evidence(holder.der)},
	})
	return err
}

// TestRecheckInstanceKeyChain: an instance key's own chain is judged
// again each time the provider relies on its record. The instance
// registered with one attestation key's chain and recorded its instance
// key with another's, under the same root, as Remote Key Provisioning
// makes happen: once Google's status list names the instance key's
// intermediate, though not the registration chain's, a renewal or a Key
// Attestation for the key is refused, and REVOKED revokes the instance
// (SUSPENDED suspends it), reported to OnRecheckRefused.
func TestRecheckInstanceKeyChain(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		request func(*rkpWallet, *testing.T) error
		verdict error
		state   walletprovider.State
	}{
		{"renewal, revoked", androidkey.StatusRevoked, renewing, walletprovider.ErrEvidenceRevoked, walletprovider.StateRevoked},
		{"renewal, suspended", androidkey.StatusSuspended, renewing, walletprovider.ErrEvidenceSuspended, walletprovider.StateSuspended},
		{"Key Attestation, revoked", androidkey.StatusRevoked, (*rkpWallet).keyAttestation, walletprovider.ErrEvidenceRevoked, walletprovider.StateRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newRKPWallet(t, rkpOpts{})
			if err := w.renew(); err != nil {
				t.Fatalf("renewal before the status list names the chain: %v", err)
			}
			if err := tc.request(w, t); err != nil {
				t.Fatalf("request before the status list names the chain: %v", err)
			}
			w.v.Revocation = listingSerial(t, serialKey(w.instance.inter), tc.status)
			var refused *walletprovider.RefusedError
			if err := tc.request(w, t); !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
				t.Fatalf("request once the instance key's intermediate is %s: %v, want evidence_rejected", tc.status, err)
			}
			if got := w.f.state(t, w.id); got != tc.state {
				t.Fatalf("the instance is %s, want %s", got, tc.state)
			}
			if r := w.f.refusals(); len(r) != 1 || !errors.Is(r[0], tc.verdict) {
				t.Fatalf("OnRecheckRefused got %v, want one refusal wrapping %v", r, tc.verdict)
			}
			// The instance's state, not the list, refuses it now.
			w.v.Revocation = &androidkey.StatusList{}
			if err := w.renew(); !errors.As(err, &refused) || refused.Code == "evidence_rejected" {
				t.Fatalf("renewal once the list no longer names the chain: %v, want the instance's state refused", err)
			}
		})
	}

	t.Run("the registration chain still refuses", func(t *testing.T) {
		w := newRKPWallet(t, rkpOpts{})
		w.v.Revocation = revokingSerial(t, serialKey(w.registration.inter))
		var refused *walletprovider.RefusedError
		if err := w.renew(); !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
			t.Fatalf("renewal once the registration chain's intermediate is revoked: %v, want evidence_rejected", err)
		}
		if got := w.f.state(t, w.id); got != walletprovider.StateRevoked {
			t.Fatalf("the instance is %s, want revoked", got)
		}
	})
}

// TestInstanceRefusalKeepsInstanceKeyRevocation: when the instance
// itself is refused for another reason than revocation — the provider's
// Policy or the Verifier tightened — Google's REVOKED or SUSPENDED
// verdict on the chain of the instance key the request names, which
// the registration's chain doesn't share, still wins: the instance is
// revoked or suspended, its key's status set, and the verdict reported
// to OnRecheckRefused, not the instance's refusal.
func TestInstanceRefusalKeepsInstanceKeyRevocation(t *testing.T) {
	raisePolicy := func(w *rkpWallet, t *testing.T) { w.f.serve(t, 43) }
	raiseVerifier := func(w *rkpWallet, _ *testing.T) { w.v.MinOSPatchLevel = 202601 }
	for _, tc := range []struct {
		name     string
		tighten  func(*rkpWallet, *testing.T)
		status   string
		request  func(*rkpWallet, *testing.T) error
		verdict  error
		state    walletprovider.State
		keyState statuslist.StatusType
	}{
		{"renewal, Policy raised, revoked", raisePolicy, androidkey.StatusRevoked, renewing, walletprovider.ErrEvidenceRevoked, walletprovider.StateRevoked, statuslist.StatusInvalid},
		{"renewal, Verifier raised, revoked", raiseVerifier, androidkey.StatusRevoked, renewing, walletprovider.ErrEvidenceRevoked, walletprovider.StateRevoked, statuslist.StatusInvalid},
		{"renewal, Policy raised, suspended", raisePolicy, androidkey.StatusSuspended, renewing, walletprovider.ErrEvidenceSuspended, walletprovider.StateSuspended, statuslist.StatusSuspended},
		{"Key Attestation, Policy raised, revoked", raisePolicy, androidkey.StatusRevoked, (*rkpWallet).keyAttestation, walletprovider.ErrEvidenceRevoked, walletprovider.StateRevoked, statuslist.StatusInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newRKPWallet(t, rkpOpts{})
			w.v.Revocation = listingSerial(t, serialKey(w.instance.inter), tc.status)
			tc.tighten(w, t)
			var refused *walletprovider.RefusedError
			if err := tc.request(w, t); !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
				t.Fatalf("request = %v, want evidence_rejected", err)
			}
			if got := w.f.state(t, w.id); got != tc.state {
				t.Fatalf("the instance is %s, want %s", got, tc.state)
			}
			if got := w.f.keyStatus(t, w.id); got != tc.keyState {
				t.Fatalf("the instance key's status is %v, want %v", got, tc.keyState)
			}
			if r := w.f.refusals(); len(r) != 1 || !errors.Is(r[0], tc.verdict) {
				t.Fatalf("OnRecheckRefused got %v, want one refusal wrapping %v", r, tc.verdict)
			}
		})
	}
}
