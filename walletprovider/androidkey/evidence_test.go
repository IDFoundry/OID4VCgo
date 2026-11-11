package androidkey_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

func evidenceInput(chain [][]byte, challenge []byte, keys ...crypto.PublicKey) walletprovider.EvidenceInput {
	return walletprovider.EvidenceInput{
		Evidence: androidkey.Evidence(chain), Challenge: challenge, Purpose: walletprovider.PurposeRegistration, Keys: keys,
	}
}

// TestEvidenceVerifier: a chain's verified properties become the
// VerifiedEvidence a provider's Policy decides on.
func TestEvidenceVerifier(t *testing.T) {
	ctx := context.Background()
	hw := goodHW(t)
	cases := map[string]struct {
		spec  func(s *spec)
		level walletprovider.SecurityLevel
		auth  walletprovider.UserAuthentication
		boot  walletprovider.BootState
		max   time.Duration // EvidenceVerifier.MaxAuthTimeout

		policy   func(v *androidkey.Verifier)
		unlocked bool // the evidence reports an unlocked bootloader
	}{
		"TEE, no user authentication": {
			level: walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationNone, boot: walletprovider.BootStateVerified},
		"StrongBox": {
			spec:  func(s *spec) { s.keyLevel, s.attLevel = androidkey.StrongBox, androidkey.StrongBox },
			level: walletprovider.SecurityLevelStrongBox, auth: walletprovider.UserAuthenticationNone, boot: walletprovider.BootStateVerified},
		"StrongBox key, TEE attestation": {
			spec:  func(s *spec) { s.keyLevel = androidkey.StrongBox },
			level: walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationNone, boot: walletprovider.BootStateVerified},
		"user authentication required": {
			spec: func(s *spec) {
				s.hw = replace(replace(hw, 503, nil), 504, derInt(t, int64(androidkey.AuthenticatorFingerprint)))
			},
			level: walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationRequired, boot: walletprovider.BootStateVerified},
		"user authentication within the timeout": {
			spec: func(s *spec) {
				s.hw = replace(replace(replace(hw, 503, nil), 504, derInt(t, int64(androidkey.AuthenticatorFingerprint))), 505, derInt(t, 30))
			},
			level: walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationRequired, boot: walletprovider.BootStateVerified},
		"user authentication with a longer timeout unreported": {
			spec: func(s *spec) {
				s.hw = replace(replace(replace(hw, 503, nil), 504, derInt(t, int64(androidkey.AuthenticatorFingerprint))), 505, derInt(t, 300))
			},
			level: walletprovider.SecurityLevelTEE, boot: walletprovider.BootStateVerified},
		"a longer timeout within a raised MaxAuthTimeout": {
			spec: func(s *spec) {
				s.hw = replace(replace(replace(hw, 503, nil), 504, derInt(t, int64(androidkey.AuthenticatorFingerprint))), 505, derInt(t, 300))
			},
			max:   10 * time.Minute,
			level: walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationRequired, boot: walletprovider.BootStateVerified},
		"any timeout unreported under a negative MaxAuthTimeout": {
			spec: func(s *spec) {
				s.hw = replace(replace(replace(hw, 503, nil), 504, derInt(t, int64(androidkey.AuthenticatorFingerprint))), 505, derInt(t, 1))
			},
			max:   -1,
			level: walletprovider.SecurityLevelTEE, boot: walletprovider.BootStateVerified},
		"user authentication one second past the default timeout unreported": {
			spec: func(s *spec) {
				s.hw = replace(replace(replace(hw, 503, nil), 504, derInt(t, int64(androidkey.AuthenticatorFingerprint))), 505, derInt(t, 31))
			},
			level: walletprovider.SecurityLevelTEE, boot: walletprovider.BootStateVerified},
		"no authenticator type unreported": {
			spec:  func(s *spec) { s.hw = replace(replace(hw, 503, nil), 504, derInt(t, 0)) },
			level: walletprovider.SecurityLevelTEE, boot: walletprovider.BootStateVerified},
		"software attestation of a TEE key": {
			spec:   func(s *spec) { s.attLevel = androidkey.Software },
			policy: func(v *androidkey.Verifier) { v.AllowSoftware = true },
			level:  walletprovider.SecurityLevelSoftware, auth: walletprovider.UserAuthenticationNone, boot: walletprovider.BootStateVerified},
		"unlocked bootloader, allowed": {
			spec:   func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], false, androidkey.Verified)) },
			policy: func(v *androidkey.Verifier) { v.AllowUntrustedBoot = true },
			level:  walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationNone, boot: walletprovider.BootStateVerified, unlocked: true},
		"unverified boot, allowed": {
			spec:   func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], true, androidkey.Unverified)) },
			policy: func(v *androidkey.Verifier) { v.AllowUntrustedBoot = true },
			level:  walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationNone, boot: walletprovider.BootStateUnverified},
		"user authentication unreported": {
			spec:  func(s *spec) { s.hw = replace(hw, 503, nil) },
			level: walletprovider.SecurityLevelTEE, boot: walletprovider.BootStateVerified},
		"self-signed boot, key trusted": {
			spec:  func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], true, androidkey.SelfSigned)) },
			level: walletprovider.SecurityLevelTEE, auth: walletprovider.UserAuthenticationNone, boot: walletprovider.BootStateSelfSigned},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := goodSpec(t)
			if tc.spec != nil {
				tc.spec(&s)
			}
			c := newChain(t, s, chainOpts{})
			v := verifierFor(t, c)
			v.TrustedBootKeys = [][]byte{bootKey[:]}
			if tc.policy != nil {
				tc.policy(v)
			}
			other := newKey(t, c.leafKey.Curve)
			ev, err := androidkey.EvidenceVerifier{Verifier: v, MaxAuthTimeout: tc.max}.Verify(ctx, evidenceInput(c.der, testChallenge, &other.PublicKey, &c.leafKey.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			want := walletprovider.VerifiedEvidence{
				Platform: walletprovider.PlatformAndroid, AppID: appPackage, AppVersion: 42,
				BootState: tc.boot, DeviceLocked: !tc.unlocked,
			}
			if len(ev.Keys) != 1 {
				t.Fatalf("keys = %+v", ev.Keys)
			}
			k := ev.Keys[0]
			ev.Keys = nil
			if !evidenceEqual(ev, want) {
				t.Fatalf("evidence = %+v, want %+v", ev, want)
			}
			if !c.leafKey.PublicKey.Equal(k.Key) || k.SecurityLevel != tc.level || k.Binding != walletprovider.KeyBindingAttested || k.UserAuthentication != tc.auth {
				t.Fatalf("key = %+v, want level %s, user authentication %q", k, tc.level, tc.auth)
			}
		})
	}
}

func evidenceEqual(a, b walletprovider.VerifiedEvidence) bool {
	return a.Platform == b.Platform && a.AppID == b.AppID && a.AppVersion == b.AppVersion &&
		a.BootState == b.BootState && a.DeviceLocked == b.DeviceLocked && a.Credential == nil && a.Counter == nil
}

// TestEvidenceVerifierRefuses: evidence the adapter or its Verifier
// refuses.
func TestEvidenceVerifierRefuses(t *testing.T) {
	ctx := context.Background()
	c := newChain(t, goodSpec(t), chainOpts{})
	ev := androidkey.EvidenceVerifier{Verifier: verifierFor(t, c)}
	leaf := &c.leafKey.PublicKey
	other := newKey(t, c.leafKey.Curve)
	twoPackages := goodSpec(t)
	twoPackages.sw = replace(goodSW(t), 709, appID(t, []pkg{{appPackage, 42}, {"com.example.wallet.helper", 42}}, appDigest[:]))
	twoApps := newChain(t, twoPackages, chainOpts{})
	twoAppsVerifier := verifierFor(t, twoApps)
	twoAppsVerifier.Apps = append(twoAppsVerifier.Apps, androidkey.AllowedApp{Package: "com.example.wallet.helper", SigningCertificateDigests: [][]byte{appDigest[:]}})

	cases := map[string]struct {
		v    androidkey.EvidenceVerifier
		in   walletprovider.EvidenceInput
		want error
	}{
		"no Verifier":         {in: evidenceInput(c.der, testChallenge, leaf), want: androidkey.ErrConfig},
		"another challenge":   {v: ev, in: evidenceInput(c.der, []byte("another challenge"), leaf), want: androidkey.ErrChallenge},
		"no data":             {v: ev, in: evidenceInput(nil, testChallenge, leaf), want: androidkey.ErrMalformed},
		"not DER":             {v: ev, in: walletprovider.EvidenceInput{Evidence: walletprovider.Evidence{Kind: androidkey.EvidenceKind, Data: []byte("not DER")}, Challenge: testChallenge, Keys: []crypto.PublicKey{leaf}}, want: androidkey.ErrMalformed},
		"trailing bytes":      {v: ev, in: walletprovider.EvidenceInput{Evidence: walletprovider.Evidence{Kind: androidkey.EvidenceKind, Data: append(slices.Concat(c.der...), 0x30)}, Challenge: testChallenge, Keys: []crypto.PublicKey{leaf}}, want: androidkey.ErrMalformed},
		"too many":            {v: ev, in: evidenceInput(slices.Repeat(c.der[:1], androidkey.MaxChainLength+1), testChallenge, leaf), want: androidkey.ErrMalformed},
		"not the chain order": {v: ev, in: evidenceInput([][]byte{c.der[1], c.der[0], c.der[2]}, testChallenge, leaf), want: androidkey.ErrChainSignature},
		"two packages":        {v: androidkey.EvidenceVerifier{Verifier: twoAppsVerifier}, in: evidenceInput(twoApps.der, testChallenge, &twoApps.leafKey.PublicKey), want: androidkey.ErrAppNotAllowed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.v.Verify(ctx, tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("too many, refused before they're all parsed", func(t *testing.T) {
		// Verify bounds the chain too: the adapter's own bound shows in
		// that it stops splitting at MaxChainLength.
		data := append(slices.Concat(slices.Repeat(c.der[:1], androidkey.MaxChainLength+1)...), "not DER"...)
		_, err := ev.Verify(ctx, walletprovider.EvidenceInput{Evidence: walletprovider.Evidence{Kind: androidkey.EvidenceKind, Data: data}, Challenge: testChallenge, Keys: []crypto.PublicKey{leaf}})
		if !errors.Is(err, androidkey.ErrMalformed) || !strings.Contains(err.Error(), fmt.Sprintf("more than %d certificates", androidkey.MaxChainLength)) {
			t.Fatalf("Verify = %v, want ErrMalformed for more than %d certificates", err, androidkey.MaxChainLength)
		}
	})
	t.Run("a key the request doesn't name", func(t *testing.T) {
		if _, err := ev.Verify(ctx, evidenceInput(c.der, testChallenge, &other.PublicKey)); !errors.Is(err, androidkey.ErrKeyNotRequested) {
			t.Fatalf("Verify = %v, want %v", err, androidkey.ErrKeyNotRequested)
		}
	})
	if ev.Kind() != androidkey.EvidenceKind || !bytes.Equal(androidkey.Evidence(c.der).Data, slices.Concat(c.der...)) {
		t.Fatal("Evidence or Kind")
	}
}

// TestEvidenceVerifier_RealChains: the real devices' chains verify
// under a Verifier allowing their unlocked bootloaders, and the adapter
// then refuses them: the system app that made them shares its user ID
// with other packages, and an instance belongs to one app.
func TestEvidenceVerifier_RealChains(t *testing.T) {
	for _, name := range []string{"ec_tee_chain.pem", "ec_strongbox_chain.pem"} {
		t.Run(name, func(t *testing.T) {
			chain := readChain(t, name)
			v := &androidkey.Verifier{
				Revocation: statusFixture(t), Apps: realApps(t, chain), AllowUntrustedBoot: true,
				Roots: []*x509.Certificate{mustParse(t, chain[len(chain)-1])},
				Now:   func() time.Time { return vectorTime },
			}
			leaf := mustParse(t, chain[0]).PublicKey
			if _, err := v.Verify(context.Background(), chain, []byte("abc")); err != nil {
				t.Fatalf("the Verifier: %v", err)
			}
			_, err := androidkey.EvidenceVerifier{Verifier: v}.Verify(context.Background(), evidenceInput(chain, []byte("abc"), leaf))
			if !errors.Is(err, androidkey.ErrAppNotAllowed) {
				t.Fatalf("the adapter: %v, want ErrAppNotAllowed", err)
			}
		})
	}
}

// TestEvidenceVerifierProvider: an Android wallet registers through a
// Provider's HTTP protocol with its instance key's attestation chain,
// and gets a Key Attestation for a StrongBox holder key with its own.
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

	// Each chain is made over a challenge the provider issued, so the
	// chains are made in the test as the device would make them; every
	// chain's root is trusted.
	var roots []*x509.Certificate
	v := &androidkey.Verifier{Revocation: statusFixture(t), Apps: []androidkey.AllowedApp{testApp}}
	adapter := androidkey.EvidenceVerifier{Verifier: v}
	p, err := walletprovider.New(walletprovider.Config{
		Identifier: "https://provider.example", ClientIDs: []string{"wallet"}, StatusListBaseURI: "https://provider.example/v1/status",
		StatusListSize: 1024,
		Policy: walletprovider.Policy{
			Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{walletprovider.PlatformAndroid: {
				SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelTEE, walletprovider.SecurityLevelStrongBox},
				MinAppVersion:  42, RequireVerifiedBoot: true,
			}},
		},
	}, walletprovider.Dependencies{
		Signer: signer, Chain: []*x509.Certificate{leafCert},
		Instances: &walletprovider.MemoryInstanceStore{}, InstanceKeys: &walletprovider.MemoryInstanceKeyStore{},
		Challenges:    &walletprovider.MemoryChallengeStore{},
		StatusIndices: &statuslist.MemoryIndexStore{}, Evidence: []walletprovider.EvidenceVerifier{adapter},
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

	chainFor := func(purpose walletprovider.Purpose, strongBox bool) (string, testChain) {
		ch, err := client.Challenge(ctx, purpose)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(ch.Value)
		if err != nil {
			t.Fatal(err)
		}
		s := goodSpec(t)
		s.challenge = raw
		if strongBox {
			s.keyLevel, s.attLevel = androidkey.StrongBox, androidkey.StrongBox
		}
		c := newChain(t, s, chainOpts{})
		roots = append(roots, c.root)
		v.Roots = roots
		return ch.Value, c
	}

	ch, registration := chainFor(walletprovider.PurposeRegistration, false)
	instanceID, err := client.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &registration.leafKey.PublicKey, Evidence: androidkey.Evidence(registration.der),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	ch, instance := chainFor(walletprovider.PurposeInstance, false)
	if _, err := client.WalletAttestation(ctx, registration.leafKey, walletprovider.WalletAttestationRequest{
		InstanceID: instanceID, ClientID: "wallet", InstanceKey: &instance.leafKey.PublicKey,
		Challenge: ch, Evidence: androidkey.Evidence(instance.der),
	}); err != nil {
		t.Fatalf("WalletAttestation: %v", err)
	}

	ch, holder := chainFor(walletprovider.PurposeHolder, true)
	res, err := client.KeyAttestation(ctx, registration.leafKey, walletprovider.KeyAttestationRequest{
		InstanceID: instanceID, InstanceKey: &instance.leafKey.PublicKey, Challenge: ch, Nonce: "c-nonce",
		Keys: []crypto.PublicKey{&holder.leafKey.PublicKey}, Evidence: []walletprovider.Evidence{androidkey.Evidence(holder.der)},
	})
	if err != nil {
		t.Fatalf("KeyAttestation: %v", err)
	}
	if len(res.AttestedKeys) != 1 || !holder.leafKey.PublicKey.Equal(res.AttestedKeys[0]) {
		t.Fatalf("attested %v", res.AttestedKeys)
	}

	// A chain made over another challenge than the request's isn't
	// evidence for its key.
	_, replayed := chainFor(walletprovider.PurposeHolder, false)
	ch2, err := client.Challenge(ctx, walletprovider.PurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.KeyAttestation(ctx, registration.leafKey, walletprovider.KeyAttestationRequest{
		InstanceID: instanceID, InstanceKey: &instance.leafKey.PublicKey, Challenge: ch2.Value, Nonce: "c-nonce",
		Keys: []crypto.PublicKey{&replayed.leafKey.PublicKey}, Evidence: []walletprovider.Evidence{androidkey.Evidence(replayed.der)},
	})
	var refused *walletprovider.RefusedError
	if !errors.As(err, &refused) || refused.Code != "no_key_attested" {
		t.Fatalf("a chain over another challenge: %v, want no_key_attested", err)
	}

	// A registration key's chain replayed with a fresh challenge is
	// refused.
	ch, _ = chainFor(walletprovider.PurposeRegistration, false)
	_, err = client.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &registration.leafKey.PublicKey, Evidence: androidkey.Evidence(registration.der),
	})
	if !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
		t.Fatalf("a registration chain over a used challenge: %v, want evidence_rejected", err)
	}

	// So is an instance key's, for a new instance key.
	ch, _ = chainFor(walletprovider.PurposeInstance, false)
	fresh := newChain(t, goodSpec(t), chainOpts{})
	_, err = client.WalletAttestation(ctx, registration.leafKey, walletprovider.WalletAttestationRequest{
		InstanceID: instanceID, ClientID: "wallet", InstanceKey: &fresh.leafKey.PublicKey,
		Challenge: ch, Evidence: androidkey.Evidence(instance.der),
	})
	if !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
		t.Fatalf("another key's instance chain: %v, want evidence_rejected", err)
	}

	// Once the status list revokes the device's attestation key, the
	// recorded instance key, which needs no evidence, is refused too.
	recorded := walletprovider.WalletAttestationRequest{InstanceID: instanceID, ClientID: "wallet", InstanceKey: &instance.leafKey.PublicKey}
	if _, err := client.WalletAttestation(ctx, registration.leafKey, recorded); err != nil {
		t.Fatalf("WalletAttestation for the recorded instance key: %v", err)
	}
	v.Revocation = revokingSerial(t, serialKey(registration.inter))
	_, err = client.WalletAttestation(ctx, registration.leafKey, recorded)
	if !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
		t.Fatalf("the recorded instance key after its attestation key's revocation: %v, want evidence_rejected", err)
	}
	// Google's REVOKED verdict revoked the instance: it stays refused
	// once the list no longer names the key.
	v.Revocation = &androidkey.StatusList{}
	_, err = client.WalletAttestation(ctx, registration.leafKey, recorded)
	if !errors.As(err, &refused) || refused.Code != "instance_revoked" {
		t.Fatalf("the revoked instance's recorded instance key: %v, want instance_revoked", err)
	}
}

// serialKey is c's serial number as the status list keys it.
func serialKey(c *x509.Certificate) string { return c.SerialNumber.Text(16) }
