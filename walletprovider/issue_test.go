package walletprovider_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

func (h *harness) x5c() []string {
	out := make([]string, len(h.chain))
	for i, c := range h.chain {
		out[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return out
}

func TestWalletAttestation(t *testing.T) {
	h := newHarness(t, nil)
	in, key := h.register(kindStrongBox)
	jwt, err := h.walletAttestation(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := jose.Verify(oid4vci.ES256, &h.signer.PublicKey, jwt)
	if err != nil {
		t.Fatalf("verifying the Wallet Attestation with the provider's key: %v", err)
	}
	if header["typ"] != attestation.WalletAttestationTypHeader {
		t.Fatalf("typ = %v", header["typ"])
	}
	var x5c []string
	for _, c := range header["x5c"].([]any) {
		x5c = append(x5c, c.(string))
	}
	if !reflect.DeepEqual(x5c, h.x5c()) {
		t.Fatalf("x5c = %v, want the signer's chain without the anchor", x5c)
	}
	var claims struct {
		Iss        string                     `json:"iss"`
		Sub        string                     `json:"sub"`
		Iat        int64                      `json:"iat"`
		Exp        int64                      `json:"exp"`
		Cnf        map[string]json.RawMessage `json:"cnf"`
		WalletName string                     `json:"wallet_name"`
		WalletLink string                     `json:"wallet_link"`
		Status     map[string]any             `json:"status"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	now := h.clock.now().Unix()
	if claims.Iss != identifier || claims.Sub != clientID || claims.Iat != now || claims.Exp != now+int64(time.Hour/time.Second) {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.WalletName != walletName || claims.WalletLink != walletLink {
		t.Fatalf("wallet_name, wallet_link = %q, %q", claims.WalletName, claims.WalletLink)
	}
	if ok, err := jwk.Matches(claims.Cnf["jwk"], &key.PublicKey); err != nil || !ok {
		t.Fatalf("cnf.jwk %s isn't the instance key (%v)", claims.Cnf["jwk"], err)
	}
	ref, err := statuslist.ParseStatusClaim(claims.Status)
	if err != nil || ref != in.Status {
		t.Fatalf("status = %v (%v), want %+v", claims.Status, err, in.Status)
	}
	extra, err := attestation.ParseWalletAttestationClaims(jwt)
	if err != nil || extra.WalletName != walletName {
		t.Fatalf("ParseWalletAttestationClaims = %+v, %v", extra, err)
	}

	stored, err := h.deps.Instances.Get(context.Background(), in.ID)
	if err != nil || stored.WalletAttestations != 1 {
		t.Fatalf("after one Wallet Attestation the instance has %d (%v)", stored.WalletAttestations, err)
	}
}

func TestWalletAttestationRefuses(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindFake)
	if _, err := h.p.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{InstanceID: in.ID, ClientID: "other"}); !errors.Is(err, walletprovider.ErrUnknownClient) {
		t.Fatalf("WalletAttestation(unknown client) = %v, want ErrUnknownClient", err)
	}
	if _, err := h.walletAttestation("nope"); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
		t.Fatalf("WalletAttestation(unknown instance) = %v, want ErrInstanceNotFound", err)
	}
	if _, err := h.walletAttestation(""); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
		t.Fatalf("WalletAttestation(no instance) = %v, want ErrInstanceNotFound", err)
	}
}

// TestPolicyTighteningRefusesExistingInstances: the policy is applied
// again at every attestation.
func TestPolicyTighteningRefusesExistingInstances(t *testing.T) {
	h := newHarness(t, nil)
	in, key := h.register(kindTEE)

	stricter := h.cfg
	stricter.Policy = policy()
	android := stricter.Policy.Platforms[walletprovider.PlatformAndroid]
	android.MinAppVersion = 11
	stricter.Policy.Platforms[walletprovider.PlatformAndroid] = android
	p2, err := walletprovider.New(stricter, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	h2 := &harness{t: t, p: p2, clock: h.clock, signer: h.signer, chain: h.chain, cfg: stricter, deps: h.deps}
	if _, err := h2.walletAttestation(in.ID); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("WalletAttestation after raising the minimum version = %v, want ErrPolicy", err)
	}
	if _, err := h2.keyAttestation(in.ID, []*ecdsa.PrivateKey{key}, kindTEE); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("KeyAttestation after raising the minimum version = %v, want ErrPolicy", err)
	}

	noStrongBoxOnly := h.cfg
	noStrongBoxOnly.Policy = policy()
	android = noStrongBoxOnly.Policy.Platforms[walletprovider.PlatformAndroid]
	android.SecurityLevels = []walletprovider.SecurityLevel{walletprovider.SecurityLevelStrongBox}
	noStrongBoxOnly.Policy.Platforms[walletprovider.PlatformAndroid] = android
	p3, err := walletprovider.New(noStrongBoxOnly, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p3.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{InstanceID: in.ID, ClientID: clientID}); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("WalletAttestation for a TEE instance once only StrongBox is accepted = %v, want ErrPolicy", err)
	}
}

// verifyKeyAttestation parses and verifies a Key Attestation as an
// issuer does, and checks the claims every one carries.
func (h *harness) verifyKeyAttestation(res walletprovider.KeyAttestationResult, in walletprovider.Instance, keys ...crypto.PublicKey) attestation.VerifiedClaims {
	h.t.Helper()
	ka, err := attestation.Parse(res.JWT)
	if err != nil {
		h.t.Fatal(err)
	}
	if !reflect.DeepEqual(ka.X5C(), h.x5c()) {
		h.t.Fatalf("x5c = %v, want the signer's chain", ka.X5C())
	}
	v, err := ka.Verify(&h.signer.PublicKey, oid4vci.ES256, attestation.VerifyOptions{Now: h.clock.now(), ExpectedNonce: "c-nonce", RequireExpiry: true})
	if err != nil {
		h.t.Fatalf("verifying the Key Attestation (Verify checks its typ): %v", err)
	}
	now := h.clock.now().Truncate(time.Second)
	if v.Issuer != identifier || !v.IssuedAt.Equal(now) || v.ExpiresAt == nil || !v.ExpiresAt.Equal(now.Add(2*time.Hour)) || v.Nonce != "c-nonce" {
		h.t.Fatalf("claims = %+v", v)
	}
	if !res.ExpiresAt.Truncate(time.Second).Equal(*v.ExpiresAt) {
		h.t.Fatalf("result expires %v, the JWT %v", res.ExpiresAt, *v.ExpiresAt)
	}
	ref, err := statuslist.ParseStatusClaim(v.Status)
	if err != nil || ref != in.Status {
		h.t.Fatalf("status = %v (%v), want %+v", v.Status, err, in.Status)
	}
	if len(v.AttestedKeys) != len(keys) || len(res.AttestedKeys) != len(keys) {
		h.t.Fatalf("attests %d keys (result %d), want %d", len(v.AttestedKeys), len(res.AttestedKeys), len(keys))
	}
	for _, k := range keys {
		if ok, _ := v.KeyAttested(k); !ok {
			h.t.Fatal("a key that should be attested isn't")
		}
	}
	if !reflect.DeepEqual(nilIfEmpty(v.KeyStorage), res.KeyStorage) || !reflect.DeepEqual(nilIfEmpty(v.UserAuthentication), res.UserAuthentication) {
		h.t.Fatalf("result claims %v %v, the JWT %v %v", res.KeyStorage, res.UserAuthentication, v.KeyStorage, v.UserAuthentication)
	}
	return v
}

func nilIfEmpty(s []attestation.AttackPotentialResistance) []attestation.AttackPotentialResistance {
	if len(s) == 0 {
		return nil
	}
	return s
}

type levels = []attestation.AttackPotentialResistance

func TestKeyAttestationClaimsFromPolicyTable(t *testing.T) {
	high, moderate := attestation.ISO18045High, attestation.ISO18045Moderate
	appAssertionRule := func(c *walletprovider.Config, binding walletprovider.KeyBinding) {
		c.Policy.KeyStorage = append(c.Policy.KeyStorage, walletprovider.KeyStorageRule{
			Platform: walletprovider.PlatformIOS, SecurityLevel: walletprovider.SecurityLevelSecureEnclave,
			Binding: binding, KeyStorage: levels{moderate},
		})
	}
	cases := []struct {
		name               string
		instance           string
		kinds              []string
		mutate             func(*walletprovider.Config)
		keyStorage, userAu levels
	}{
		{"strongbox with user authentication", kindStrongBox, []string{kindStrongBox, kindStrongBox}, nil, levels{high, moderate}, levels{high}},
		{"tee", kindTEE, []string{kindTEE}, nil, levels{moderate}, nil},
		{"strongbox and tee share only what both rows list", kindTEE, []string{kindStrongBox, kindTEE}, nil, levels{moderate}, nil},
		{"no matching row claims nothing", kindFake, []string{kindFake}, nil, nil, nil},
		{"ios claims nothing by default", kindIOS, []string{kindIOS}, nil, nil, nil},
		{"ios with an app-assertion row", kindIOS, []string{kindIOS}, func(c *walletprovider.Config) {
			appAssertionRule(c, walletprovider.KeyBindingAppAssertion)
		}, levels{moderate}, nil},
		{"ios against a row for attested keys", kindIOS, []string{kindIOS}, func(c *walletprovider.Config) {
			appAssertionRule(c, "")
		}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) {
				if tc.mutate != nil {
					tc.mutate(c)
				}
			})
			in, _ := h.register(tc.instance)
			keys := make([]*ecdsa.PrivateKey, len(tc.kinds))
			pubs := make([]crypto.PublicKey, len(tc.kinds))
			for i := range keys {
				keys[i] = newKey(t)
				pubs[i] = &keys[i].PublicKey
			}
			res, err := h.keyAttestation(in.ID, keys, tc.kinds...)
			if err != nil {
				t.Fatal(err)
			}
			v := h.verifyKeyAttestation(res, in, pubs...)
			if !reflect.DeepEqual(nilIfEmpty(v.KeyStorage), tc.keyStorage) || !reflect.DeepEqual(nilIfEmpty(v.UserAuthentication), tc.userAu) {
				t.Fatalf("key_storage %v, user_authentication %v; want %v, %v", v.KeyStorage, v.UserAuthentication, tc.keyStorage, tc.userAu)
			}
		})
	}
}

func TestKeyAttestationOnlyKeysWithPassingEvidence(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindStrongBox)
	good, badChallenge, otherApp, software, none := newKey(t), newKey(t), newKey(t), newKey(t), newKey(t)
	ch := h.challenge(walletprovider.PurposeHolder)
	res, err := h.p.KeyAttestation(context.Background(), walletprovider.KeyAttestationRequest{
		InstanceID: in.ID, Challenge: ch, Nonce: "c-nonce",
		Keys: []crypto.PublicKey{&good.PublicKey, &badChallenge.PublicKey, &otherApp.PublicKey, &software.PublicKey, &none.PublicKey},
		Evidence: []walletprovider.Evidence{
			evidence(t, kindStrongBox, ch, &good.PublicKey),
			evidence(t, kindStrongBox, h.challenge(walletprovider.PurposeHolder), &badChallenge.PublicKey),
			evidence(t, kindOtherApp, ch, &otherApp.PublicKey),
			evidence(t, kindSoftware, ch, &software.PublicKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	v := h.verifyKeyAttestation(res, in, &good.PublicKey)
	if !reflect.DeepEqual(v.KeyStorage, levels{attestation.ISO18045High, attestation.ISO18045Moderate}) {
		t.Fatalf("key_storage = %v", v.KeyStorage)
	}
	stored, err := h.deps.Instances.Get(context.Background(), in.ID)
	if err != nil || stored.KeyAttestations != 1 {
		t.Fatalf("after one Key Attestation the instance has %d (%v)", stored.KeyAttestations, err)
	}
}

func TestKeyAttestationRefuses(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindStrongBox)
	k := newKey(t)
	t.Run("no evidence", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, []*ecdsa.PrivateKey{k}); !errors.Is(err, walletprovider.ErrEvidenceRequired) {
			t.Fatalf("KeyAttestation = %v, want ErrEvidenceRequired", err)
		}
	})
	t.Run("no keys", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, nil); !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("too many keys", func(t *testing.T) {
		keys := make([]*ecdsa.PrivateKey, walletprovider.DefaultMaxKeys+1)
		kinds := make([]string, len(keys))
		for i := range keys {
			keys[i], kinds[i] = newKey(t), kindStrongBox
		}
		if _, err := h.keyAttestation(in.ID, keys, kinds...); !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("a key twice", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, []*ecdsa.PrivateKey{k, k}, kindStrongBox, kindStrongBox); !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("only evidence from another platform", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, []*ecdsa.PrivateKey{k}, kindIOS); !errors.Is(err, walletprovider.ErrNoKeyAttested) {
			t.Fatalf("KeyAttestation = %v, want ErrNoKeyAttested", err)
		}
	})
	t.Run("only evidence the policy refuses", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, []*ecdsa.PrivateKey{k}, kindRooted); !errors.Is(err, walletprovider.ErrNoKeyAttested) {
			t.Fatalf("KeyAttestation = %v, want ErrNoKeyAttested", err)
		}
	})
	t.Run("unknown instance", func(t *testing.T) {
		if _, err := h.keyAttestation("nope", []*ecdsa.PrivateKey{k}, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
			t.Fatalf("KeyAttestation = %v, want ErrInstanceNotFound", err)
		}
	})
}

// TestKeyAttestationCounter: evidence that advances the instance's
// counter (an App Attest assertion) is accepted once.
func TestKeyAttestationCounter(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindIOS)
	attest := func(counter uint64) error {
		k := newKey(t)
		ch := h.challenge(walletprovider.PurposeHolder)
		ev, err := walletprovidertest.FakeAssertion(kindIOS, ch, counter, &k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.p.KeyAttestation(context.Background(), walletprovider.KeyAttestationRequest{
			InstanceID: in.ID, Challenge: ch, Keys: []crypto.PublicKey{&k.PublicKey}, Evidence: []walletprovider.Evidence{ev},
		})
		return err
	}
	if err := attest(1); err != nil {
		t.Fatal(err)
	}
	if err := attest(1); !errors.Is(err, walletprovider.ErrNoKeyAttested) && !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("a repeated counter = %v, want it refused", err)
	}
	if err := attest(5); err != nil {
		t.Fatal(err)
	}
	stored, err := h.deps.Instances.Get(context.Background(), in.ID)
	if err != nil || stored.Counter != 5 {
		t.Fatalf("the instance's counter is %d (%v), want 5", stored.Counter, err)
	}
}

// misbehavingVerifier reports what its report function returns, after
// running its before hook.
type misbehavingVerifier struct {
	kind   string
	before func(walletprovider.EvidenceInput)
	report func(walletprovider.EvidenceInput) walletprovider.VerifiedEvidence
}

func (v misbehavingVerifier) Kind() string { return v.kind }

func (v misbehavingVerifier) Verify(_ context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	if v.before != nil {
		v.before(in)
	}
	return v.report(in), nil
}

// TestVerifierOutputChecked: what a verifier returns is checked, so a
// faulty one can't attest a key it wasn't asked about, or leave out how
// it vouched for one.
func TestVerifierOutputChecked(t *testing.T) {
	other := newKey(t)
	key := func(in walletprovider.EvidenceInput, level walletprovider.SecurityLevel, binding walletprovider.KeyBinding) []walletprovider.AttestedKey {
		return []walletprovider.AttestedKey{{Key: in.Keys[0], SecurityLevel: level, Binding: binding}}
	}
	cases := map[string]func(walletprovider.EvidenceInput) walletprovider.VerifiedEvidence{
		"no platform": func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Keys: key(in, walletprovider.SecurityLevelSoftware, walletprovider.KeyBindingAttested)}
		},
		"a key it wasn't asked about": func(walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform, Keys: []walletprovider.AttestedKey{{
				Key: &other.PublicKey, SecurityLevel: walletprovider.SecurityLevelSoftware, Binding: walletprovider.KeyBindingAttested,
			}}}
		},
		"no security level": func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform, Keys: key(in, "", walletprovider.KeyBindingAttested)}
		},
		"no binding": func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform, Keys: key(in, walletprovider.SecurityLevelSoftware, "")}
		},
	}
	for name, report := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
				d.Evidence = append(d.Evidence, misbehavingVerifier{kind: "faulty", report: report})
			})
			if _, _, err := h.tryRegister("faulty"); err == nil {
				t.Fatal("Register accepted a faulty verifier's report")
			}
		})
	}
}

// TestKeyAttestationCounterRace: an assertion verified against a
// counter that changed meanwhile — another request using the same
// assertion — is refused by the store's compare-and-swap.
func TestKeyAttestationCounterRace(t *testing.T) {
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		instances := d.Instances
		d.Evidence = append(d.Evidence, misbehavingVerifier{
			kind: "racing",
			before: func(in walletprovider.EvidenceInput) {
				cur, err := instances.Get(context.Background(), in.Instance.ID)
				if err != nil {
					t.Error(err)
					return
				}
				cur.Counter++
				if err := instances.Update(context.Background(), cur); err != nil {
					t.Error(err)
				}
			},
			report: func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
				ev := walletprovider.VerifiedEvidence{Platform: walletprovider.PlatformIOS, AppID: iosApp}
				for _, k := range in.Keys {
					ev.Keys = append(ev.Keys, walletprovider.AttestedKey{Key: k, SecurityLevel: walletprovider.SecurityLevelSecureEnclave, Binding: walletprovider.KeyBindingAppAssertion})
				}
				next := in.Instance.Counter + 1
				ev.Counter = &next
				return ev
			},
		})
	})
	in, _ := h.register(kindIOS)
	if _, err := h.keyAttestation(in.ID, []*ecdsa.PrivateKey{newKey(t)}, "racing"); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("KeyAttestation with a counter that changed meanwhile = %v, want ErrEvidenceRejected", err)
	}
}
