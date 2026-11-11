package walletprovider_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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
	in, _ := h.register(kindStrongBox)
	key := newKey(t)
	jwt, err := h.walletAttestation(in.ID, &key.PublicKey, kindTEE)
	if err != nil {
		t.Fatal(err)
	}
	ik := h.instanceKey(&key.PublicKey)
	if ik.InstanceID != in.ID || ik.SecurityLevel != walletprovider.SecurityLevelTEE || ik.Binding != walletprovider.KeyBindingAttested ||
		ik.Status.URI != listURI(h.periodStart(), 0) || ik.PreviousStatus != (statuslist.StatusListRef{}) || ik.Revision != 1 ||
		!ik.CreatedAt.Equal(h.clock.now()) {
		t.Fatalf("recorded instance key %+v", ik)
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
	if err != nil || ref != ik.Status {
		t.Fatalf("status = %v (%v), want the instance key's %+v", claims.Status, err, ik.Status)
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

// TestWalletAttestationReusesInstanceKey: a Wallet Attestation for an
// instance key already recorded for the instance needs no evidence,
// ignores what's sent, and carries the key's status index again; a new
// instance key gets an index of its own.
func TestWalletAttestationReusesInstanceKey(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	first := h.instanceKey(&key.PublicKey)

	again, err := h.walletAttestation(in.ID, &key.PublicKey, "")
	if err != nil {
		t.Fatalf("a second Wallet Attestation for the instance key, without evidence: %v", err)
	}
	if ref := walletAttestationStatus(t, again); ref != first.Status {
		t.Fatalf("the second Wallet Attestation's status is %+v, want the instance key's %+v", ref, first.Status)
	}

	// Evidence sent for a recorded key is ignored: not verified, and its
	// challenge left unused.
	ch := h.challenge(walletprovider.PurposeInstance)
	if _, err := h.p.WalletAttestation(ctx, walletprovider.WalletAttestationRequest{
		InstanceID: in.ID, ClientID: clientID, InstanceKey: &key.PublicKey,
		Challenge: ch, Evidence: walletprovider.Evidence{Kind: "unknown", Data: []byte("x")},
	}); err != nil {
		t.Fatalf("a recorded key with evidence that wouldn't verify: %v", err)
	}
	other := newKey(t)
	if _, err := h.p.WalletAttestation(ctx, walletprovider.WalletAttestationRequest{
		InstanceID: in.ID, ClientID: clientID, InstanceKey: &other.PublicKey,
		Challenge: ch, Evidence: evidence(t, kindStrongBox, ch, &other.PublicKey),
	}); err != nil {
		t.Fatalf("a new key with the challenge a recorded key's request named: %v", err)
	}
	if second := h.instanceKey(&other.PublicKey); second.Status == first.Status || second.InstanceID != in.ID {
		t.Fatalf("a second instance key %+v shares the first's status or isn't the instance's", second)
	}
	if got := h.instanceKey(&key.PublicKey); !reflect.DeepEqual(got, first) {
		t.Fatalf("the instance key's record changed: %+v, was %+v", got, first)
	}
	keys, err := h.deps.InstanceKeys.List(ctx, in.ID, "", 10)
	if err != nil || len(keys) != 2 {
		t.Fatalf("the instance has %d instance keys (%v), want 2", len(keys), err)
	}
	stored, err := h.deps.Instances.Get(ctx, in.ID)
	if err != nil || stored.WalletAttestations != 4 {
		t.Fatalf("after four Wallet Attestations the instance has %d (%v)", stored.WalletAttestations, err)
	}
}

func walletAttestationStatus(t *testing.T, jwt string) statuslist.StatusListRef {
	t.Helper()
	_, payload, err := jose.DecodeUnverified(jwt)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Status map[string]any `json:"status"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	ref, err := statuslist.ParseStatusClaim(claims.Status)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestWalletAttestationRefuses(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	in, regKey := h.register(kindStrongBox)
	key := newKey(t)
	if _, err := h.p.WalletAttestation(ctx, walletprovider.WalletAttestationRequest{InstanceID: in.ID, ClientID: "other", InstanceKey: &key.PublicKey}); !errors.Is(err, walletprovider.ErrUnknownClient) {
		t.Fatalf("WalletAttestation(unknown client) = %v, want ErrUnknownClient", err)
	}
	if _, err := h.walletAttestation("nope", &key.PublicKey, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
		t.Fatalf("WalletAttestation(unknown instance) = %v, want ErrInstanceNotFound", err)
	}
	if _, err := h.walletAttestation("", &key.PublicKey, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
		t.Fatalf("WalletAttestation(no instance) = %v, want ErrInstanceNotFound", err)
	}
	if _, err := h.p.WalletAttestation(ctx, walletprovider.WalletAttestationRequest{InstanceID: in.ID, ClientID: clientID}); !errors.Is(err, walletprovider.ErrInvalidRequest) {
		t.Fatalf("WalletAttestation(no instance key) = %v, want ErrInvalidRequest", err)
	}

	other, _ := h.register(kindStrongBox)
	othersKey := h.newInstanceKey(other.ID, kindStrongBox)
	_, otherReg := h.register(kindStrongBox)
	cases := []struct {
		name string
		key  crypto.PublicKey
		req  func(*walletprovider.WalletAttestationRequest)
		want error
	}{
		{"a new instance key without evidence", &key.PublicKey, nil, walletprovider.ErrEvidenceRequired},
		{"another instance's instance key", &othersKey.PublicKey, nil, walletprovider.ErrInstanceKeyRegistered},
		{"its registration key as an instance key", &regKey.PublicKey, nil, walletprovider.ErrInstanceKeyRegistered},
		{"evidence from another platform", &key.PublicKey, withEvidence(t, h, kindIOS, walletprovider.PurposeInstance), walletprovider.ErrEvidenceRejected},
		{"evidence from another app", &key.PublicKey, withEvidence(t, h, kindOtherApp, walletprovider.PurposeInstance), walletprovider.ErrEvidenceRejected},
		{"a security level the policy refuses", &key.PublicKey, withEvidence(t, h, kindSoftware, walletprovider.PurposeInstance), walletprovider.ErrPolicy},
		{"a device the policy refuses", &key.PublicKey, withEvidence(t, h, kindRooted, walletprovider.PurposeInstance), walletprovider.ErrPolicy},
		{"an unknown evidence kind", &key.PublicKey, withEvidence(t, h, "play-integrity", walletprovider.PurposeInstance), walletprovider.ErrEvidenceKind},
		{"a registration challenge", &key.PublicKey, withEvidence(t, h, kindStrongBox, walletprovider.PurposeRegistration), walletprovider.ErrChallenge},
		{"a holder challenge", &key.PublicKey, withEvidence(t, h, kindStrongBox, walletprovider.PurposeHolder), walletprovider.ErrChallenge},
		{"evidence for another key", &key.PublicKey, func(r *walletprovider.WalletAttestationRequest) {
			r.Challenge = h.challenge(walletprovider.PurposeInstance)
			r.Evidence = evidence(t, kindStrongBox, r.Challenge, &otherReg.PublicKey)
		}, walletprovider.ErrEvidenceRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := walletprovider.WalletAttestationRequest{InstanceID: in.ID, ClientID: clientID, InstanceKey: tc.key}
			if tc.req != nil {
				tc.req(&req)
			}
			if _, err := h.p.WalletAttestation(ctx, req); !errors.Is(err, tc.want) {
				t.Fatalf("WalletAttestation = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := h.deps.InstanceKeys.Get(ctx, h.thumbprint(&key.PublicKey)); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("a refused instance key was recorded: %v", err)
	}

	// Nor is an instance key registered as another instance's
	// registration key.
	ch := h.challenge(walletprovider.PurposeRegistration)
	if _, err := h.p.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &othersKey.PublicKey, Evidence: evidence(t, kindStrongBox, ch, &othersKey.PublicKey),
	}); !errors.Is(err, walletprovider.ErrInstanceKeyRegistered) {
		t.Fatalf("registering an instance key as a registration key = %v, want ErrInstanceKeyRegistered", err)
	}
}

// withEvidence sets a request's challenge, one issued for purpose, and
// evidence of kind over it for its instance key.
func withEvidence(t *testing.T, h *harness, kind string, purpose walletprovider.Purpose) func(*walletprovider.WalletAttestationRequest) {
	return func(r *walletprovider.WalletAttestationRequest) {
		r.Challenge = h.challenge(purpose)
		r.Evidence = evidence(t, kind, r.Challenge, r.InstanceKey)
	}
}

// TestStatusIndexPerInstanceKey: registering reserves no status index;
// each new instance key reserves one, on the period's lists in order,
// until every one of them is full.
func TestStatusIndexPerInstanceKey(t *testing.T) {
	// Four entries a list, of which half are handed out.
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) { c.StatusListSize = 4 })
	in, _ := h.register(kindStrongBox)
	if n, err := h.deps.StatusIndices.Reserved(context.Background(), listURI(h.periodStart(), 0)); err != nil || n != 0 {
		t.Fatalf("registering reserved %d status indices (%v)", n, err)
	}
	fill := func() walletprovider.StatusListFill {
		t.Helper()
		f, err := h.p.StatusListFill(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if f := fill(); len(f.Lists) != walletprovider.MaxStatusListsPerPeriod || f.Free() != walletprovider.MaxStatusListsPerPeriod*2 ||
		f.Start.Unix() != h.periodStart() || f.End.Sub(f.Start) != walletprovider.DefaultStatusListPeriod ||
		f.Lists[1].URI != listURI(h.periodStart(), 1) || f.Lists[1].Size != 4 || f.Lists[1].Limit != 2 {
		t.Fatalf("an unused period's fill = %+v", f)
	}
	for i := range 2 * walletprovider.MaxStatusListsPerPeriod {
		key := h.newInstanceKey(in.ID, kindStrongBox)
		if got, want := h.instanceKey(&key.PublicKey).Status.URI, listURI(h.periodStart(), i/2); got != want {
			t.Fatalf("instance key %d is on %s, want %s", i, got, want)
		}
		if i == 2 {
			if f := fill(); f.Free() != 2*walletprovider.MaxStatusListsPerPeriod-3 || !f.Lists[0].Full() || f.Lists[1].Reserved != 1 {
				t.Fatalf("after 3 instance keys, fill = %+v", f)
			}
		}
	}
	if f := fill(); f.Free() != 0 {
		t.Fatalf("a full period's lists have %d free", f.Free())
	}
	_, err := h.walletAttestation(in.ID, &newKey(t).PublicKey, kindStrongBox)
	if !errors.Is(err, statuslist.ErrListsFull) || !strings.Contains(err.Error(), "the status lists of the current period are full") {
		t.Fatalf("an instance key past the period's lists = %v, want them full", err)
	}
	// The next period has room again.
	h.clock.advance(walletprovider.DefaultStatusListPeriod)
	h.newInstanceKey(in.ID, kindStrongBox)
	if f := fill(); f.Start.Unix() != h.periodStart() || f.Free() != 2*walletprovider.MaxStatusListsPerPeriod-1 {
		t.Fatalf("the next period's fill = %+v", f)
	}
}

// reservedErrIndices fails Reserved.
type reservedErrIndices struct{ statuslist.MemoryIndexStore }

func (*reservedErrIndices) Reserved(context.Context, string) (int, error) {
	return 0, errors.New("store down")
}

// TestStatusListFillStoreError: StatusListFill reports a store that
// can't count.
func TestStatusListFillStoreError(t *testing.T) {
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.StatusIndices = &reservedErrIndices{}
	})
	if _, err := h.p.StatusListFill(context.Background()); err == nil || !strings.Contains(err.Error(), "store down") {
		t.Fatalf("StatusListFill with a failing store = %v", err)
	}
}

// TestInstanceKeyAssertionCounter: instance key evidence that advances
// the instance's counter (an App Attest assertion) is accepted once.
func TestInstanceKeyAssertionCounter(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindIOS)
	record := func(counter uint64) error {
		k := newKey(t)
		ch := h.challenge(walletprovider.PurposeInstance)
		ev, err := walletprovidertest.FakeAssertion(kindIOS, ch, counter, &k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.p.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{
			InstanceID: in.ID, ClientID: clientID, InstanceKey: &k.PublicKey, Challenge: ch, Evidence: ev,
		})
		return err
	}
	if err := record(3); err != nil {
		t.Fatal(err)
	}
	if err := record(3); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("a repeated counter = %v, want ErrEvidenceRejected", err)
	}
	stored, err := h.deps.Instances.Get(context.Background(), in.ID)
	if err != nil || stored.Counter != 3 {
		t.Fatalf("the instance's counter is %d (%v), want 3", stored.Counter, err)
	}
}

// TestPolicyTighteningRefusesExistingInstances: the policy is applied
// again at every attestation.
func TestPolicyTighteningRefusesExistingInstances(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindTEE)
	ik := h.newInstanceKey(in.ID, kindTEE)
	key := newKey(t)

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
	if _, err := h2.walletAttestation(in.ID, &ik.PublicKey, ""); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("WalletAttestation after raising the minimum version = %v, want ErrPolicy", err)
	}
	if _, err := h2.keyAttestation(in.ID, &ik.PublicKey, []*ecdsa.PrivateKey{key}, kindTEE); !errors.Is(err, walletprovider.ErrPolicy) {
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
	if _, err := p3.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{InstanceID: in.ID, ClientID: clientID, InstanceKey: &ik.PublicKey}); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("WalletAttestation for a TEE instance once only StrongBox is accepted = %v, want ErrPolicy", err)
	}

	// The instance key's own security level is checked again too.
	sb, _ := h.register(kindStrongBox)
	sbKey := h.newInstanceKey(sb.ID, kindTEE)
	if _, err := p3.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{InstanceID: sb.ID, ClientID: clientID, InstanceKey: &sbKey.PublicKey}); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("WalletAttestation for a TEE instance key once only StrongBox is accepted = %v, want ErrPolicy", err)
	}
	h3 := &harness{t: t, p: p3, clock: h.clock, signer: h.signer, chain: h.chain, cfg: noStrongBoxOnly, deps: h.deps}
	if _, err := h3.keyAttestation(sb.ID, &sbKey.PublicKey, []*ecdsa.PrivateKey{key}, kindStrongBox); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("KeyAttestation for a TEE instance key once only StrongBox is accepted = %v, want ErrPolicy", err)
	}
}

// verifyKeyAttestation parses and verifies a Key Attestation as an
// issuer does, and checks the claims every one carries.
func (h *harness) verifyKeyAttestation(res walletprovider.KeyAttestationResult, status statuslist.StatusListRef, keys ...crypto.PublicKey) attestation.VerifiedClaims {
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
	if err != nil || ref != status {
		h.t.Fatalf("status = %v (%v), want the instance key's %+v", v.Status, err, status)
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
	strongBoxOnly := func(c *walletprovider.Config) {
		c.Policy.KeyStorage = []walletprovider.KeyStorageRule{{
			Platform: walletprovider.PlatformAndroid, SecurityLevel: walletprovider.SecurityLevelStrongBox, KeyStorage: levels{high},
		}}
	}
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
		{"a row for another level matches no key", kindTEE, []string{kindTEE}, strongBoxOnly, nil, nil},
		{"a row requiring user authentication doesn't match a key without it", kindTEE, []string{kindTEE}, func(c *walletprovider.Config) {
			c.Policy.KeyStorage = []walletprovider.KeyStorageRule{{
				Platform: walletprovider.PlatformAndroid, SecurityLevel: walletprovider.SecurityLevelTEE,
				UserAuthentication: walletprovider.UserAuthenticationRequired,
				KeyStorage:         levels{moderate}, UserAuthenticationLevels: levels{high},
			}}
		}, nil, nil},
		{"a key no row matches leaves out what the others' rows list", kindStrongBox, []string{kindStrongBox, kindTEE}, strongBoxOnly, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) {
				if tc.mutate != nil {
					tc.mutate(c)
				}
			})
			in, _ := h.register(tc.instance)
			ik := h.newInstanceKey(in.ID, tc.instance)
			keys := make([]*ecdsa.PrivateKey, len(tc.kinds))
			pubs := make([]crypto.PublicKey, len(tc.kinds))
			for i := range keys {
				keys[i] = newKey(t)
				pubs[i] = &keys[i].PublicKey
			}
			res, err := h.keyAttestation(in.ID, &ik.PublicKey, keys, tc.kinds...)
			if err != nil {
				t.Fatal(err)
			}
			v := h.verifyKeyAttestation(res, h.instanceKey(&ik.PublicKey).Status, pubs...)
			if !reflect.DeepEqual(nilIfEmpty(v.KeyStorage), tc.keyStorage) || !reflect.DeepEqual(nilIfEmpty(v.UserAuthentication), tc.userAu) {
				t.Fatalf("key_storage %v, user_authentication %v; want %v, %v", v.KeyStorage, v.UserAuthentication, tc.keyStorage, tc.userAu)
			}
		})
	}
}

func TestKeyAttestationOnlyKeysWithPassingEvidence(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindStrongBox)
	ik := h.newInstanceKey(in.ID, kindStrongBox)
	good, badChallenge, otherApp, software, none := newKey(t), newKey(t), newKey(t), newKey(t), newKey(t)
	ch := h.challenge(walletprovider.PurposeHolder)
	res, err := h.p.KeyAttestation(context.Background(), walletprovider.KeyAttestationRequest{
		InstanceID: in.ID, InstanceKey: &ik.PublicKey, Challenge: ch, Nonce: "c-nonce",
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
	v := h.verifyKeyAttestation(res, h.instanceKey(&ik.PublicKey).Status, &good.PublicKey)
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
	in, regKey := h.register(kindStrongBox)
	ik := &h.newInstanceKey(in.ID, kindStrongBox).PublicKey
	k := newKey(t)
	t.Run("no evidence", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, ik, []*ecdsa.PrivateKey{k}); !errors.Is(err, walletprovider.ErrEvidenceRequired) {
			t.Fatalf("KeyAttestation = %v, want ErrEvidenceRequired", err)
		}
	})
	t.Run("no keys", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, ik, nil); !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation = %v, want ErrInvalidRequest", err)
		}
	})
	other, _ := h.register(kindStrongBox)
	othersKey := &h.newInstanceKey(other.ID, kindStrongBox).PublicKey
	for name, instanceKey := range map[string]crypto.PublicKey{
		"an instance key never recorded":  &newKey(t).PublicKey,
		"another instance's instance key": othersKey,
		"the registration key":            &regKey.PublicKey,
		"no instance key":                 nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.keyAttestation(in.ID, instanceKey, []*ecdsa.PrivateKey{k}, kindStrongBox)
			want := walletprovider.ErrUnknownInstanceKey
			if instanceKey == nil {
				want = walletprovider.ErrInvalidRequest
			}
			if !errors.Is(err, want) {
				t.Fatalf("KeyAttestation = %v, want %v", err, want)
			}
		})
	}
	t.Run("too many keys", func(t *testing.T) {
		keys := make([]*ecdsa.PrivateKey, walletprovider.DefaultMaxKeys+1)
		kinds := make([]string, len(keys))
		for i := range keys {
			keys[i], kinds[i] = newKey(t), kindStrongBox
		}
		if _, err := h.keyAttestation(in.ID, ik, keys, kinds...); !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("a key twice", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, ik, []*ecdsa.PrivateKey{k, k}, kindStrongBox, kindStrongBox); !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("only evidence from another platform", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, ik, []*ecdsa.PrivateKey{k}, kindIOS); !errors.Is(err, walletprovider.ErrNoKeyAttested) {
			t.Fatalf("KeyAttestation = %v, want ErrNoKeyAttested", err)
		}
	})
	t.Run("only evidence the policy refuses", func(t *testing.T) {
		if _, err := h.keyAttestation(in.ID, ik, []*ecdsa.PrivateKey{k}, kindRooted); !errors.Is(err, walletprovider.ErrNoKeyAttested) {
			t.Fatalf("KeyAttestation = %v, want ErrNoKeyAttested", err)
		}
	})
	t.Run("unknown instance", func(t *testing.T) {
		if _, err := h.keyAttestation("nope", ik, []*ecdsa.PrivateKey{k}, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
			t.Fatalf("KeyAttestation = %v, want ErrInstanceNotFound", err)
		}
	})
}

// TestKeyAttestationCounter: evidence that advances the instance's
// counter (an App Attest assertion) is accepted once.
func TestKeyAttestationCounter(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindIOS)
	ik := h.newInstanceKey(in.ID, kindIOS)
	attest := func(counter uint64) error {
		k := newKey(t)
		ch := h.challenge(walletprovider.PurposeHolder)
		ev, err := walletprovidertest.FakeAssertion(kindIOS, ch, counter, &k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.p.KeyAttestation(context.Background(), walletprovider.KeyAttestationRequest{
			InstanceID: in.ID, InstanceKey: &ik.PublicKey, Challenge: ch,
			Keys: []crypto.PublicKey{&k.PublicKey}, Evidence: []walletprovider.Evidence{ev},
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

// misbehavingVerifier reports what its report function returns.
type misbehavingVerifier struct {
	kind   string
	report func(walletprovider.EvidenceInput) walletprovider.VerifiedEvidence
}

func (v misbehavingVerifier) Kind() string { return v.kind }

func (v misbehavingVerifier) Verify(_ context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	return v.report(in), nil
}

// racingVerifier is the harness's iOS verifier, except that for
// evidence for purpose it advances the stored instance's counter
// before reporting an assertion advancing the one it was given: as if
// a concurrent request used the same assertion meanwhile.
type racingVerifier struct {
	walletprovidertest.FakeVerifier
	purpose   walletprovider.Purpose
	instances walletprovider.InstanceStore
}

func (v racingVerifier) Verify(ctx context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	ev, err := v.FakeVerifier.Verify(ctx, in)
	if err != nil || in.Purpose != v.purpose {
		return ev, err
	}
	cur, err := v.instances.Get(ctx, in.Instance.ID)
	if err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	cur.Counter++
	if err := v.instances.Update(ctx, cur); err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	next := in.Instance.Counter + 1
	ev.Counter = &next
	return ev, nil
}

// racing has the harness's iOS evidence for purpose race (racingVerifier).
func racing(purpose walletprovider.Purpose) func(*walletprovider.Config, *walletprovider.Dependencies) {
	return func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		for i, v := range d.Evidence {
			if v.Kind() == kindIOS {
				d.Evidence[i] = racingVerifier{FakeVerifier: iosVerifier(), purpose: purpose, instances: d.Instances}
			}
		}
	}
}

// TestVerifierOutputChecked: what a verifier returns is checked, so a
// faulty one can't attest a key it wasn't asked about, or leave out how
// it vouched for one.
func TestVerifierOutputChecked(t *testing.T) {
	other := newKey(t)
	key := func(in walletprovider.EvidenceInput, level walletprovider.SecurityLevel, binding walletprovider.KeyBinding) []walletprovider.AttestedKey {
		return []walletprovider.AttestedKey{{Key: in.Keys[0], SecurityLevel: level, Binding: binding}}
	}
	// Each report is refused for what's wrong with it, not by a later
	// check that happens to catch it too, such as the Policy refusing
	// an empty platform or level.
	cases := map[string]struct {
		report func(walletprovider.EvidenceInput) walletprovider.VerifiedEvidence
		want   string
	}{
		"no platform": {func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Keys: key(in, walletprovider.SecurityLevelSoftware, walletprovider.KeyBindingAttested)}
		}, "reported no platform"},
		"a key it wasn't asked about": {func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform, Keys: append(
				key(in, walletprovider.SecurityLevelSoftware, walletprovider.KeyBindingAttested),
				walletprovider.AttestedKey{Key: &other.PublicKey, SecurityLevel: walletprovider.SecurityLevelSoftware, Binding: walletprovider.KeyBindingAttested},
			)}
		}, "a key it wasn't asked about"},
		"no security level": {func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform, Keys: key(in, "", walletprovider.KeyBindingAttested)}
		}, "without a security level"},
		"no binding": {func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform, Keys: key(in, walletprovider.SecurityLevelSoftware, "")}
		}, "with binding"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
				d.Evidence = append(d.Evidence, misbehavingVerifier{kind: "faulty", report: tc.report})
			})
			if _, _, err := h.tryRegister("faulty"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Register with a faulty verifier's report = %v, want it refused as %q", err, tc.want)
			}
		})
	}
}

// TestKeyAttestationCounterRace: an assertion verified against a
// counter that changed meanwhile — another request using the same
// assertion — is refused by the store's compare-and-swap.
func TestKeyAttestationCounterRace(t *testing.T) {
	h := newHarness(t, racing(walletprovider.PurposeHolder))
	in, _ := h.register(kindIOS)
	ik := h.newInstanceKey(in.ID, kindIOS)
	if _, err := h.keyAttestation(in.ID, &ik.PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindIOS); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("KeyAttestation with a counter that changed meanwhile = %v, want ErrEvidenceRejected", err)
	}
}

// TestInstanceKeyCounterRace: a first Wallet Attestation for an
// instance key whose assertion the compare-and-swap refuses leaves the
// key unrecorded, so asking again without evidence gets nothing.
func TestInstanceKeyCounterRace(t *testing.T) {
	h := newHarness(t, racing(walletprovider.PurposeInstance))
	in, _ := h.register(kindIOS)
	key := newKey(t)
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, kindIOS); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("WalletAttestation with a counter that changed meanwhile = %v, want ErrEvidenceRejected", err)
	}
	if _, err := h.deps.InstanceKeys.Get(context.Background(), h.thumbprint(&key.PublicKey)); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("the refused instance key's record: %v, want ErrNotFound", err)
	}
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrEvidenceRequired) {
		t.Fatalf("WalletAttestation again without evidence = %v, want ErrEvidenceRequired", err)
	}
}

// TestEvidenceKindMatchesRegistration: later evidence must be of the
// Kind the instance registered with, not just from its platform and
// app: another verifier for the platform would skip the instance's
// own verifier's checks, such as App Attest's counter.
func TestEvidenceKindMatchesRegistration(t *testing.T) {
	const kindOtherIOS = "ios-other"
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		other := iosVerifier()
		other.KindName = kindOtherIOS
		d.Evidence = append(d.Evidence, other)
	})
	in, _ := h.register(kindIOS)
	key := newKey(t)
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, kindOtherIOS); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("WalletAttestation with another iOS verifier's evidence = %v, want ErrEvidenceRejected", err)
	}
	ik := h.newInstanceKey(in.ID, kindIOS)
	if _, err := h.keyAttestation(in.ID, &ik.PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindOtherIOS); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("KeyAttestation with another iOS verifier's evidence = %v, want ErrEvidenceRejected", err)
	}
}

// TestWalletAttestationSubject: the Wallet Attestation's sub is the
// client the request names, not the first one configured.
func TestWalletAttestationSubject(t *testing.T) {
	const second = "second-wallet-client"
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) {
		c.ClientIDs = []string{clientID, second}
	})
	in, _ := h.register(kindStrongBox)
	key := newKey(t)
	ch := h.challenge(walletprovider.PurposeInstance)
	jwt, err := h.p.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{
		InstanceID: in.ID, ClientID: second, InstanceKey: &key.PublicKey,
		Challenge: ch, Evidence: evidence(t, kindTEE, ch, &key.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := jose.Verify(oid4vci.ES256, &h.signer.PublicKey, jwt)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Sub != second {
		t.Fatalf("sub = %q, want %q", claims.Sub, second)
	}
}

// suspendingVerifier is the harness's fake verifier, except that for
// evidence for purpose it suspends the stored instance before
// reporting: as if the instance were suspended while its evidence was
// verified.
type suspendingVerifier struct {
	walletprovidertest.FakeVerifier
	purpose   walletprovider.Purpose
	instances walletprovider.InstanceStore
}

func (v suspendingVerifier) Verify(ctx context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	ev, err := v.FakeVerifier.Verify(ctx, in)
	if err != nil || in.Purpose != v.purpose {
		return ev, err
	}
	cur, err := v.instances.Get(ctx, in.Instance.ID)
	if err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	cur.State, cur.Reason = walletprovider.StateSuspended, "suspended meanwhile"
	if err := v.instances.Update(ctx, cur); err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	return ev, nil
}

// TestSuspendedWhileVerifying: an instance suspended while its
// evidence is verified gets nothing: the instance's state is checked
// again when its use is recorded.
func TestSuspendedWhileVerifying(t *testing.T) {
	suspending := func(purpose walletprovider.Purpose) func(*walletprovider.Config, *walletprovider.Dependencies) {
		return func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
			for i, v := range d.Evidence {
				if v.Kind() == kindFake {
					d.Evidence[i] = suspendingVerifier{purpose: purpose, instances: d.Instances}
				}
			}
		}
	}
	t.Run("Wallet Attestation", func(t *testing.T) {
		h := newHarness(t, suspending(walletprovider.PurposeInstance))
		in, _ := h.register(kindFake)
		if _, err := h.walletAttestation(in.ID, &newKey(t).PublicKey, kindFake); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
			t.Fatalf("WalletAttestation for an instance suspended meanwhile = %v, want ErrInstanceNotActive", err)
		}
	})
	t.Run("Key Attestation", func(t *testing.T) {
		h := newHarness(t, suspending(walletprovider.PurposeHolder))
		in, _ := h.register(kindFake)
		ik := h.newInstanceKey(in.ID, kindFake)
		if _, err := h.keyAttestation(in.ID, &ik.PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindFake); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
			t.Fatalf("KeyAttestation for an instance suspended meanwhile = %v, want ErrInstanceNotActive", err)
		}
	})
}

// TestKeyAttestationEvidenceBounds: a request may carry no more
// evidence than keys, and only one piece of it may advance the
// instance's counter.
func TestKeyAttestationEvidenceBounds(t *testing.T) {
	t.Run("more evidence than keys", func(t *testing.T) {
		h := newHarness(t, nil)
		in, _ := h.register(kindStrongBox)
		ik := h.newInstanceKey(in.ID, kindStrongBox)
		k := newKey(t)
		ch := h.challenge(walletprovider.PurposeHolder)
		_, err := h.p.KeyAttestation(context.Background(), walletprovider.KeyAttestationRequest{
			InstanceID: in.ID, InstanceKey: &ik.PublicKey, Challenge: ch,
			Keys:     []crypto.PublicKey{&k.PublicKey},
			Evidence: []walletprovider.Evidence{evidence(t, kindStrongBox, ch, &k.PublicKey), evidence(t, kindStrongBox, ch, &k.PublicKey)},
		})
		if !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation with two pieces of evidence for one key = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("two counters", func(t *testing.T) {
		h := newHarness(t, nil)
		in, _ := h.register(kindIOS)
		ik := h.newInstanceKey(in.ID, kindIOS)
		k1, k2 := newKey(t), newKey(t)
		ch := h.challenge(walletprovider.PurposeHolder)
		assertion := func(counter uint64, k *ecdsa.PrivateKey) walletprovider.Evidence {
			ev, err := walletprovidertest.FakeAssertion(kindIOS, ch, counter, &k.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			return ev
		}
		_, err := h.p.KeyAttestation(context.Background(), walletprovider.KeyAttestationRequest{
			InstanceID: in.ID, InstanceKey: &ik.PublicKey, Challenge: ch,
			Keys:     []crypto.PublicKey{&k1.PublicKey, &k2.PublicKey},
			Evidence: []walletprovider.Evidence{assertion(1, k1), assertion(2, k2)},
		})
		if !errors.Is(err, walletprovider.ErrInvalidRequest) {
			t.Fatalf("KeyAttestation with two assertions = %v, want ErrInvalidRequest", err)
		}
	})
}
