package walletprovider_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

const (
	identifier = "https://provider.example"
	statusBase = "https://provider.example/status"
	clientID   = "wallet-client"
	walletName = "Example Wallet"
	walletLink = "https://wallet.example"

	androidApp = "com.example.wallet"
	iosApp     = "TEAMID.com.example.wallet"
)

// The evidence kinds the harness's fake verifiers read.
const (
	kindFake             = walletprovidertest.FakeKind
	kindStrongBox        = "android-strongbox"
	kindTEE              = "android-tee"
	kindOldApp           = "android-old-app"
	kindRooted           = "android-unverified-boot"
	kindUnlocked         = "android-unlocked"
	kindLockedUnverified = "android-locked-unverified"
	kindSoftware         = "android-software"
	kindIOS              = "ios-app-attest"
	kindOtherApp         = "android-other-app"
)

func androidResult(version uint64) walletprovider.VerifiedEvidence {
	return walletprovider.VerifiedEvidence{
		Platform: walletprovider.PlatformAndroid, AppID: androidApp, AppVersion: version,
		BootState: walletprovider.BootStateVerified, DeviceLocked: true,
	}
}

// verifiers are fakes standing in for each platform's evidence.
func verifiers() []walletprovider.EvidenceVerifier {
	other := androidResult(10)
	other.AppID = "com.example.other"
	rooted := androidResult(10)
	rooted.BootState, rooted.DeviceLocked = walletprovider.BootStateUnverified, false
	unlocked := androidResult(10)
	unlocked.DeviceLocked = false
	unverifiedLocked := androidResult(10)
	unverifiedLocked.BootState = walletprovider.BootStateUnverified
	return []walletprovider.EvidenceVerifier{
		walletprovidertest.FakeVerifier{},
		androidVerifier{
			kindStrongBox: {Result: androidResult(10),
				SecurityLevel: walletprovider.SecurityLevelStrongBox, UserAuthentication: walletprovider.UserAuthenticationRequired},
			kindTEE: {Result: androidResult(10),
				SecurityLevel: walletprovider.SecurityLevelTEE, UserAuthentication: walletprovider.UserAuthenticationNone},
			kindOldApp:           {Result: androidResult(3), SecurityLevel: walletprovider.SecurityLevelTEE},
			kindRooted:           {Result: rooted, SecurityLevel: walletprovider.SecurityLevelTEE},
			kindUnlocked:         {Result: unlocked, SecurityLevel: walletprovider.SecurityLevelTEE},
			kindLockedUnverified: {Result: unverifiedLocked, SecurityLevel: walletprovider.SecurityLevelTEE},
			kindSoftware:         {Result: androidResult(10)},
			kindOtherApp:         {Result: other, SecurityLevel: walletprovider.SecurityLevelTEE},
		},
		iosVerifier(),
	}
}

func iosVerifier() walletprovidertest.FakeVerifier {
	return walletprovidertest.FakeVerifier{KindName: kindIOS,
		Result:        walletprovider.VerifiedEvidence{Platform: walletprovider.PlatformIOS, AppID: iosApp},
		SecurityLevel: walletprovider.SecurityLevelSecureEnclave, Binding: walletprovider.KeyBindingAppAssertion}
}

// kindAndroid is the one Kind of the harness's Android evidence, as a
// real Android Key Attestation verifier has one: an instance's later
// evidence must be of the Kind it registered with. The android-*
// kinds above name which fake stands in for a device's evidence.
const kindAndroid = "android"

// androidVerifier verifies kindAndroid evidence with the fake its
// evidence names (androidEvidence).
type androidVerifier map[string]walletprovidertest.FakeVerifier

// androidEvidence is kindAndroid evidence's Data: As names the fake
// that verifies Data.
type androidEvidence struct {
	As   string          `json:"as"`
	Data json.RawMessage `json:"data"`
}

func (androidVerifier) Kind() string { return kindAndroid }

func (v androidVerifier) Verify(ctx context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	var ev androidEvidence
	if err := json.Unmarshal(in.Evidence.Data, &ev); err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	fake, ok := v[ev.As]
	if !ok {
		return walletprovider.VerifiedEvidence{}, fmt.Errorf("no %q fake", ev.As)
	}
	in.Evidence = walletprovider.Evidence{Kind: ev.As, Data: ev.Data}
	return fake.Verify(ctx, in)
}

func policy() walletprovider.Policy {
	return walletprovider.Policy{
		Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{
			walletprovidertest.FakePlatform: {SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelSoftware}},
			walletprovider.PlatformAndroid: {
				SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelTEE, walletprovider.SecurityLevelStrongBox},
				MinAppVersion:  5, RequireVerifiedBoot: true,
			},
			walletprovider.PlatformIOS: {SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelSecureEnclave}},
		},
		KeyStorage: []walletprovider.KeyStorageRule{
			{
				Platform: walletprovider.PlatformAndroid, SecurityLevel: walletprovider.SecurityLevelStrongBox,
				UserAuthentication:       walletprovider.UserAuthenticationRequired,
				KeyStorage:               []attestation.AttackPotentialResistance{attestation.ISO18045High, attestation.ISO18045Moderate},
				UserAuthenticationLevels: []attestation.AttackPotentialResistance{attestation.ISO18045High},
			},
			{
				Platform: walletprovider.PlatformAndroid, SecurityLevel: walletprovider.SecurityLevelTEE,
				KeyStorage: []attestation.AttackPotentialResistance{attestation.ISO18045Moderate},
			},
		},
	}
}

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harness struct {
	t      *testing.T
	p      *walletprovider.Provider
	clock  *clock
	signer *ecdsa.PrivateKey
	chain  []*x509.Certificate
	cfg    walletprovider.Config
	deps   walletprovider.Dependencies
}

// signerChain is a Wallet Provider signing key and its certificate,
// naming identifier, under a fresh CA (left out of the chain).
func signerChain(t *testing.T) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	ca, caKey := testcert.CA(t, "Wallet Provider CA")
	id, err := url.Parse(identifier)
	if err != nil {
		t.Fatal(err)
	}
	leaf, key := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Wallet Provider"}, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{id},
	}, ca, caKey)
	return key, []*x509.Certificate{leaf}
}

func baseConfig() walletprovider.Config {
	return walletprovider.Config{
		Identifier: identifier, ClientIDs: []string{clientID}, WalletName: walletName, WalletLink: walletLink,
		StatusListBaseURI: statusBase, StatusListSize: 1024, Policy: policy(),
	}
}

func baseDeps(t *testing.T, c *clock) walletprovider.Dependencies {
	key, chain := signerChain(t)
	return walletprovider.Dependencies{
		Signer: key, Chain: chain,
		Instances: &walletprovider.MemoryInstanceStore{}, InstanceKeys: &walletprovider.MemoryInstanceKeyStore{},
		Challenges:    &walletprovider.MemoryChallengeStore{},
		StatusIndices: &statuslist.MemoryIndexStore{}, Evidence: verifiers(),
		Clock: c.now, Random: rand.Reader,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// newHarness builds a provider, mutate changing its configuration
// first.
func newHarness(t *testing.T, mutate func(*walletprovider.Config, *walletprovider.Dependencies)) *harness {
	t.Helper()
	c := &clock{t: time.Now()}
	cfg, deps := baseConfig(), baseDeps(t, c)
	if mutate != nil {
		mutate(&cfg, &deps)
	}
	p, err := walletprovider.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := &harness{t: t, p: p, clock: c, signer: deps.Signer.(*ecdsa.PrivateKey), chain: deps.Chain, cfg: cfg, deps: deps}
	// Near the end of a status list period, start in the next one, so a
	// test that expects to stay within a period doesn't cross into the
	// next one.
	if end := time.Unix(h.periodStart(), 0).Add(h.period()); end.Sub(c.now()) < 10*time.Minute {
		c.advance(end.Add(time.Minute).Sub(c.now()))
	}
	return h
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (h *harness) challenge(purpose walletprovider.Purpose) string {
	h.t.Helper()
	c, err := h.p.Challenge(context.Background(), purpose)
	if err != nil {
		h.t.Fatalf("Challenge(%s): %v", purpose, err)
	}
	return c.Value
}

// evidence is fake evidence of kind over challenge for keys: for one of
// the android-* kinds, kindAndroid evidence verified as that kind.
func evidence(t *testing.T, kind, challenge string, keys ...crypto.PublicKey) walletprovider.Evidence {
	t.Helper()
	ev, err := walletprovidertest.FakeEvidence(kind, challenge, keys...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kind, kindAndroid+"-") {
		return ev
	}
	data, err := json.Marshal(androidEvidence{As: kind, Data: ev.Data})
	if err != nil {
		t.Fatal(err)
	}
	return walletprovider.Evidence{Kind: kindAndroid, Data: data}
}

// tryRegister registers an instance with evidence of kind, returning it
// with its registration key.
func (h *harness) tryRegister(kind string) (walletprovider.Instance, *ecdsa.PrivateKey, error) {
	h.t.Helper()
	key := newKey(h.t)
	ch := h.challenge(walletprovider.PurposeRegistration)
	in, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &key.PublicKey, Evidence: evidence(h.t, kind, ch, &key.PublicKey),
	})
	return in, key, err
}

func (h *harness) register(kind string) (walletprovider.Instance, *ecdsa.PrivateKey) {
	h.t.Helper()
	in, key, err := h.tryRegister(kind)
	if err != nil {
		h.t.Fatalf("Register(%s): %v", kind, err)
	}
	return in, key
}

// walletAttestation asks for a Wallet Attestation for the instance key
// key of the instance id, with evidence of kind over a fresh instance
// challenge unless kind is empty.
func (h *harness) walletAttestation(id string, key crypto.PublicKey, kind string) (string, error) {
	h.t.Helper()
	req := walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID, InstanceKey: key}
	if kind != "" {
		req.Challenge = h.challenge(walletprovider.PurposeInstance)
		req.Evidence = evidence(h.t, kind, req.Challenge, key)
	}
	return h.p.WalletAttestation(context.Background(), req)
}

// newInstanceKey makes an instance key for the instance id and has its
// first Wallet Attestation record it, with evidence of kind.
func (h *harness) newInstanceKey(id, kind string) *ecdsa.PrivateKey {
	h.t.Helper()
	key := newKey(h.t)
	if _, err := h.walletAttestation(id, &key.PublicKey, kind); err != nil {
		h.t.Fatalf("recording an instance key with %s evidence: %v", kind, err)
	}
	return key
}

// instanceKey reads the record of the instance key key.
func (h *harness) instanceKey(key crypto.PublicKey) walletprovider.InstanceKey {
	h.t.Helper()
	ik, err := h.deps.InstanceKeys.Get(context.Background(), h.thumbprint(key))
	if err != nil {
		h.t.Fatalf("reading the instance key: %v", err)
	}
	return ik
}

// thumbprint is key's JWK thumbprint, base64url.
func (h *harness) thumbprint(key crypto.PublicKey) string {
	h.t.Helper()
	tp, err := jwk.Thumbprint(key)
	if err != nil {
		h.t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// keyAttestation asks for a Key Attestation over keys, for the
// issuance of instanceKey, each with evidence of the kind at the same
// index of kinds.
func (h *harness) keyAttestation(id string, instanceKey crypto.PublicKey, keys []*ecdsa.PrivateKey, kinds ...string) (walletprovider.KeyAttestationResult, error) {
	h.t.Helper()
	ch := h.challenge(walletprovider.PurposeHolder)
	req := walletprovider.KeyAttestationRequest{InstanceID: id, InstanceKey: instanceKey, Challenge: ch, Nonce: "c-nonce"}
	for i, k := range keys {
		req.Keys = append(req.Keys, &k.PublicKey)
		if i < len(kinds) {
			req.Evidence = append(req.Evidence, evidence(h.t, kinds[i], ch, &k.PublicKey))
		}
	}
	return h.p.KeyAttestation(context.Background(), req)
}

// status reads the status at ref from the provider's published list,
// in the JWT form or the CWT one.
func (h *harness) status(ref statuslist.StatusListRef, cwt bool) statuslist.StatusType {
	h.t.Helper()
	accept := statuslist.TokenMediaType
	if cwt {
		accept = statuslist.CWTTokenMediaType
	}
	code, token := h.getStatusList(strings.TrimPrefix(ref.URI, statusBase), accept)
	if code != http.StatusOK {
		h.t.Fatalf("GET %s: %d %s", ref.URI, code, token)
	}
	opts := statuslist.VerifyOptions{Now: h.clock.now}
	var status statuslist.StatusType
	var err error
	if cwt {
		status, _, err = statuslist.CheckCWT(token, &h.signer.PublicKey, oid4vci.COSEES256, ref, opts)
	} else {
		status, _, err = statuslist.Check(string(token), &h.signer.PublicKey, oid4vci.ES256, ref, opts)
	}
	if err != nil {
		h.t.Fatalf("checking the published status list (cwt %t): %v", cwt, err)
	}
	return status
}

// getStatusList asks StatusLists for path, relative to the base URI,
// with accept as its Accept header.
func (h *harness) getStatusList(path, accept string) (int, []byte) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", accept)
	rec := httptest.NewRecorder()
	h.p.StatusLists().ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// period is the provider's StatusListPeriod.
func (h *harness) period() time.Duration {
	if h.cfg.StatusListPeriod == 0 {
		return walletprovider.DefaultStatusListPeriod
	}
	return h.cfg.StatusListPeriod
}

// periodStart is the start of the period of the harness's clock, in
// seconds since the Unix epoch.
func (h *harness) periodStart() int64 {
	period, now := int64(h.period()/time.Second), h.clock.now().Unix()
	return now - now%period
}

// toNextPeriod advances the clock to a minute into the next period.
func (h *harness) toNextPeriod() {
	h.clock.advance(time.Unix(h.periodStart(), 0).Add(h.period() + time.Minute).Sub(h.clock.now()))
}

// listURI is the uri of list n of the period starting at start.
func listURI(start int64, n int) string {
	return statusBase + "/" + strconv.FormatInt(start, 10) + "/" + strconv.Itoa(n)
}
