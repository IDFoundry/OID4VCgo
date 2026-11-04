package walletprovider_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"sync"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

const (
	identifier = "https://provider.example"
	statusURI  = "https://provider.example/status"
	clientID   = "wallet-client"
	walletName = "Example Wallet"
	walletLink = "https://wallet.example"

	androidApp = "com.example.wallet"
	iosApp     = "TEAMID.com.example.wallet"
)

// The evidence kinds the harness's fake verifiers read.
const (
	kindFake      = walletprovidertest.FakeKind
	kindStrongBox = "android-strongbox"
	kindTEE       = "android-tee"
	kindOldApp    = "android-old-app"
	kindRooted    = "android-unverified-boot"
	kindSoftware  = "android-software"
	kindIOS       = "ios-app-attest"
	kindOtherApp  = "android-other-app"
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
	return []walletprovider.EvidenceVerifier{
		walletprovidertest.FakeVerifier{},
		walletprovidertest.FakeVerifier{KindName: kindStrongBox, Result: androidResult(10),
			SecurityLevel: walletprovider.SecurityLevelStrongBox, UserAuthentication: walletprovider.UserAuthenticationRequired},
		walletprovidertest.FakeVerifier{KindName: kindTEE, Result: androidResult(10),
			SecurityLevel: walletprovider.SecurityLevelTEE, UserAuthentication: walletprovider.UserAuthenticationNone},
		walletprovidertest.FakeVerifier{KindName: kindOldApp, Result: androidResult(3), SecurityLevel: walletprovider.SecurityLevelTEE},
		walletprovidertest.FakeVerifier{KindName: kindRooted, Result: rooted, SecurityLevel: walletprovider.SecurityLevelTEE},
		walletprovidertest.FakeVerifier{KindName: kindSoftware, Result: androidResult(10)},
		walletprovidertest.FakeVerifier{KindName: kindOtherApp, Result: other, SecurityLevel: walletprovider.SecurityLevelTEE},
		walletprovidertest.FakeVerifier{KindName: kindIOS,
			Result:        walletprovider.VerifiedEvidence{Platform: walletprovider.PlatformIOS, AppID: iosApp},
			SecurityLevel: walletprovider.SecurityLevelSecureEnclave, Binding: walletprovider.KeyBindingAppAssertion},
	}
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
		StatusListURI: statusURI, StatusListSize: 1024, Policy: policy(),
	}
}

func baseDeps(t *testing.T, c *clock) walletprovider.Dependencies {
	key, chain := signerChain(t)
	return walletprovider.Dependencies{
		Signer: key, Chain: chain,
		Instances: &walletprovider.MemoryInstanceStore{}, Challenges: &walletprovider.MemoryChallengeStore{},
		StatusIndices: &statuslist.MemoryIndexStore{}, Evidence: verifiers(),
		Clock: c.now, Random: rand.Reader,
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
	return &harness{t: t, p: p, clock: c, signer: deps.Signer.(*ecdsa.PrivateKey), chain: deps.Chain, cfg: cfg, deps: deps}
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

func evidence(t *testing.T, kind, challenge string, keys ...crypto.PublicKey) walletprovider.Evidence {
	t.Helper()
	ev, err := walletprovidertest.FakeEvidence(kind, challenge, keys...)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// tryRegister registers an instance with evidence of kind.
func (h *harness) tryRegister(kind string) (walletprovider.Instance, *ecdsa.PrivateKey, error) {
	h.t.Helper()
	key := newKey(h.t)
	ch := h.challenge(walletprovider.PurposeInstance)
	in, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{
		Challenge: ch, InstanceKey: &key.PublicKey, Evidence: evidence(h.t, kind, ch, &key.PublicKey),
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

func (h *harness) walletAttestation(id string) (string, error) {
	return h.p.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID})
}

// keyAttestation asks for a Key Attestation over keys, each with
// evidence of the kind at the same index of kinds.
func (h *harness) keyAttestation(id string, keys []*ecdsa.PrivateKey, kinds ...string) (walletprovider.KeyAttestationResult, error) {
	h.t.Helper()
	ch := h.challenge(walletprovider.PurposeHolder)
	req := walletprovider.KeyAttestationRequest{InstanceID: id, Challenge: ch, Nonce: "c-nonce"}
	for i, k := range keys {
		req.Keys = append(req.Keys, &k.PublicKey)
		if i < len(kinds) {
			req.Evidence = append(req.Evidence, evidence(h.t, kinds[i], ch, &k.PublicKey))
		}
	}
	return h.p.KeyAttestation(context.Background(), req)
}

// status reads the instance's status from the provider's published
// list, in the JWT form or the CWT one.
func (h *harness) status(ref statuslist.StatusListRef, cwt bool) statuslist.StatusType {
	h.t.Helper()
	token, err := h.p.StatusList().Token(context.Background(), cwt)
	if err != nil {
		h.t.Fatalf("StatusList().Token: %v", err)
	}
	opts := statuslist.VerifyOptions{Now: h.clock.now}
	var status statuslist.StatusType
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
