package walletprovider

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest/attesttest"
)

// evidenceFixture is a service with a clock the test moves and a log it
// reads.
type evidenceFixture struct {
	t   *testing.T
	s   *service
	now time.Time

	mu  sync.Mutex
	log []string
}

func newEvidenceFixture(t *testing.T, cfg ServiceConfig) *evidenceFixture {
	t.Helper()
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	f := &evidenceFixture{t: t, now: time.Now()}
	cfg.ClientID = "wallet-1"
	cfg.Now = func() time.Time { return f.now }
	cfg.Logf = func(format string, args ...any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.log = append(f.log, fmt.Sprintf(format, args...))
	}
	if f.s, err = p.newService(cfg); err != nil {
		t.Fatal(err)
	}
	return f
}

// lastLog is the most recent log line.
func (f *evidenceFixture) lastLog() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.log) == 0 {
		return ""
	}
	return f.log[len(f.log)-1]
}

// post calls handler with body as JSON, returning the status and body.
func (f *evidenceFixture) post(handler http.HandlerFunc, body any) (int, string) {
	f.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(data))))
	return w.Code, w.Body.String()
}

// challenge asks the service for a challenge for purpose.
func (f *evidenceFixture) challenge(purpose string) []byte {
	f.t.Helper()
	code, body := f.post(f.s.challenge, ChallengeRequest{Purpose: purpose})
	if code != http.StatusOK {
		f.t.Fatalf("challenge: %d %s", code, body)
	}
	var resp ChallengeResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		f.t.Fatal(err)
	}
	c, err := base64.RawURLEncoding.DecodeString(resp.Challenge)
	if err != nil || len(c) != ChallengeBytes || resp.ExpiresIn != 300 {
		f.t.Fatalf("challenge response %s", body)
	}
	return c
}

// walletAttestation asks for a Wallet Attestation for key with chain.
func (f *evidenceFixture) walletAttestation(key *ecdsa.PublicKey, chain [][]byte) (int, string) {
	f.t.Helper()
	return f.post(f.s.walletAttestation, WalletAttestationRequest{ClientID: "wallet-1", InstanceKey: jwkOf(f.t, key), InstanceKeyCertificateChain: b64(chain)})
}

func jwkOf(t *testing.T, key *ecdsa.PublicKey) json.RawMessage {
	t.Helper()
	raw, err := attestation.AttestedKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func b64(chain [][]byte) []string {
	out := make([]string, len(chain))
	for i, der := range chain {
		out[i] = base64.StdEncoding.EncodeToString(der)
	}
	return out
}

// TestEvidence_Challenges: the challenge endpoint gives distinct
// challenges for the purposes the Kotlin library asks for.
func TestEvidence_Challenges(t *testing.T) {
	f := newEvidenceFixture(t, ServiceConfig{})
	a, b := f.challenge(PurposeInstance), f.challenge(PurposeHolder)
	if string(a) == string(b) {
		t.Error("two challenges are the same")
	}
	for _, purpose := range []string{"", "dpop", "INSTANCE"} {
		if code, _ := f.post(f.s.challenge, ChallengeRequest{Purpose: purpose}); code != http.StatusBadRequest {
			t.Errorf("purpose %q: status %d, want 400", purpose, code)
		}
	}
}

// TestEvidence_VerifiesChains: a chain over an issued challenge, for the
// key sent, is attested once over that challenge; the same key and
// chain again is recognised; anything else is refused.
func TestEvidence_VerifiesChains(t *testing.T) {
	var roots []*x509.Certificate
	f := newEvidenceFixture(t, ServiceConfig{})
	// Each chain has a root of its own: trust them as they're made.
	f.s.ev.roots = nil
	chainFor := func(key *ecdsa.PublicKey, challenge []byte, level androidattest.SecurityLevel) [][]byte {
		c := attesttest.New(t, key, attesttest.Options{Level: level, Challenge: challenge})
		roots = append(roots, c.Root)
		f.s.ev.roots = roots
		return c.DER
	}

	key := &p256(t).PublicKey
	chain := chainFor(key, f.challenge(PurposeInstance), androidattest.TrustedEnvironment)
	if code, body := f.walletAttestation(key, chain); code != http.StatusOK {
		t.Fatalf("a good chain: %d %s", code, body)
	}
	if log := f.lastLog(); !strings.HasPrefix(log, "wallet provider: Wallet Attestation for instance key ") || !strings.Contains(log, "hardware: ") {
		t.Errorf("log %q, want the chain logged as hardware", log)
	}
	// A refresh re-attests the instance key with the same chain.
	if code, body := f.walletAttestation(key, chain); code != http.StatusOK || !strings.Contains(f.lastLog(), "verified before") {
		t.Errorf("the same key and chain again: %d %s, log %q", code, body, f.lastLog())
	}

	// The challenge is used up: another key's chain over it is refused.
	other := &p256(t).PublicKey
	reused := chainFor(other, chainChallenge(t, chain), androidattest.TrustedEnvironment)
	unknown := chainFor(other, []byte("a challenge the provider never issued"), androidattest.TrustedEnvironment)
	holderChallenge := chainFor(other, f.challenge(PurposeHolder), androidattest.TrustedEnvironment)
	forAnotherKey := chainFor(other, f.challenge(PurposeInstance), androidattest.TrustedEnvironment)
	tampered := chainFor(other, f.challenge(PurposeInstance), androidattest.TrustedEnvironment)
	tampered[0][len(tampered[0])-1] ^= 1
	expiring := chainFor(other, f.challenge(PurposeInstance), androidattest.TrustedEnvironment)
	for name, tc := range map[string]struct {
		key   *ecdsa.PublicKey
		chain [][]byte
		later time.Duration
	}{
		"a used challenge":            {other, reused, 0},
		"an unknown challenge":        {other, unknown, 0},
		"a holder key's challenge":    {other, holderChallenge, 0},
		"a chain for another key":     {key, forAnotherKey, 0},
		"a tampered signature":        {other, tampered, 0},
		"an expired challenge":        {other, expiring, ChallengeLifetime},
		"the first key, another leaf": {key, chainFor(key, chainChallenge(t, chain), androidattest.TrustedEnvironment), 0},
	} {
		f.now = f.now.Add(tc.later)
		if code, body := f.walletAttestation(tc.key, tc.chain); code != http.StatusForbidden {
			t.Errorf("%s: %d %s, want 403", name, code, body)
		} else if !strings.Contains(f.lastLog(), "refused") {
			t.Errorf("%s: log %q, want the refusal logged", name, f.lastLog())
		}
		f.now = f.now.Add(-tc.later)
	}

	// A Key Attestation checks each key's chain against a holder
	// challenge.
	k1, k2 := &p256(t).PublicKey, &p256(t).PublicKey
	c1 := chainFor(k1, f.challenge(PurposeHolder), androidattest.StrongBox)
	c2 := chainFor(k2, f.challenge(PurposeHolder), androidattest.TrustedEnvironment)
	req := KeyAttestationRequest{Keys: []json.RawMessage{jwkOf(t, k1), jwkOf(t, k2)}, Nonce: "n", CertificateChains: [][]string{b64(c1), b64(c2)}}
	if code, body := f.post(f.s.keyAttestation, req); code != http.StatusOK {
		t.Errorf("Key Attestation with chains: %d %s", code, body)
	}
	req.CertificateChains = req.CertificateChains[:1]
	if code, _ := f.post(f.s.keyAttestation, req); code != http.StatusBadRequest {
		t.Errorf("one chain for two keys: status %d, want 400", code)
	}
	// An instance key's chain isn't a holder key's.
	req = KeyAttestationRequest{Keys: []json.RawMessage{jwkOf(t, key)}, Nonce: "n", CertificateChains: [][]string{b64(chain)}}
	if code, _ := f.post(f.s.keyAttestation, req); code != http.StatusForbidden {
		t.Errorf("the instance key's chain for a Key Attestation: status %d, want 403", code)
	}
}

// chainChallenge is the challenge chain's leaf was made over.
func chainChallenge(t *testing.T, chain [][]byte) []byte {
	t.Helper()
	a, err := androidattest.Verify(chain[:1], nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a.AttestationChallenge
}

// TestEvidence_HardwarePolicy: a chain that isn't hardware Google
// vouches for is attested and logged, unless hardware is required; a
// key without a chain is attested either way.
func TestEvidence_HardwarePolicy(t *testing.T) {
	for _, require := range []bool{false, true} {
		f := newEvidenceFixture(t, ServiceConfig{RequireHardwareKeyAttestation: require})
		want := http.StatusOK
		if require {
			want = http.StatusForbidden
		}
		key := &p256(t).PublicKey
		// Under a root that isn't Google's.
		unknownRoot := attesttest.New(t, key, attesttest.Options{Level: androidattest.StrongBox, Challenge: f.challenge(PurposeInstance)})
		if code, body := f.walletAttestation(key, unknownRoot.DER); code != want {
			t.Errorf("require %v, unknown root: %d %s, want %d", require, code, body, want)
		}
		if log := f.lastLog(); !strings.Contains(log, "not a Google hardware attestation root") {
			t.Errorf("require %v, unknown root: log %q", require, log)
		}
		// Software, under a trusted root: an emulator's.
		software := attesttest.New(t, key, attesttest.Options{Level: androidattest.Software, Challenge: f.challenge(PurposeInstance)})
		f.s.ev.roots = []*x509.Certificate{software.Root}
		if code, body := f.walletAttestation(key, software.DER); code != want {
			t.Errorf("require %v, software: %d %s, want %d", require, code, body, want)
		}
		if log := f.lastLog(); !strings.Contains(log, "software security level") {
			t.Errorf("require %v, software: log %q", require, log)
		}
		if code, body := f.walletAttestation(key, nil); code != http.StatusOK || !strings.Contains(f.lastLog(), "no key attestation chain") {
			t.Errorf("require %v, no chain: %d %s, log %q", require, code, body, f.lastLog())
		}
	}
}

// TestEvidence_RealGoogleChain: a real device's TEE attestation chain,
// to Google's root (androidattest's testdata, from Google's
// android-key-attestation test resources), is verified as hardware.
func TestEvidence_RealGoogleChain(t *testing.T) {
	data, err := os.ReadFile("../internal/androidattest/testdata/ec_tee_chain.pem")
	if err != nil {
		t.Fatal(err)
	}
	var chain [][]byte
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		chain = append(chain, block.Bytes)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	f := newEvidenceFixture(t, ServiceConfig{RequireHardwareKeyAttestation: true})
	// Its intermediates are valid until 2028; it was made over "abc",
	// which the provider is taken to have issued.
	f.now = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	f.s.ev.outstanding["abc"] = challenge{purpose: PurposeInstance, expires: f.now.Add(time.Minute)}
	if code, body := f.walletAttestation(leaf.PublicKey.(*ecdsa.PublicKey), chain); code != http.StatusOK {
		t.Fatalf("a real Google TEE chain: %d %s", code, body)
	}
	if log := f.lastLog(); !strings.Contains(log, "hardware: Android Key Attestation, attestation TrustedEnvironment, key TrustedEnvironment, Google root") {
		t.Errorf("log %q", log)
	}
}

// TestEvidence_RemembersAcrossRestarts: with VerifiedKeysPath, a key
// verified before a restart is recognised after it.
func TestEvidence_RemembersAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	f := newEvidenceFixture(t, ServiceConfig{VerifiedKeysPath: path})
	key := &p256(t).PublicKey
	c := attesttest.New(t, key, attesttest.Options{Level: androidattest.TrustedEnvironment, Challenge: f.challenge(PurposeInstance)})
	f.s.ev.roots = []*x509.Certificate{c.Root}
	if code, body := f.walletAttestation(key, c.DER); code != http.StatusOK {
		t.Fatalf("first attestation: %d %s", code, body)
	}

	restarted := newEvidenceFixture(t, ServiceConfig{VerifiedKeysPath: path, AttestationRoots: []*x509.Certificate{c.Root}})
	if code, body := restarted.walletAttestation(key, c.DER); code != http.StatusOK || !strings.Contains(restarted.lastLog(), "verified before") {
		t.Errorf("after a restart: %d %s, log %q", code, body, restarted.lastLog())
	}
	without := newEvidenceFixture(t, ServiceConfig{AttestationRoots: []*x509.Certificate{c.Root}})
	if code, _ := without.walletAttestation(key, c.DER); code != http.StatusForbidden {
		t.Errorf("after a restart without the file: status %d, want 403", code)
	}

	if err := os.WriteFile(path, []byte("not JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.NewService(ServiceConfig{ClientID: "wallet-1", VerifiedKeysPath: path}); err == nil {
		t.Error("NewService accepted a corrupt verified keys file")
	}
}

// TestEvidence_BoundsChallenges: outstanding challenges are bounded;
// expired ones make room.
func TestEvidence_BoundsChallenges(t *testing.T) {
	f := newEvidenceFixture(t, ServiceConfig{})
	for i := 0; i < maxOutstandingChallenges; i++ {
		f.s.ev.outstanding[fmt.Sprint(i)] = challenge{purpose: PurposeHolder, expires: f.now.Add(time.Minute)}
	}
	if code, _ := f.post(f.s.challenge, ChallengeRequest{Purpose: PurposeHolder}); code != http.StatusServiceUnavailable {
		t.Errorf("past the bound: status %d, want 503", code)
	}
	f.now = f.now.Add(time.Minute)
	f.challenge(PurposeHolder)
	if n := len(f.s.ev.outstanding); n != 1 {
		t.Errorf("%d challenges outstanding after expiry, want 1", n)
	}
}
