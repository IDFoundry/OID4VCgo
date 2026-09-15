package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcigo/internal/dpop"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// fakeReplayChecker is an in-memory dpop.ReplayChecker for tests.
type fakeReplayChecker struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newFakeReplayChecker() *fakeReplayChecker { return &fakeReplayChecker{seen: map[string]bool{}} }

func (f *fakeReplayChecker) UseOnce(_ context.Context, jti string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[jti] {
		return fakeErr("jti already used")
	}
	f.seen[jti] = true
	return nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// testWallet builds a real *wallet.Wallet whose only job in these
// tests is producing real DPoP proofs via GenerateDPoPProof — the
// exported primitive whose own doc comment names exactly this reuse
// case.
func testWallet(t *testing.T, now time.Time) *wallet.Wallet {
	t.Helper()
	w, err := wallet.New(wallet.Config{
		ProofSigningAlg: jose.ES256,
		Fetch:           fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second},
	}, wallet.Dependencies{
		HTTP:   http.DefaultClient,
		Clock:  wallet.ClockFunc(func() time.Time { return now }),
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}
	return w
}

// TestVerifyAcceptsWalletGeneratedProof is the real round trip: a
// genuine DPoP proof from wallet.GenerateDPoPProof, verified by this
// package's own Verify — proving the two independently-built halves
// (client-side generation, server-side verification) agree on the wire
// format, the same discipline every other cross-package claim in this
// repo is held to.
func TestVerifyAcceptsWalletGeneratedProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	key := testP256Key(t)

	proof, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	verified, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.IssuedAt.Unix() != now.Unix() {
		t.Errorf("IssuedAt = %v, want %v", verified.IssuedAt, now)
	}
	wantThumbprint, err := func() (string, error) {
		wireJWK, err := jwk.Marshal(&key.PublicKey)
		if err != nil {
			return "", err
		}
		return wireJWK.Thumbprint()
	}()
	if err != nil {
		t.Fatalf("compute expected thumbprint: %v", err)
	}
	if verified.Thumbprint != wantThumbprint {
		t.Errorf("Thumbprint = %q, want %q", verified.Thumbprint, wantThumbprint)
	}
}

func TestVerifyAcceptsMatchingNonce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	key := testP256Key(t)

	proof, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example.com/token", "server-nonce", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	verified, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, RequiredNonce: "server-nonce", Replay: newFakeReplayChecker(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Nonce != "server-nonce" {
		t.Errorf("Nonce = %q, want server-nonce", verified.Nonce)
	}
}

func TestVerifyIgnoresQueryAndFragmentInURL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	key := testP256Key(t)

	// GenerateDPoPProof signs whatever htu it's given verbatim — the
	// caller (wallet.RequestPreAuthorizedCodeToken) is the one that
	// strips query/fragment before calling it. This test signs a htu
	// that already carries a query/fragment to confirm Verify itself
	// also ignores them (RFC 9449 §4.3), not just that a well-behaved
	// caller never sends one.
	proof, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example.com/token?a=b#frag", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsMethodMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "GET", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyRejectsURLMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/other",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyRejectsExpiredProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now.Add(2 * time.Minute), MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyRejectsFutureIAT(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now.Add(-time.Hour), MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyAllowsClockSkew(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now.Add(-10 * time.Second), MaxProofAge: time.Minute, MaxClockSkew: 30 * time.Second,
		Replay: newFakeReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsNonceMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "wrong-nonce", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, RequiredNonce: "expected-nonce", Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyRejectsMissingNonceWhenRequired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, RequiredNonce: "expected-nonce", Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyRejectsReplayedJTI(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	replay := newFakeReplayChecker()
	req := dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: replay,
	}
	if _, err := dpop.Verify(context.Background(), req); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), req); err == nil {
		t.Fatalf("second Verify (same jti) = nil error, want error")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	tampered := tamperLastChar(proof)
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: tampered, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

// tamperLastChar flips the second-to-last character of proof's own
// signature segment — not the very last one, since a fixed-width R||S
// signature's final base64url character can carry unused padding bits
// that legally decode to the same bytes (see internal/jose's own
// TestVerifyRejectsTampering for the same finding).
func tamperLastChar(proof string) string {
	r := []rune(proof)
	idx := len(r) - 2
	if r[idx] == 'x' {
		r[idx] = 'y'
	} else {
		r[idx] = 'x'
	}
	return string(r)
}

func TestVerifyRejectsWrongTyp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	// Sign a proof-shaped JWT directly with the wrong typ, bypassing
	// wallet.GenerateDPoPProof (which always sets it correctly) to
	// exercise this rejection path.
	proof, err := jose.Sign(jose.ES256, key, map[string]any{
		"typ": "wrong+jwt",
		"jwk": mustJWK(t, key),
	}, []byte(`{"jti":"j1","htm":"POST","htu":"https://issuer.example.com/token","iat":1700000000}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyRejectsMissingJWKHeader(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dpop+jwt"},
		[]byte(`{"jti":"j1","htm":"POST","htu":"https://issuer.example.com/token","iat":1700000000}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func TestVerifyRejectsMissingJTI(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dpop+jwt", "jwk": mustJWK(t, key)},
		[]byte(`{"htm":"POST","htu":"https://issuer.example.com/token","iat":1700000000}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Fatalf("Verify = nil error, want error")
	}
}

func mustJWK(t *testing.T, key *ecdsa.PrivateKey) jwk.JWK {
	t.Helper()
	k, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	return k
}

func TestVerifyRequiresReplayChecker(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: "https://issuer.example.com/token",
		Now: now, MaxProofAge: time.Minute,
	}); err == nil {
		t.Fatalf("Verify = nil error, want error (replay is required)")
	}
}
