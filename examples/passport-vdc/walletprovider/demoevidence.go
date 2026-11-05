package walletprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"slices"
	"sync"

	wp "github.com/idfoundry/oid4vcgo/walletprovider"
)

// DEMO ONLY. The demo's wallets speak this package's own stateless
// protocol (WalletAttestationPath, KeyAttestationPath), which names no
// wallet instance and carries no platform evidence from iOS, the CLI
// or the web wallet. The library's Provider attests nothing without
// evidence, so the service vouches for those requests itself, as
// evidence of DemoEvidenceKind: a single-use token it mints for a
// request it has already checked (an Android chain verified by
// evidence.check, or no chain at all), naming the challenge and the
// keys. A real Wallet Provider has no such kind: it verifies platform
// evidence the wallet sends, as androidkey.EvidenceVerifier does.
const (
	// DemoEvidenceKind is the demo-only evidence's Kind.
	DemoEvidenceKind = "passport-vdc-demo-only"

	// DemoPlatform is the platform demo-only evidence reports: not
	// Android or iOS, since the library's Policy for those platforms
	// is never applied to it.
	DemoPlatform wp.Platform = "passport-vdc-demo-only"
)

// demoKey is a key the service vouches for, at the security level its
// check found (software for a key sent without a chain).
type demoKey struct {
	key   crypto.PublicKey
	level wp.SecurityLevel
}

// demoClaim is what a token vouches for.
type demoClaim struct {
	challenge []byte
	keys      []demoKey
}

// demoVerifier is the EvidenceVerifier for DemoEvidenceKind. Its
// tokens are 32 random bytes held only in memory, used once, and only
// ever minted by the service for a request it is answering, so no
// caller of the library's own Handler can present one.
type demoVerifier struct {
	mu      sync.Mutex
	pending map[string]demoClaim
}

var _ wp.EvidenceVerifier = (*demoVerifier)(nil)

func newDemoVerifier() *demoVerifier { return &demoVerifier{pending: map[string]demoClaim{}} }

// vouch mints evidence over challenge (a library Challenge's raw bytes)
// for keys; forget it once the request is answered.
func (d *demoVerifier) vouch(challenge []byte, keys ...demoKey) (wp.Evidence, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return wp.Evidence{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending[string(token)] = demoClaim{challenge: slices.Clone(challenge), keys: keys}
	return wp.Evidence{Kind: DemoEvidenceKind, Data: token}, nil
}

// forget drops ev's token if it wasn't used.
func (d *demoVerifier) forget(ev wp.Evidence) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.pending, string(ev.Data))
}

// Kind implements wp.EvidenceVerifier.
func (*demoVerifier) Kind() string { return DemoEvidenceKind }

// Verify implements wp.EvidenceVerifier: the token must be one the
// service minted, unused, over in.Challenge; it vouches for the keys
// it names that in.Keys holds.
func (d *demoVerifier) Verify(_ context.Context, in wp.EvidenceInput) (wp.VerifiedEvidence, error) {
	d.mu.Lock()
	claim, ok := d.pending[string(in.Evidence.Data)]
	delete(d.pending, string(in.Evidence.Data))
	d.mu.Unlock()
	if !ok {
		return wp.VerifiedEvidence{}, errors.New("not a token this demo service minted, or already used")
	}
	if subtle.ConstantTimeCompare(claim.challenge, in.Challenge) != 1 {
		return wp.VerifiedEvidence{}, errors.New("the token is for another challenge")
	}
	out := wp.VerifiedEvidence{Platform: DemoPlatform}
	for _, k := range claim.keys {
		if slices.ContainsFunc(in.Keys, func(want crypto.PublicKey) bool { return samePublicKey(want, k.key) }) {
			// Nothing attested the key itself to the library: the demo
			// service vouches for it, much as an app would.
			out.Keys = append(out.Keys, wp.AttestedKey{Key: k.key, SecurityLevel: k.level, Binding: wp.KeyBindingAppAssertion})
		}
	}
	return out, nil
}

// samePublicKey reports whether a and b are the same public key.
func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}
