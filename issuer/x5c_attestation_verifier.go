package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// X5CAttestationVerifier implements AttestationVerifier by validating
// a presented Key Attestation JWT's own "x5c" header (RFC 7515
// §4.1.6) against Roots — a reference implementation of the one
// concrete trust strategy this package's own doc comments describe
// ("an x5c chain's own trust anchor"), the issuer-side analog of
// verifier.X5CIssuerKeyResolver/X5ChainIssuerKeyResolver. A self-signed
// leaf is always rejected, even if that exact certificate is itself a
// configured root — see internal/certchain.VerifyLeaf's own doc
// comment for why. A caller whose Key Attestation trust model is DID
// resolution, a private key registry, or OpenID Federation's own
// "trust_chain" (KeyAttestation.TrustChain) needs its own
// AttestationVerifier implementation instead — see that interface's
// own doc comment.
type X5CAttestationVerifier struct {
	// Roots is the trust anchor set a presented x5c chain must
	// validate against. REQUIRED.
	Roots *x509.CertPool
}

// ResolveAttestationKey implements AttestationVerifier.
func (v X5CAttestationVerifier) ResolveAttestationKey(_ context.Context, a attestation.KeyAttestation) (crypto.PublicKey, jose.Alg, error) {
	x5c := a.X5C()
	entries := make([]any, len(x5c))
	for i, s := range x5c {
		entries[i] = s
	}
	leaf, err := resolveX5CLeaf(entries, v.Roots)
	if err != nil {
		return nil, "", err
	}
	alg, err := algForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// algForKey maps pub to the JOSE algorithm this package's own signers
// use for it — the same ES256/EdDSA-only mapping
// verifier.sdjwtvcAlgForKey establishes on the verifying side, kept as
// its own small copy here rather than a cross-package export: it's a
// trivial, self-contained switch, not the security-relevant logic
// internal/certchain centralizes.
func algForKey(pub crypto.PublicKey) (jose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return jose.ES256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("issuer: unsupported public key type %T", pub)
	}
}
