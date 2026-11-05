package cose

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// X5ChainTrust is how X5ChainSigner verifies a token's x5chain.
type X5ChainTrust struct {
	// MaxBytes caps the token's size.
	MaxBytes int

	// ProtectedOnly reads the x5chain from the protected header alone;
	// unset, X5ChainOf's.
	ProtectedOnly bool

	Roots      *x509.CertPool
	Policy     func(*x509.Certificate, [][]*x509.Certificate) error
	Revocation certrevocation.Checker
	Now        time.Time
}

// X5ChainSigner decodes sign1, tagged or untagged, without checking its
// signature, verifies its x5chain to trust.Roots at trust.Now on a path
// trust.Policy approves and trust.Revocation passes
// (certchain.VerifyTrustedChainsAt), and returns the chain's leaf and
// the alg its key signs with. The caller then verifies sign1 with them.
// Its errors start "decode token: " or "token signer: ", for the caller
// to prefix with its package.
func X5ChainSigner(ctx context.Context, sign1 []byte, trust X5ChainTrust) (*x509.Certificate, Alg, error) {
	chain, _, err := trust.Chain(sign1)
	if err != nil {
		return nil, 0, err
	}
	return trust.Signer(ctx, chain)
}

// Chain is sign1's x5chain as X5ChainSigner reads it, unverified, and
// whether it's from the protected header.
func (trust X5ChainTrust) Chain(sign1 []byte) (chain [][]byte, protected bool, err error) {
	p, u, _, err := DecodeUnverifiedMax(sign1, trust.MaxBytes)
	if err != nil {
		return nil, false, fmt.Errorf("decode token: %w", err)
	}
	if trust.ProtectedOnly || len(p.X5Chain) > 0 {
		return p.X5Chain, true, nil
	}
	return u.X5Chain, false, nil
}

// Signer is X5ChainSigner given chain, the x5chain Chain read: for a
// caller that verified a token's signature under that chain's leaf
// before, and checks only its trust again.
func (trust X5ChainTrust) Signer(ctx context.Context, chain [][]byte) (*x509.Certificate, Alg, error) {
	leaf, _, err := certchain.VerifyTrustedChainsAt(ctx, chain, trust.Roots, trust.Policy, trust.Revocation, trust.Now)
	if err != nil {
		return nil, 0, fmt.Errorf("token signer: %w", err)
	}
	alg, err := AlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, 0, fmt.Errorf("token signer: %w", err)
	}
	return leaf, alg, nil
}
