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
	protected, unprotected, _, err := DecodeUnverifiedMax(sign1, trust.MaxBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("decode token: %w", err)
	}
	chain := X5ChainOf(protected, unprotected)
	if trust.ProtectedOnly {
		chain = protected.X5Chain
	}
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
