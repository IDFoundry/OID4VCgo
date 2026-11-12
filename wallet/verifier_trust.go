package wallet

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// VerifierTrust decides whether this Wallet trusts the certificate a
// Verifier signed its Request Object with. OID4VP §5.9.3 (x509_hash):
// "The Wallet MUST validate the signature and the trust chain of the
// X.509 leaf certificate" — ParseAuthorizationRequest checks the
// signature and the x509_hash itself, and delegates the trust chain to
// this policy.
//
// Deciding which Verifiers to trust is the Wallet's own policy (HAIP
// 1.0 leaves X.509 certificate profiles and trust anchors to the
// ecosystem); X5CVerifierRoots covers the common case of a fixed set
// of trust anchors.
type VerifierTrust interface {
	// VerifyVerifierChain validates chain — the Request Object's "x5c"
	// header as DER certificates, leaf first, then any intermediates —
	// and returns the trusted leaf.
	VerifyVerifierChain(chain [][]byte) (*x509.Certificate, error)
}

// X5CVerifierRoots trusts a Verifier whose x5c chain verifies against
// Roots with a leaf that isn't self-signed — HAIP 1.0 §5: "The X.509
// certificate of the trust anchor MUST NOT be included in the x5c JOSE
// header of the signed request. The X.509 certificate signing the
// request MUST NOT be self-signed." A chain that includes the trust
// anchor it verifies to is refused. The leaf must also be an end-entity
// certificate (not a CA), and when it has a key usage extension, one
// that allows digitalSignature.
//
// With x509_hash, nothing ties a Request Object's response_uri to a
// name in the certificate: every certificate that chains to Roots, for
// any purpose, is a Verifier this Wallet trusts. Roots must therefore
// anchor only Verifier certificates — never x509.SystemCertPool(), or
// an ecosystem CA that also issues issuer or wallet provider
// certificates, unless LeafPolicy tells them apart. With
// Config.AcceptX509SANDNS, every dNSName in those certificates is also
// a Verifier name the Wallet will send presentations to, under the
// same rule.
type X5CVerifierRoots struct {
	// Roots is the trust anchor set a Verifier's chain must verify
	// against. REQUIRED.
	Roots *x509.CertPool

	// LeafPolicy, if set, is run on the chain-verified leaf and its
	// verified paths, and can refuse it: require what distinguishes a
	// Verifier's certificate (an extended key usage, a certificate
	// policy) where Roots also anchor other roles.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// Revocation checks the Verifier's certificate chain for
	// revocation: only a verified path that passes LeafPolicy and
	// Revocation is accepted, and a revoked certificate is refused with
	// an error wrapping certrevocation.ErrRevoked. VerifierTrust's
	// method takes no context, so a certrevocation.CRLs's Lists gets
	// context.Background(): keep the lists in memory, as CRLs asks. As
	// a Config.VerifierTrust under AssuranceProduction (and walletflow
	// outside Development), New requires it: certrevocation.NoCheck{}
	// declines. Otherwise nil checks no revocation; see certrevocation.
	Revocation certrevocation.Checker
}

// VerifyVerifierChain implements VerifierTrust.
func (v X5CVerifierRoots) VerifyVerifierChain(chain [][]byte) (*x509.Certificate, error) {
	if v.Roots == nil {
		return nil, fmt.Errorf("wallet: X5CVerifierRoots.Roots is required")
	}
	if err := certchain.CheckNoAnchor(chain); err != nil {
		return nil, fmt.Errorf("wallet: verifier certificate chain: %w", err)
	}
	leaf, _, err := certchain.VerifyTrustedChainsAt(context.Background(), chain, v.Roots, func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		if err := verifierLeafProfile(leaf); err != nil {
			return err
		}
		if err := anchorNotIncluded(chain, chains); err != nil {
			return err
		}
		if v.LeafPolicy != nil {
			return v.LeafPolicy(leaf, chains)
		}
		return nil
	}, v.Revocation, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("wallet: verifier certificate: %w", err)
	}
	return leaf, nil
}

// validateVerifierTrust refuses an X5CVerifierRoots, by value or by
// pointer, whose Revocation reports itself incomplete
// (certrevocation.CRLs.Validate), so New refuses it rather than every
// request afterwards, and under AssuranceProduction one with no
// Revocation, which must be an explicit choice there.
func validateVerifierTrust(assurance AssuranceLevel, t VerifierTrust) error {
	var revocation certrevocation.Checker
	isX5C := false
	switch v := t.(type) {
	case X5CVerifierRoots:
		revocation, isX5C = v.Revocation, true
	case *X5CVerifierRoots:
		if v != nil {
			revocation, isX5C = v.Revocation, true
		}
	}
	if isX5C && revocation == nil && assurance == AssuranceProduction {
		return fmt.Errorf("wallet: config: verifier_trust: X5CVerifierRoots.Revocation is required under AssuranceProduction: %s", certchain.RevocationChoices)
	}
	if err := certchain.ValidateRevocation(revocation); err != nil {
		return fmt.Errorf("wallet: config: verifier_trust: Revocation: %w", err)
	}
	return nil
}

// verifierLeafProfile refuses a leaf that can't be a Verifier's
// request-signing certificate: a CA certificate, or one whose key usage
// doesn't allow signing.
func verifierLeafProfile(leaf *x509.Certificate) error {
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return fmt.Errorf("the leaf is a CA certificate")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("the leaf's key usage doesn't allow digitalSignature")
	}
	return nil
}

// anchorNotIncluded refuses a presented chain that includes the trust
// anchor any of its verified paths ends at (HAIP 1.0 §5).
func anchorNotIncluded(presented [][]byte, chains [][]*x509.Certificate) error {
	for _, path := range chains {
		anchor := path[len(path)-1]
		for _, der := range presented {
			if bytes.Equal(der, anchor.Raw) {
				return fmt.Errorf("the x5c chain includes its trust anchor")
			}
		}
	}
	return nil
}

// NoVerifierTrust accepts any Verifier certificate, skipping OID4VP
// §5.9.3's trust chain validation: the Wallet then learns only that
// the request is signed by the key its x509_hash client identifier
// names, not who that is. It exists as a visible, explicit opt-out for
// tests and conformance runs, never as a default — New rejects it
// under AssuranceProduction.
type NoVerifierTrust struct{}

// VerifyVerifierChain implements VerifierTrust: it parses the leaf and
// checks nothing else.
func (NoVerifierTrust) VerifyVerifierChain(chain [][]byte) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("wallet: verifier certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("wallet: parse verifier certificate: %w", err)
	}
	return leaf, nil
}

// isNoVerifierTrust reports whether t is the NoVerifierTrust opt-out.
func isNoVerifierTrust(t VerifierTrust) bool {
	switch t.(type) {
	case NoVerifierTrust, *NoVerifierTrust:
		return true
	}
	return false
}
