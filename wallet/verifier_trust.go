package wallet

import (
	"bytes"
	"crypto/x509"
	"fmt"

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
// certificates, unless LeafPolicy tells them apart.
type X5CVerifierRoots struct {
	// Roots is the trust anchor set a Verifier's chain must verify
	// against. REQUIRED.
	Roots *x509.CertPool

	// LeafPolicy, if set, is run on the chain-verified leaf and its
	// verified paths, and can refuse it: require what distinguishes a
	// Verifier's certificate (an extended key usage, a certificate
	// policy) where Roots also anchor other roles.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
}

// VerifyVerifierChain implements VerifierTrust.
func (v X5CVerifierRoots) VerifyVerifierChain(chain [][]byte) (*x509.Certificate, error) {
	if v.Roots == nil {
		return nil, fmt.Errorf("wallet: X5CVerifierRoots.Roots is required")
	}
	leaf, err := certchain.VerifyLeafWithPolicy(chain, v.Roots, func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
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
	})
	if err != nil {
		return nil, fmt.Errorf("wallet: verifier certificate: %w", err)
	}
	return leaf, nil
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
