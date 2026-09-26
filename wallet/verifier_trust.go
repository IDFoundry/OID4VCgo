package wallet

import (
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
// request MUST NOT be self-signed."
type X5CVerifierRoots struct {
	// Roots is the trust anchor set a Verifier's chain must verify
	// against. REQUIRED.
	Roots *x509.CertPool
}

// VerifyVerifierChain implements VerifierTrust.
func (v X5CVerifierRoots) VerifyVerifierChain(chain [][]byte) (*x509.Certificate, error) {
	if v.Roots == nil {
		return nil, fmt.Errorf("wallet: X5CVerifierRoots.Roots is required")
	}
	leaf, err := certchain.VerifyLeaf(chain, v.Roots)
	if err != nil {
		return nil, fmt.Errorf("wallet: verifier certificate: %w", err)
	}
	return leaf, nil
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
