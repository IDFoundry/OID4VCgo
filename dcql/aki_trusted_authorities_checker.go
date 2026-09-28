package dcql

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// AKITrustedAuthoritiesChecker implements TrustedAuthoritiesChecker for
// TrustedAuthorityAKI only (§6.1.1.1) — HAIP 1.0 §5's own required
// TrustedAuthoritiesType. Each requested value is a CA's Subject Key
// Identifier, base64url-encoded (see AKITrustedAuthorities); §6.1.1.1
// matches it against the Authority Key Identifier (RFC 5280 §4.2.1.1)
// of a certificate in the credential's chain.
//
// How it matches depends on Roots:
//
//   - With Roots set, it verifies issuerChain against Roots and matches
//     the requested values against the Subject Key Identifiers of the
//     certificate authorities actually on a verified path — every
//     intermediate and the root. That establishes which CA really
//     issued the credential's certificate, so it's a verification
//     control. verifier.VerifyResponse requires it.
//   - Without Roots, it reads the leaf certificate's own Authority Key
//     Identifier extension. That's what the leaf states about its
//     issuer, not something chain validation checks: any CA can issue
//     a certificate naming another CA's key identifier there. It's only
//     fit for a Wallet narrowing which of its own credentials to offer
//     (wallet.MatchDCQLQuery), never for deciding whether to trust a
//     presented credential.
//
// Either way it only narrows trust in an issuer that a role package's
// own key resolver already established (e.g. verifier.X5CIssuerKeyResolver's
// Roots); OID4VP §6.1.1 calls trusted_authorities chiefly a data
// minimisation aid, and a Verifier must still decide issuer trust on
// its own.
type AKITrustedAuthoritiesChecker struct {
	// Roots, if set, are the trust anchors issuerChain is verified
	// against before matching (see the type's doc comment) — normally
	// the same anchors the Verifier's issuer key resolver uses.
	Roots *x509.CertPool
}

// CheckTrustedAuthorities implements TrustedAuthoritiesChecker.
func (c AKITrustedAuthoritiesChecker) CheckTrustedAuthorities(_ context.Context, authorities []TrustedAuthoritiesQuery, issuerChain [][]byte) error {
	var wantAKIs []string
	for _, ta := range authorities {
		if ta.Type == TrustedAuthorityAKI {
			wantAKIs = append(wantAKIs, ta.Values...)
		}
	}
	if len(wantAKIs) == 0 {
		return fmt.Errorf("dcql: no %q entry in trusted_authorities", TrustedAuthorityAKI)
	}
	if len(issuerChain) == 0 {
		return fmt.Errorf("dcql: no issuer certificate chain to check an %q trusted_authorities entry against", TrustedAuthorityAKI)
	}
	if c.Roots != nil {
		return checkVerifiedChainAKI(issuerChain, c.Roots, wantAKIs)
	}
	leaf, err := x509.ParseCertificate(issuerChain[0])
	if err != nil {
		return fmt.Errorf("dcql: parse issuer leaf certificate: %w", err)
	}
	if len(leaf.AuthorityKeyId) == 0 {
		return fmt.Errorf("dcql: issuer leaf certificate has no authority key identifier extension")
	}
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)
	if !slices.Contains(wantAKIs, aki) {
		return fmt.Errorf("dcql: issuer certificate's authority key identifier is not among the requested trusted_authorities")
	}
	return nil
}

// checkVerifiedChainAKI succeeds when a certificate authority on a
// verified path from issuerChain's leaf to roots has one of wantAKIs as
// its Subject Key Identifier.
func checkVerifiedChainAKI(issuerChain [][]byte, roots *x509.CertPool, wantAKIs []string) error {
	_, chains, err := certchain.VerifyChains(issuerChain, roots)
	if err != nil {
		return fmt.Errorf("dcql: issuer certificate chain: %w", err)
	}
	for _, chain := range chains {
		for _, ca := range chain[1:] {
			if len(ca.SubjectKeyId) > 0 && slices.Contains(wantAKIs, base64.RawURLEncoding.EncodeToString(ca.SubjectKeyId)) {
				return nil
			}
		}
	}
	return fmt.Errorf("dcql: no certificate authority on the issuer's verified chain is among the requested trusted_authorities")
}
