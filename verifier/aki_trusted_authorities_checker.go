package verifier

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// AKITrustedAuthoritiesChecker implements TrustedAuthoritiesChecker for
// dcql.TrustedAuthorityAKI only (§6.1.1.1) — HAIP 1.0 §5's own required
// TrustedAuthoritiesType. It parses issuerChain's own leaf certificate
// and succeeds if its X.509 Authority Key Identifier extension (RFC
// 5280 §4.2.1.1) — the base64url-encoded value §6.1.1.1 itself
// specifies — matches any Values entry across every
// dcql.TrustedAuthorityAKI entry in authorities.
//
// This is a purely local, offline check: unlike a Trust Anchor set
// resolved via network (e.g. OpenID Federation's own Trust Chain
// walk), an Authority Key Identifier only ever names which key signed
// the leaf certificate — it says nothing about whether that key is
// itself trustworthy. Establishing that is IssuerKeys'/MdocIssuerKeys'
// own job (e.g. X5CIssuerKeyResolver's own Roots) — this checker only
// ever narrows an already-trusted chain further, per the specific
// authorities values a Credential Query declared, never substitutes
// for it.
type AKITrustedAuthoritiesChecker struct{}

// CheckTrustedAuthorities implements TrustedAuthoritiesChecker.
func (AKITrustedAuthoritiesChecker) CheckTrustedAuthorities(_ context.Context, authorities []dcql.TrustedAuthoritiesQuery, issuerChain [][]byte) error {
	var wantAKIs []string
	for _, ta := range authorities {
		if ta.Type == dcql.TrustedAuthorityAKI {
			wantAKIs = append(wantAKIs, ta.Values...)
		}
	}
	if len(wantAKIs) == 0 {
		return fmt.Errorf("verifier: no %q entry in trusted_authorities", dcql.TrustedAuthorityAKI)
	}
	if len(issuerChain) == 0 {
		return fmt.Errorf("verifier: no issuer certificate chain to check an %q trusted_authorities entry against", dcql.TrustedAuthorityAKI)
	}
	leaf, err := x509.ParseCertificate(issuerChain[0])
	if err != nil {
		return fmt.Errorf("verifier: parse issuer leaf certificate: %w", err)
	}
	if len(leaf.AuthorityKeyId) == 0 {
		return fmt.Errorf("verifier: issuer leaf certificate has no authority key identifier extension")
	}
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)
	if !slices.Contains(wantAKIs, aki) {
		return fmt.Errorf("verifier: issuer certificate's authority key identifier is not among the requested trusted_authorities")
	}
	return nil
}
