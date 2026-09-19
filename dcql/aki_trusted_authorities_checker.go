package dcql

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
)

// AKITrustedAuthoritiesChecker implements TrustedAuthoritiesChecker for
// TrustedAuthorityAKI only (§6.1.1.1) — HAIP 1.0 §5's own required
// TrustedAuthoritiesType. It parses issuerChain's own leaf certificate
// and succeeds if its X.509 Authority Key Identifier extension (RFC
// 5280 §4.2.1.1) — the base64url-encoded value §6.1.1.1 itself
// specifies — matches any Values entry across every TrustedAuthorityAKI
// entry in authorities.
//
// This is a purely local, offline check: unlike a Trust Anchor set
// resolved via network (e.g. OpenID Federation's own Trust Chain
// walk), an Authority Key Identifier only ever names which key signed
// the leaf certificate — it says nothing about whether that key is
// itself trustworthy. Establishing that is each role package's own
// issuer key resolver's job (e.g. verifier.X5CIssuerKeyResolver's own
// Roots) — this checker only ever narrows an already-trusted chain
// further, per the specific authorities values a Credential Query
// declared, never substitutes for it.
type AKITrustedAuthoritiesChecker struct{}

// CheckTrustedAuthorities implements TrustedAuthoritiesChecker.
func (AKITrustedAuthoritiesChecker) CheckTrustedAuthorities(_ context.Context, authorities []TrustedAuthoritiesQuery, issuerChain [][]byte) error {
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
