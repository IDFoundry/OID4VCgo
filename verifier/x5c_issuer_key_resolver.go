package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// X5CIssuerKeyResolver implements SDJWTVCIssuerKeyResolver by
// validating a presented "dc+sd-jwt" credential's own "x5c" header
// (RFC 7515 §4.1.6) against Roots — HAIP 1.0 §5.3's own MUST for
// "dc+sd-jwt" issuer trust, which SDJWTVCIssuerKeyResolver's own doc
// comment names as a deployment policy decision but leaves
// unimplemented anywhere in this repo. Confirmed live against the
// OpenID Foundation conformance suite's own two checks on this exact
// requirement ("Credential MUST contain an x5c in the header", "Leaf
// certificate in x5c chain must not be self-signed" —
// cmd/conformance-wallet-vp's own README) — this resolver enforces
// both on the verifying side, not just the issuing side
// credential/sdjwtvc.IssueOptions.IssuerCertificate satisfies on the
// issuing side.
//
// A self-signed leaf is always rejected, even if that exact
// certificate also happens to be present in Roots — see
// internal/certchain.VerifyLeaf's own doc comment for why.
type X5CIssuerKeyResolver struct {
	// Roots is the trust anchor set a presented x5c chain must
	// validate against. REQUIRED.
	Roots *x509.CertPool
}

// ResolveIssuerKey implements SDJWTVCIssuerKeyResolver.
func (r X5CIssuerKeyResolver) ResolveIssuerKey(_ context.Context, header, _ map[string]any) (crypto.PublicKey, jose.Alg, error) {
	ders, err := x5cDERs(header)
	if err != nil {
		return nil, "", err
	}
	leaf, err := certchain.VerifyLeaf(ders, r.Roots)
	if err != nil {
		return nil, "", err
	}
	alg, err := sdjwtvcAlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// x5cDERs extracts header's own "x5c" member (RFC 7515 §4.1.6: a JSON
// array of standard-base64-encoded DER certificates, leaf first) as
// raw DER bytes, requiring at least one entry — HAIP 1.0 §5.3's own
// MUST, absent from any header a wallet built without
// credential/sdjwtvc.IssueOptions.IssuerCertificate set.
func x5cDERs(header map[string]any) ([][]byte, error) {
	raw, ok := header["x5c"]
	if !ok {
		return nil, fmt.Errorf("verifier: issuer JWT header has no x5c (HAIP 1.0 §5.3 requires one for dc+sd-jwt)")
	}
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("verifier: issuer JWT x5c header is not a non-empty array")
	}
	ders, err := certchain.DERsFromBase64(entries)
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}
	return ders, nil
}
