package verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"

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
// certificate also happens to be present in Roots — HAIP's own trust
// model wants a leaf issued by a separate CA (so the leaf can be
// rotated/revoked without redistributing a new trust anchor to every
// relying party), not a leaf that doubles as its own anchor.
type X5CIssuerKeyResolver struct {
	// Roots is the trust anchor set a presented x5c chain must
	// validate against. REQUIRED.
	Roots *x509.CertPool
}

// ResolveIssuerKey implements SDJWTVCIssuerKeyResolver.
func (r X5CIssuerKeyResolver) ResolveIssuerKey(_ context.Context, header, _ map[string]any) (crypto.PublicKey, jose.Alg, error) {
	certs, err := x5cCertificates(header)
	if err != nil {
		return nil, "", err
	}
	leaf := certs[0]

	if isSelfSigned(leaf) {
		return nil, "", fmt.Errorf("verifier: x5c leaf certificate must not be self-signed")
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         r.Roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, "", fmt.Errorf("verifier: x5c chain does not verify against a trusted root: %w", err)
	}

	alg, err := sdjwtvcAlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// x5cCertificates extracts and parses header's own "x5c" member
// (RFC 7515 §4.1.6: a JSON array of standard-base64-encoded DER
// certificates, leaf first), requiring at least one entry — HAIP
// 1.0 §5.3's own MUST, absent from any header a wallet built without
// credential/sdjwtvc.IssueOptions.IssuerCertificate set.
func x5cCertificates(header map[string]any) ([]*x509.Certificate, error) {
	raw, ok := header["x5c"]
	if !ok {
		return nil, fmt.Errorf("verifier: issuer JWT header has no x5c (HAIP 1.0 §5.3 requires one for dc+sd-jwt)")
	}
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("verifier: issuer JWT x5c header is not a non-empty array")
	}
	certs := make([]*x509.Certificate, 0, len(entries))
	for i, e := range entries {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("verifier: x5c[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("verifier: decode x5c[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("verifier: parse x5c[%d]: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// isSelfSigned reports whether cert's own signature was produced by
// its own public key (regardless of any IsCA/BasicConstraints
// extension) — deliberately not x509.Certificate.CheckSignatureFrom,
// which additionally enforces CA constraints that a self-signed *leaf*
// (the exact shape being rejected here) typically doesn't carry.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
