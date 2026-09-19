// Package certchain implements the one certificate-chain-trust
// primitive shared by every X5C/X5C-chain-shaped resolver this repo
// ships (verifier.X5CIssuerKeyResolver, verifier.X5ChainIssuerKeyResolver,
// issuer.X5CAttestationVerifier, issuer.X5CProofBindingKeyResolver):
// parse a leaf-first chain and verify it against a trust anchor set,
// rejecting a self-signed leaf even when that leaf is itself a
// configured root. Promoted here once a second package (issuer)
// needed the identical logic verifier already had — see
// ARCHITECTURE.md's own stance on not sharing code across a boundary
// until a second real consumer exists.
package certchain

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// VerifyLeaf parses ders (leaf first, then any intermediates — RFC
// 7515 §4.1.6's own "x5c" ordering, which RFC 9360 §2's own "x5chain"
// mirrors) and verifies the leaf against roots, rejecting a
// self-signed leaf even when that leaf is itself a configured root —
// HAIP's own trust model wants a leaf issued by a separate CA (so the
// leaf can be rotated/revoked without redistributing a new trust
// anchor to every relying party), not a leaf that doubles as its own
// anchor.
func VerifyLeaf(ders [][]byte, roots *x509.CertPool) (*x509.Certificate, error) {
	if len(ders) == 0 {
		return nil, fmt.Errorf("certchain: certificate chain is empty")
	}
	certs := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certchain: parse certificate chain entry %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	if IsSelfSigned(leaf) {
		return nil, fmt.Errorf("certchain: leaf certificate must not be self-signed")
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	// ExtKeyUsageAny is deliberate, not an oversight: there's no
	// standard EKU value for "OID4VCI/OID4VP issuer/verifier identity"
	// the way ExtKeyUsageServerAuth exists for TLS, so requiring a
	// specific one here would risk rejecting real, spec-compliant
	// certificates that were never issued with OID4VCI/HAIP in mind
	// (found and deliberately left as-is in a repo-wide security
	// review — accepting a leaf issued for a different purpose, e.g.
	// TLS server auth, as long as it still chains to a trusted roots
	// entry, is a tightenable defense-in-depth gap, not on its own
	// exploitable: roots is the caller's own trust anchor set, already
	// the actual security boundary here). A caller wanting to restrict
	// certificates to a specific EKU should build its own check on top.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("certchain: certificate chain does not verify against a trusted root: %w", err)
	}
	return leaf, nil
}

// IsSelfSigned reports whether cert's own signature was produced by
// its own public key (regardless of any IsCA/BasicConstraints
// extension) — deliberately not x509.Certificate.CheckSignatureFrom,
// which additionally enforces CA constraints that a self-signed *leaf*
// (the exact shape VerifyLeaf rejects) typically doesn't carry.
func IsSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// DERsFromBase64 decodes entries (RFC 7515 §4.1.6: a JSON array of
// standard-base64-encoded DER certificates, leaf first, e.g. a JOSE
// "x5c" header member already type-asserted to []any) into raw DER
// bytes suitable for VerifyLeaf.
func DERsFromBase64(entries []any) ([][]byte, error) {
	ders := make([][]byte, 0, len(entries))
	for i, e := range entries {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("certchain: entry %d is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("certchain: decode entry %d: %w", i, err)
		}
		ders = append(ders, der)
	}
	return ders, nil
}
