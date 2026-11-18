package certchain

import (
	"crypto/sha1" //nolint:gosec // RFC 5280's key identifier method
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// DerivedKeyIdentifiers are the key identifiers derived from cert's
// public key: RFC 5280 §4.2.1.2 method 1's (SHA-1 of the
// subjectPublicKey BIT STRING's value) and RFC 7093 method 1's (SHA-256
// of it, truncated to 160 bits). Unlike the Subject Key Identifier a
// certificate declares, which its signer writes, no certificate for
// another key can have them. nil when the key doesn't parse.
func DerivedKeyIdentifiers(cert *x509.Certificate) [][]byte {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 {
		return nil
	}
	sha1Sum := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // RFC 5280's key identifier method, not a security use of SHA-1
	sha256Sum := sha256.Sum256(spki.PublicKey.Bytes)
	return [][]byte{sha1Sum[:], sha256Sum[:20]}
}
