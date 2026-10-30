package certchain

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
)

// oidExtKeyUsage is the extended key usage extension's OID (RFC 5280
// §4.2.1.12).
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// oidAnyExtendedKeyUsage is anyExtendedKeyUsage (RFC 5280 §4.2.1.12).
var oidAnyExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37, 0}

// ExtKeyUsages is the key purposes cert's extended key usage extension
// lists, read from the extension itself so that a standard purpose and
// a private one look alike, and whether cert has the extension.
func ExtKeyUsages(cert *x509.Certificate) ([]asn1.ObjectIdentifier, bool, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtKeyUsage) {
			continue
		}
		var usages []asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(ext.Value, &usages); err != nil || len(rest) > 0 {
			return nil, true, fmt.Errorf("certchain: the certificate's extended key usage extension is malformed")
		}
		return usages, true, nil
	}
	return nil, false, nil
}

// EKUInPath is a role's extended key usage check over a verified path,
// not just its leaf: leaf must list oid in its extended key usage, and
// at least one of chains (the paths VerifyChains built, leaf first,
// as a LeafPolicy receives them) must have every intermediate that
// carries an extended key usage extension list oid or
// anyExtendedKeyUsage. Chain validation here accepts any key usage
// (VerifyChains), so without the second check a CA an ecosystem
// restricts to one role could issue a certificate for another. The
// trust anchor at a path's end isn't checked: the relying party chose
// it. With no chains, only the leaf is checked.
func EKUInPath(leaf *x509.Certificate, chains [][]*x509.Certificate, oid asn1.ObjectIdentifier) error {
	usages, _, err := ExtKeyUsages(leaf)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(usages, oid.Equal) {
		return fmt.Errorf("certchain: the certificate's extended key usage doesn't include %s", oid)
	}
	return EKUInIntermediates(chains, oid)
}

// EKUInIntermediates is EKUInPath's check of chains' intermediates
// alone, for a caller that has checked the leaf: nil when chains is
// empty, or when one of them has every intermediate that carries an
// extended key usage extension list oid or anyExtendedKeyUsage.
func EKUInIntermediates(chains [][]*x509.Certificate, oid asn1.ObjectIdentifier) error {
	if len(chains) == 0 {
		return nil
	}
	for _, chain := range chains {
		if intermediatesAllow(chain, oid) {
			return nil
		}
	}
	return fmt.Errorf("certchain: an intermediate CA on every verified path restricts its extended key usage to purposes other than %s", oid)
}

// intermediatesAllow reports whether every intermediate of chain (the
// certificates between its leaf and its anchor) that has an extended
// key usage extension lists oid or anyExtendedKeyUsage.
func intermediatesAllow(chain []*x509.Certificate, oid asn1.ObjectIdentifier) bool {
	if len(chain) == 0 {
		return false
	}
	for _, cert := range chain[1:max(1, len(chain)-1)] {
		if cert == nil {
			return false
		}
		usages, present, err := ExtKeyUsages(cert)
		if err != nil {
			return false
		}
		if present && !slices.ContainsFunc(usages, func(u asn1.ObjectIdentifier) bool {
			return u.Equal(oid) || u.Equal(oidAnyExtendedKeyUsage)
		}) {
			return false
		}
	}
	return true
}
