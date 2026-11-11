package mobile

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// oidAnyExtendedKeyUsage is anyExtendedKeyUsage (RFC 5280 §4.2.1.12).
var oidAnyExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37, 0}

// parseOID parses a dotted object identifier, such as "1.3.6.1.5.5.7.3.2".
// Each arc must be written canonically, in decimal digits with no sign
// and no leading zero, so one object identifier has one spelling.
func parseOID(dotted string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(dotted, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%q isn't a dotted object identifier", dotted)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		if !canonicalArc(p) {
			return nil, fmt.Errorf("%q isn't a dotted object identifier", dotted)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("%q isn't a dotted object identifier", dotted)
		}
		oid[i] = n
	}
	return oid, nil
}

// canonicalArc reports whether p is an object identifier arc written
// canonically: decimal digits only, and no leading zero but in "0".
func canonicalArc(p string) bool {
	if p == "" || (len(p) > 1 && p[0] == '0') {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// requireEKU is a leaf policy refusing a certificate whose extended key
// usage extension doesn't list oid — the role an ecosystem marks its
// verifiers' or registrars' certificates with — or whose every
// verified path has an intermediate CA whose own extended key usage
// excludes it (certchain.EKUInPath). It reads the extension itself, so
// a standard key usage and a private one match alike.
func requireEKU(oid asn1.ObjectIdentifier) func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		return certchain.EKUInPath(leaf, chains, oid)
	}
}

// pemCertificates are the DER certificates in pemText.
func pemCertificates(pemText string) [][]byte {
	var out [][]byte
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
}

// mdocReaderAuthEKU is ISO/IEC 18013-5's mdoc reader authentication
// extended key usage (mdoc_reader_require_eku).
const mdocReaderAuthEKU = "1.0.18013.5.1.6"

// checkRoleRoots refuses, outside development, two roles whose roots
// may vouch for the same certificates unless each has its own extended
// key usage, and the two differ: otherwise an issuer's signing
// certificate, say, would be taken for a trusted Verifier, a Verifier's
// for an issuer able to issue credentials, or a Verifier's second
// certificate for a registrar. Roots may vouch for the same
// certificates when they share an anchor, and whenever either holds an
// intermediate: where that chains to can't be known from the roots
// alone, so it may be the other's.
//
// The credential issuers' roots, issuer_roots and the mdoc ones, are
// one role: an ecosystem's CA may certify both its SD-JWT VC issuers
// and its document signers, told apart by their extended key usages,
// so they aren't checked against each other.
func checkRoleRoots(cfg config) error {
	if cfg.Development {
		return nil
	}
	mdocEKU := ""
	if cfg.MdocReaderRequireEKU {
		mdocEKU = mdocReaderAuthEKU
	}
	roles := []roleRoots{
		{name: "verifier_roots", roots: cfg.VerifierRoots, eku: cfg.VerifierRequireEKU},
		{name: "registrar_roots", roots: cfg.RegistrarRoots, eku: cfg.RegistrarRequireEKU},
		{name: "issuer_roots", roots: cfg.IssuerRoots, eku: cfg.IssuerRequireEKU, family: roleIssuer},
		{name: "issuer_metadata_roots", roots: cfg.IssuerMetadataRoots, eku: cfg.IssuerMetadataRequireEKU},
		{name: "mdoc_reader_roots", roots: cfg.MdocReaderRoots, eku: mdocEKU},
		{name: "mdoc_issuer_roots", roots: cfg.MdocIssuerRoots, eku: cfg.MdocIssuerRequireEKU, family: roleIssuer},
	}
	if cfg.MdocIssuerRoots == "" && cfg.MdocIssuerRequireEKU != "" {
		// Then mdocs are received under issuer_roots, recognized by
		// mdoc_issuer_require_eku: that pair must be told apart from the
		// other roles too, beside issuer_roots' own.
		roles = append(roles, roleRoots{name: "issuer_roots", roots: cfg.IssuerRoots, eku: cfg.MdocIssuerRequireEKU, ekuName: "mdoc_issuer_require_eku", family: roleIssuer})
	}
	for _, docType := range slices.Sorted(maps.Keys(cfg.MdocIssuerRootsByDocType)) {
		roles = append(roles, roleRoots{
			name: fmt.Sprintf("mdoc_issuer_roots_by_doctype[%q]", docType), roots: cfg.MdocIssuerRootsByDocType[docType],
			eku: cfg.MdocIssuerRequireEKU, ekuName: "mdoc_issuer_require_eku", family: roleIssuer,
		})
	}
	for i, a := range roles {
		for _, b := range roles[i+1:] {
			if a.family != "" && a.family == b.family {
				continue
			}
			if err := checkRolePair(a, b); err != nil {
				return err
			}
		}
	}
	return nil
}

// roleIssuer is the family of the credential issuers' roots.
const roleIssuer = "issuer"

// roleRoots is one role's roots configuration key, its roots and its
// extended key usage, for checkRoleRoots: ekuName is the key setting
// it, when it isn't ekuKey(name), and family the roles, if any, whose
// roots may share anchors.
type roleRoots struct {
	name, roots string
	eku         string
	ekuName     string
	family      string
}

// ekuConfigKey is the configuration key naming r's extended key usage.
func (r roleRoots) ekuConfigKey() string {
	if r.ekuName != "" {
		return r.ekuName
	}
	return ekuKey(r.name)
}

// checkRolePair is checkRoleRoots for roles a and b.
func checkRolePair(a, b roleRoots) error {
	if !mayShareAnchor(a.roots, b.roots) {
		return nil
	}
	for _, r := range []struct {
		role  roleRoots
		other string
	}{{a, b.name}, {b, a.name}} {
		if r.role.eku == "" {
			return newError(CodeInvalidInput, fmt.Errorf("%s may share a trust anchor with %s: set %s to tell its certificates apart", r.role.name, r.other, r.role.ekuConfigKey()))
		}
	}
	ekus := make([]asn1.ObjectIdentifier, 2)
	for i, r := range []roleRoots{a, b} {
		oid, err := parseOID(r.eku)
		if err != nil {
			return newError(CodeInvalidInput, fmt.Errorf("%s: %w", r.ekuConfigKey(), err))
		}
		ekus[i] = oid
	}
	// Compared parsed, so one object identifier is one however spelled.
	if ekus[0].Equal(ekus[1]) {
		return newError(CodeInvalidInput, fmt.Errorf("%s and %s may share a trust anchor, and %s and %s are the same extended key usage, which can't tell their certificates apart", a.name, b.name, a.ekuConfigKey(), b.ekuConfigKey()))
	}
	return nil
}

// ekuKey is the configuration key naming the extended key usage of the
// role whose roots are rootsKey.
func ekuKey(rootsKey string) string {
	return strings.TrimSuffix(rootsKey, "_roots") + "_require_eku"
}

// mayShareAnchor reports whether roots a and b may vouch for the same
// certificates: they share an anchor (shareAnchor), or either holds a
// certificate that isn't self-signed, an intermediate, whose own
// anchor is unknown.
func mayShareAnchor(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return shareAnchor(a, b) || holdsIntermediate(a) || holdsIntermediate(b)
}

// holdsIntermediate reports whether pemText has a certificate not
// signed by its own key.
func holdsIntermediate(pemText string) bool {
	for _, c := range parseCertificates(pemCertificates(pemText)) {
		// Self-signed is the certificate's own key signing it, CA flag or
		// not (CheckSignatureFrom would also want the flag).
		if c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil {
			return true
		}
	}
	return false
}

// shareAnchor reports whether roots a and b can vouch for the same
// certificates: they share a certificate, or the same key under the
// same subject (a reissued anchor), or a certificate in one is
// certified, directly or through others in either, by one in the other
// (an intermediate, or a cross-certificate). A certificate chaining to
// one may then chain to both.
func shareAnchor(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	as, bs := parseCertificates(pemCertificates(a)), parseCertificates(pemCertificates(b))
	all := append(slices.Clone(as), bs...)
	for _, x := range as {
		for _, y := range bs {
			if sameAnchor(x, y) || certifiedBy(x, y, all) || certifiedBy(y, x, all) {
				return true
			}
		}
	}
	return false
}

func parseCertificates(ders [][]byte) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		if cert, err := x509.ParseCertificate(der); err == nil {
			out = append(out, cert)
		}
	}
	return out
}

// sameAnchor reports whether x and y are one anchor: the same
// certificate, or the same key under the same subject.
func sameAnchor(x, y *x509.Certificate) bool {
	return bytes.Equal(x.Raw, y.Raw) ||
		(bytes.Equal(x.RawSubject, y.RawSubject) && bytes.Equal(x.RawSubjectPublicKeyInfo, y.RawSubjectPublicKeyInfo))
}

// certifiedBy reports whether x is certified by y, directly or through
// a path of certificates in all.
func certifiedBy(x, y *x509.Certificate, all []*x509.Certificate) bool {
	seen := map[*x509.Certificate]bool{x: true}
	frontier := []*x509.Certificate{x}
	for len(frontier) > 0 {
		cur := frontier[0]
		frontier = frontier[1:]
		for _, issuer := range all {
			if seen[issuer] || !bytes.Equal(cur.RawIssuer, issuer.RawSubject) || cur.CheckSignatureFrom(issuer) != nil {
				continue
			}
			if sameAnchor(issuer, y) {
				return true
			}
			seen[issuer] = true
			frontier = append(frontier, issuer)
		}
	}
	return false
}

// roleEKU is the leaf policy for the config key name's OID, nil if
// it's unset.
func roleEKU(name, dotted string) (func(*x509.Certificate, [][]*x509.Certificate) error, error) {
	if dotted == "" {
		return nil, nil
	}
	oid, err := parseOID(dotted)
	if err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("%s: %w", name, err))
	}
	// anyExtendedKeyUsage (RFC 5280 §4.2.1.12) names no role: every
	// certificate with it would pass.
	if oid.Equal(oidAnyExtendedKeyUsage) {
		return nil, newError(CodeInvalidInput, fmt.Errorf("%s: anyExtendedKeyUsage can't tell a role's certificates apart", name))
	}
	return requireEKU(oid), nil
}
