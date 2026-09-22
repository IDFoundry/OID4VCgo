// This file builds ISO/IEC 18013-5 Annex B-compliant certificates for
// the mdoc Document Signer/IACA root identity — deliberately separate
// from GenerateSignerAndCert/GenerateCA's own generic certs (used for
// client attestation, SD-JWT VC issuer signing, key attestation, and
// everything else in this package), since Annex B's own requirements
// (a ≤457-day leaf validity, an mdlDS-only extended key usage, a
// digitalSignature-only key usage) are specific to mdoc document
// signing and would be actively wrong to impose on a general-purpose
// multi-format Credential Issuer identity. Confirmed against the OIDF
// conformance suite's own decompiled source
// (ValidateMdocDsCertificateProfile/ValidateMdocDsCertificateKeyUsage/
// ValidateMdocTrustAnchorIacaCertificateProfile/
// MdocCertificateProfileChecks), not guessed from the spec text alone
// — the suite's own "strict verifiers will reject credentials signed
// with it" WARNING is a real, non-hypothetical compliance gap, even
// though it's a WARNING today rather than a FAILURE.
package conformancecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 method (1) mandates SHA-1 specifically for a Subject Key Identifier — this is a required identifier derivation, not a security-sensitive digest
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// mdlDocumentSigningKeyPurpose is ISO/IEC 18013-5's own "mdlDS"
// extended key usage OID (Annex B.1.4/Table B.3) — the suite's own
// ValidateMdocDsCertificateProfile requires it present (and the
// extension marked critical) whenever the mdoc's own MSO carries
// docType "org.iso.18013.5.1.mDL", which this repo's own mdoc battery
// fixture always does.
var mdlDocumentSigningKeyPurpose = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}

// issuerAltNameOID is the Issuer Alternative Name extension (RFC 5280
// §4.2.1.7) — Annex B requires it on both the IACA root and the
// Document Signer leaf, carrying contact information for the issuing
// authority as an rfc822Name or uniformResourceIdentifier. Go's
// crypto/x509 has no built-in field for it (unlike Subject Alternative
// Name), so it's built by hand via ExtraExtensions.
var issuerAltNameOID = asn1.ObjectIdentifier{2, 5, 29, 18}

// mdocIACAValidity is comfortably under Annex B Table B.1's own
// 7305-day (20-year) maximum.
const mdocIACAValidity = 10 * 365 * 24 * time.Hour

// mdocDocumentSignerValidity is comfortably under Annex B Table B.3's
// own 457-day maximum, and deliberately longer than a caller's own
// issued-credential lifetime (this repo's own cmd/conformance-issuer
// issues mdocs with a 365-day MSO ValidityInfo — see
// issuedCredentialLifetime there): the suite's own live-verified
// ValidateMdocDsCertificateProfile check flags a WARNING whenever an
// MSO's own "validUntil" outlives the signing certificate's own
// "notAfter" (ISO/IEC 18013-5 §9.3.1 lets a reader reject such a
// credential outright), which a same-length window would always
// trigger — a credential is always minted some time strictly after
// this certificate, so an equal-length window guarantees the MSO's
// later start time pushes its own end past the certificate's.
const mdocDocumentSignerValidity = 400 * 24 * time.Hour

// mdocCertificateBackdate backdates both the IACA root's and the
// Document Signer's own NotBefore — a plain "-1h" (this package's own
// convention everywhere else, e.g. GenerateSignerAndCert/IssueLeafCertPEM)
// isn't enough here: cmd/conformance-issuer's own mdocClaimsForRequest
// rounds an issued mdoc's own MSO "signed"/"validFrom" down to the
// start of the current UTC day (RFC 9901 §10.1 anti-linkability, the
// same reasoning sdjwtvc.RoundedExp applies to SD-JWT VC's own "exp" —
// but unlike RoundedExp, which only rounds the far-future "exp", never
// the present-instant "iat", mdocClaimsForRequest rounds the *signing*
// timestamp itself). Confirmed live against a real OIDF conformance
// suite instance: whenever "now" is more than an hour past UTC
// midnight (i.e. nearly always), that rounding lands the MSO's own
// "signed" before a "-1h"-backdated Document Signer certificate's own
// NotBefore — ISO/IEC 18013-5 §9.3.1's own "signed... within the
// validity period of the certificate" requirement, deterministically
// violated, every run
// ("ValidateMdocMsoSignedWithinDsCertificateValidity" FAILURE). 25
// hours covers the full 24-hour truncation range with an hour to
// spare; both certs are throwaway conformance-testing material (this
// package's own doc comment), so there's no real-world constraint
// against backdating them further to accommodate it. Both the IACA
// root and the Document Signer it issues need it, not just the
// Document Signer: a child certificate's own validity starting before
// its issuing CA's would itself be a separate, avoidable red flag.
const mdocCertificateBackdate = 25 * time.Hour

// GenerateMdocIACA builds a fresh, self-signed EC P-256 IACA root
// certificate meeting ISO/IEC 18013-5 Annex B Table B.1: a v3
// certificate with a countryName+commonName subject, a critical
// keyUsage asserting only keyCertSign+cRLSign, critical
// basicConstraints with cA=true and pathLenConstraint=0, a Subject Key
// Identifier that's the SHA-1 hash of the raw public key, an Issuer
// Alternative Name, and none of Annex B.1.1's forbidden extensions
// (policy mappings/constraints, name constraints, inhibit-any-policy,
// freshest-CRL).
func GenerateMdocIACA(commonName, countryCode, contactURI string) (cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM, keyPEM string, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", "", err
	}
	serial, err := randomCertSerial()
	if err != nil {
		return nil, nil, "", "", err
	}
	ian, err := issuerAlternativeNameExtension(contactURI)
	if err != nil {
		return nil, nil, "", "", err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Country: []string{countryCode}, CommonName: commonName},
		NotBefore:             time.Now().Add(-mdocCertificateBackdate),
		NotAfter:              time.Now().Add(mdocIACAValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          subjectKeyIdentifier(&key.PublicKey),
		ExtraExtensions:       []pkix.Extension{ian},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", "", err
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", "", err
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		return nil, nil, "", "", err
	}
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, nil
}

// GenerateMdocDocumentSigner builds a fresh EC P-256 Document Signer
// leaf certificate, signed by iacaCert/iacaKey (see GenerateMdocIACA),
// meeting ISO/IEC 18013-5 Annex B Table B.3: a v3 certificate valid
// for at most 457 days, a countryName+commonName subject, a critical
// keyUsage asserting only digitalSignature, a critical extended key
// usage asserting only mdlDS, no basicConstraints (this leaf must not
// be a CA), a Subject Key Identifier and an Authority Key Identifier
// matching the IACA's own Subject Key Identifier, a CRL Distribution
// Points extension with a URI (required present, unlike the IACA
// root's own optional one), and an Issuer Alternative Name.
func GenerateMdocDocumentSigner(commonName, countryCode, contactURI, crlURI string, iacaCert *x509.Certificate, iacaKey *ecdsa.PrivateKey) (key *ecdsa.PrivateKey, keyPEM, certPEM string, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	serial, err := randomCertSerial()
	if err != nil {
		return nil, "", "", err
	}
	ian, err := issuerAlternativeNameExtension(contactURI)
	if err != nil {
		return nil, "", "", err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Country: []string{countryCode}, CommonName: commonName},
		NotBefore:             time.Now().Add(-mdocCertificateBackdate),
		NotAfter:              time.Now().Add(mdocDocumentSignerValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyIdentifier(&key.PublicKey),
		AuthorityKeyId:        iacaCert.SubjectKeyId,
		CRLDistributionPoints: []string{crlURI},
		ExtraExtensions:       []pkix.Extension{ian, extendedKeyUsageExtension(mdlDocumentSigningKeyPurpose)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, iacaCert, &key.PublicKey, iacaKey)
	if err != nil {
		return nil, "", "", err
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		return nil, "", "", err
	}
	return key, keyPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// randomCertSerial returns a positive, cryptographically random serial
// number well under Annex B's own 20-octet maximum (16 bytes/128
// bits, with the top bit cleared to keep it unambiguously positive).
func randomCertSerial() (*big.Int, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	buf[0] &= 0x7f
	return new(big.Int).SetBytes(buf), nil
}

// subjectKeyIdentifier computes RFC 5280 §4.2.1.2 method (1): the
// SHA-1 hash of the raw (uncompressed) EC public key bit string — the
// suite's own checkSubjectKeyIdentifierValue requires exactly this,
// not whatever crypto/x509 would derive on its own if SubjectKeyId
// were left unset.
func subjectKeyIdentifier(pub *ecdsa.PublicKey) []byte {
	raw := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck // SA1019: Marshal (not MarshalCompressed) is required here — Annex B mandates the uncompressed point form, and its own SKI is the SHA-1 hash of exactly these bytes
	sum := sha1.Sum(raw)                             //nolint:gosec // see this file's own top-level import comment
	return sum[:]
}

// generalName is one GeneralName choice (RFC 5280 §4.2.1.6) encoded as
// a raw context-specific IMPLICIT tag — asn1.Marshal of a slice of
// these produces the GeneralNames SEQUENCE OF an Issuer/Subject
// Alternative Name extension's own value needs.
type generalName = asn1.RawValue

const (
	generalNameTagRFC822 = 1
	generalNameTagURI    = 6
)

// issuerAlternativeNameExtension builds a non-critical Issuer
// Alternative Name extension (OID 2.5.29.18) carrying uri as a single
// uniformResourceIdentifier GeneralName — crypto/x509 has no built-in
// field for this extension (unlike Subject Alternative Name), so it's
// built by hand.
func issuerAlternativeNameExtension(uri string) (pkix.Extension, error) {
	names := []generalName{{Class: asn1.ClassContextSpecific, Tag: generalNameTagURI, Bytes: []byte(uri)}}
	der, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal issuer alternative name: %w", err)
	}
	return pkix.Extension{Id: issuerAltNameOID, Critical: false, Value: der}, nil
}

// extendedKeyUsageExtension builds a critical Extended Key Usage
// extension (OID 2.5.29.37) asserting exactly one key purpose OID —
// crypto/x509's own ExtKeyUsage/UnknownExtKeyUsage fields always emit
// this extension as non-critical, which Annex B Table B.3 doesn't
// allow, so it's built by hand instead.
func extendedKeyUsageExtension(purpose asn1.ObjectIdentifier) pkix.Extension {
	der, err := asn1.Marshal([]asn1.ObjectIdentifier{purpose})
	if err != nil {
		// asn1.Marshal only fails on values it can't represent at all —
		// a single well-formed ObjectIdentifier always marshals.
		panic(fmt.Sprintf("conformancecert: marshal extended key usage: %v", err))
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: der}
}
