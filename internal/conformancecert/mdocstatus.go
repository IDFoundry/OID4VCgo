package conformancecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"time"
)

// mdocRevocationListSignerValidity is under ISO/IEC 18013-5 Table
// B.9's 1187-day maximum, and longer than the Document Signer's own,
// so a list signer outlives the credentials whose status it signs.
const mdocRevocationListSignerValidity = 450 * 24 * time.Hour

// oauthStatusSigningKeyPurpose is id-kp-oauthStatusSigning
// (draft-ietf-oauth-status-list §10.2, 1.3.6.1.5.5.7.3.45): the
// extended key usage of a certificate that signs Status List Tokens.
var oauthStatusSigningKeyPurpose = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 45}

// GenerateMdocRevocationListSigner builds a fresh EC P-256 MSO
// revocation list signer certificate, signed by iacaCert/iacaKey (see
// GenerateMdocIACA), meeting ISO/IEC 18013-5 Table B.9 (§12.3.6.3): a
// v3 certificate valid for at most 1187 days, a countryName+commonName
// subject, a critical keyUsage asserting only digitalSignature, a
// Subject Key Identifier and an Authority Key Identifier matching the
// IACA's, no other critical extension and none Annex B.1.1 forbids.
// Its extended key usage, which §12.3.6.3 leaves optional and
// recommends against marking critical, is id-kp-oauthStatusSigning,
// non-critical. It signs the Token Status Lists an mdoc's MSO status
// references, which a reader validates to the IACA that issued the
// mdoc's Document Signer (§12.3.6.2).
func GenerateMdocRevocationListSigner(commonName, countryCode string, iacaCert *x509.Certificate, iacaKey *ecdsa.PrivateKey) (key *ecdsa.PrivateKey, keyPEM, certPEM string, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	serial, err := randomCertSerial()
	if err != nil {
		return nil, "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{Country: []string{countryCode}, CommonName: commonName},
		NotBefore:          time.Now().Add(-mdocCertificateBackdate),
		NotAfter:           time.Now().Add(mdocRevocationListSignerValidity),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SubjectKeyId:       subjectKeyIdentifier(&key.PublicKey),
		AuthorityKeyId:     iacaCert.SubjectKeyId,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oauthStatusSigningKeyPurpose},
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
