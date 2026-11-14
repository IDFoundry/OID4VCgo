package conformancecert_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// TestGenerateMdocRevocationListSigner_MeetsTableB9 mirrors the OIDF
// suite's ValidateMdocRevocationListSignerCertificateProfile: ISO/IEC
// 18013-5 Table B.9's profile for the signer of an MSO revocation list.
func TestGenerateMdocRevocationListSigner_MeetsTableB9(t *testing.T) {
	iaca, iacaKey, _, _, err := conformancecert.GenerateMdocIACA("test-mdoc-iaca", "FR", "https://example.com/contact")
	if err != nil {
		t.Fatal(err)
	}
	key, _, certPEM, err := conformancecert.GenerateMdocRevocationListSigner("test-mdoc-status", "FR", iaca, iacaKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := conformancecert.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("signature does not verify against the IACA: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey.(*ecdsa.PublicKey)) {
		t.Error("certificate is not the returned key's")
	}
	if cert.Version != 3 || cert.SerialNumber.Sign() != 1 {
		t.Errorf("version %d, serial sign %d; want 3 and positive", cert.Version, cert.SerialNumber.Sign())
	}
	if days := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24; days > 1187 {
		t.Errorf("validity period is %.0f days, want <=1187", days)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want the signature bit alone", cert.KeyUsage)
	}
	if cert.IsCA || cert.BasicConstraintsValid {
		t.Error("the signer must not be a CA")
	}
	if len(cert.SubjectKeyId) != 20 || string(cert.AuthorityKeyId) != string(iaca.SubjectKeyId) {
		t.Error("want a SHA-1 Subject Key Identifier and the IACA's as Authority Key Identifier")
	}
	if len(cert.UnknownExtKeyUsage) != 1 || cert.UnknownExtKeyUsage[0].String() != "1.3.6.1.5.5.7.3.45" {
		t.Errorf("UnknownExtKeyUsage = %v, want id-kp-oauthStatusSigning alone", cert.UnknownExtKeyUsage)
	}
	for _, ext := range cert.Extensions {
		if id := ext.Id.String(); ext.Critical != (id == "2.5.29.15") {
			t.Errorf("extension %s: Critical = %v; only key usage is critical", id, ext.Critical)
		}
	}
	for _, forbidden := range []string{"2.5.29.33", "2.5.29.30", "2.5.29.36", "2.5.29.54", "2.5.29.46"} {
		if _, ok := findExtension(cert, forbidden); ok {
			t.Errorf("forbidden extension %s is present", forbidden)
		}
	}
}
