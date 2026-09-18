package conformancecert_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// These tests re-implement, in Go, the exact checks the OIDF
// conformance suite's own decompiled ValidateMdocTrustAnchorIacaCertificateProfile/
// ValidateMdocDsCertificateProfile/ValidateMdocDsCertificateKeyUsage/
// MdocCertificateProfileChecks classes run — not a paraphrase of ISO/IEC
// 18013-5 Annex B from memory, but the suite's own literal logic —
// so a regression here is caught before it ever needs a live suite run
// to surface.

func generateTestCerts(t *testing.T) (iaca *x509.Certificate, ds *x509.Certificate) {
	t.Helper()
	iacaCert, iacaKey, _, _, err := conformancecert.GenerateMdocIACA("test-mdoc-iaca", "FR", "https://example.com/contact")
	if err != nil {
		t.Fatalf("GenerateMdocIACA: %v", err)
	}
	_, _, dsCertPEM, err := conformancecert.GenerateMdocDocumentSigner("test-mdoc-ds", "FR", "https://example.com/contact", "https://example.com/mdoc.crl", iacaCert, iacaKey)
	if err != nil {
		t.Fatalf("GenerateMdocDocumentSigner: %v", err)
	}
	dsCert, err := conformancecert.ParseCertificatePEM(dsCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(ds): %v", err)
	}
	return iacaCert, dsCert
}

func findExtension(cert *x509.Certificate, oid string) (ext pkix.Extension, ok bool) {
	for _, e := range cert.Extensions {
		if e.Id.String() == oid {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

// TestGenerateMdocIACA_MeetsAnnexBTableB1 mirrors
// ValidateMdocTrustAnchorIacaCertificateProfile's own checks.
func TestGenerateMdocIACA_MeetsAnnexBTableB1(t *testing.T) {
	iaca, _ := generateTestCerts(t)

	if iaca.Version != 3 {
		t.Errorf("Version = %d, want 3", iaca.Version)
	}
	if iaca.SerialNumber.Sign() != 1 {
		t.Errorf("SerialNumber.Sign() = %d, want 1 (positive)", iaca.SerialNumber.Sign())
	}
	if n := len(iaca.SerialNumber.Bytes()); n > 20 {
		t.Errorf("serial number is %d octets, want <=20", n)
	}
	if days := iaca.NotAfter.Sub(iaca.NotBefore).Hours() / 24; days > 7305 {
		t.Errorf("validity period is %.0f days, want <=7305", days)
	}
	if !iaca.IsCA {
		t.Error("IsCA = false, want true")
	}
	if iaca.MaxPathLen != 0 || !iaca.MaxPathLenZero {
		t.Errorf("pathLenConstraint = %d (zero=%v), want exactly 0", iaca.MaxPathLen, iaca.MaxPathLenZero)
	}
	if iaca.Subject.String() == "" || len(iaca.Subject.Country) == 0 {
		t.Error("subject has no countryName")
	} else if c := iaca.Subject.Country[0]; c != "FR" {
		t.Errorf("subject countryName = %q, want %q", c, "FR")
	}
	if iaca.Subject.CommonName == "" {
		t.Error("subject has no commonName")
	}
	if iaca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("KeyUsage = %v, want exactly KeyUsageCertSign|KeyUsageCRLSign", iaca.KeyUsage)
	}
	if len(iaca.SubjectKeyId) != 20 {
		t.Errorf("SubjectKeyId is %d bytes, want 20 (a SHA-1 digest)", len(iaca.SubjectKeyId))
	}
	pub, ok := iaca.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey is %T, want *ecdsa.PublicKey", iaca.PublicKey)
	}
	if pub.Curve.Params().Name != "P-256" {
		t.Errorf("curve = %s, want P-256 (one of ISO 18013-5 Annex B's allowed curves)", pub.Curve.Params().Name)
	}

	// Critical extensions: only keyUsage(2.5.29.15) and
	// basicConstraints(2.5.29.19) may be critical.
	for _, ext := range iaca.Extensions {
		id := ext.Id.String()
		wantCritical := id == "2.5.29.15" || id == "2.5.29.19"
		if ext.Critical != wantCritical {
			t.Errorf("extension %s: Critical = %v, want %v", id, ext.Critical, wantCritical)
		}
	}
	if _, ok := findExtension(iaca, "2.5.29.18"); !ok {
		t.Error("issuer alternative name extension (2.5.29.18) is missing")
	}
	for _, forbidden := range []string{"2.5.29.33", "2.5.29.30", "2.5.29.36", "2.5.29.54", "2.5.29.46"} {
		if _, ok := findExtension(iaca, forbidden); ok {
			t.Errorf("forbidden extension %s is present", forbidden)
		}
	}

	// Self-signed: subject == issuer, and the self-signature verifies.
	if iaca.Subject.String() != iaca.Issuer.String() {
		t.Errorf("subject %q != issuer %q, want a self-signed root", iaca.Subject, iaca.Issuer)
	}
	if err := iaca.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
}

// TestGenerateMdocDocumentSigner_MeetsAnnexBTableB3 mirrors
// ValidateMdocDsCertificateProfile/ValidateMdocDsCertificateKeyUsage's
// own checks.
func TestGenerateMdocDocumentSigner_MeetsAnnexBTableB3(t *testing.T) {
	iaca, ds := generateTestCerts(t)

	if ds.Version != 3 {
		t.Errorf("Version = %d, want 3", ds.Version)
	}
	if days := ds.NotAfter.Sub(ds.NotBefore).Hours() / 24; days > 457 {
		t.Errorf("validity period is %.0f days, want <=457", days)
	}
	if ds.IsCA || ds.BasicConstraintsValid {
		t.Error("document signer certificate must not carry basicConstraints with cA=true")
	}
	if ds.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want exactly KeyUsageDigitalSignature", ds.KeyUsage)
	}
	if len(ds.SubjectKeyId) != 20 {
		t.Errorf("SubjectKeyId is %d bytes, want 20", len(ds.SubjectKeyId))
	}
	if string(ds.AuthorityKeyId) != string(iaca.SubjectKeyId) {
		t.Error("AuthorityKeyId does not match the IACA's own SubjectKeyId")
	}
	if ds.Issuer.String() != iaca.Subject.String() {
		t.Errorf("issuer %q does not match the IACA's own subject %q", ds.Issuer, iaca.Subject)
	}
	if len(ds.CRLDistributionPoints) != 1 {
		t.Errorf("CRLDistributionPoints has %d entries, want exactly 1", len(ds.CRLDistributionPoints))
	}
	if len(ds.UnknownExtKeyUsage) != 1 || ds.UnknownExtKeyUsage[0].String() != "1.0.18013.5.1.2" {
		t.Errorf("UnknownExtKeyUsage = %v, want exactly [1.0.18013.5.1.2] (mdlDS)", ds.UnknownExtKeyUsage)
	}
	if len(ds.ExtKeyUsage) != 0 {
		t.Errorf("ExtKeyUsage = %v, want none (only the custom mdlDS OID)", ds.ExtKeyUsage)
	}

	// Critical extensions: only keyUsage(2.5.29.15) and
	// extKeyUsage(2.5.29.37) may be critical.
	for _, ext := range ds.Extensions {
		id := ext.Id.String()
		wantCritical := id == "2.5.29.15" || id == "2.5.29.37"
		if ext.Critical != wantCritical {
			t.Errorf("extension %s: Critical = %v, want %v", id, ext.Critical, wantCritical)
		}
	}
	if _, ok := findExtension(ds, "2.5.29.35"); !ok {
		t.Error("authority key identifier extension (2.5.29.35) is missing")
	}
	if _, ok := findExtension(ds, "2.5.29.31"); !ok {
		t.Error("CRL distribution points extension (2.5.29.31) is missing")
	}
	if _, ok := findExtension(ds, "2.5.29.18"); !ok {
		t.Error("issuer alternative name extension (2.5.29.18) is missing")
	}
	for _, forbidden := range []string{"2.5.29.33", "2.5.29.30", "2.5.29.36", "2.5.29.54", "2.5.29.46"} {
		if _, ok := findExtension(ds, forbidden); ok {
			t.Errorf("forbidden extension %s is present", forbidden)
		}
	}

	// Chain verification: the DS cert's own signature must verify
	// against the IACA.
	if err := ds.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("document signer certificate signature does not verify against the IACA: %v", err)
	}
}
