package mdoc_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// An OCSP signer, a certificate whose key usage doesn't allow digital
// signatures, or one whose extended key usage leaves out the mDL
// document signer's (a reader authentication certificate's, say),
// doesn't sign mdocs. By default neither does one without an extended
// key usage (a revocation list signer's, say, which ISO/IEC 18013-5
// Annex B.1.7 lets go without), which LenientDocumentSignerPolicy
// accepts.
func TestDefaultDocumentSignerPolicy(t *testing.T) {
	readerAuth := asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
	for name, tc := range map[string]struct {
		cert          *x509.Certificate
		ok, lenientOK bool
	}{
		"no extensions":           {&x509.Certificate{}, false, true},
		"digitalSignature":        {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}, false, true},
		"OCSP signer":             {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}, false, false},
		"OCSP signer, no KU":      {&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}, false, false},
		"KU without digitalSig":   {&x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}, false, false},
		"CRL signer KU":           {&x509.Certificate{KeyUsage: x509.KeyUsageCRLSign}, false, false},
		"another EKU with digSig": {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, false, false},
		"reader authentication":   {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{readerAuth}}, false, false},
		"mDL document signer":     {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}, true, true},
		"mDL DS and another EKU": {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}, true, true},
		"mDL DS and OCSP signer": {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}, false, false},
	} {
		if err := mdoc.DefaultDocumentSignerPolicy(tc.cert, nil); tc.ok != (err == nil) {
			t.Errorf("%s: %v, want ok %v", name, err, tc.ok)
		}
		if err := mdoc.LenientDocumentSignerPolicy(tc.cert, nil); tc.lenientOK != (err == nil) {
			t.Errorf("%s, lenient: %v, want ok %v", name, err, tc.lenientOK)
		}
	}
}

// DefaultDocumentSignerPolicy refuses a document signer whose every
// path runs through an intermediate CA whose extended key usage leaves
// out the mDL document signer's.
func TestDefaultDocumentSignerPolicy_Intermediate(t *testing.T) {
	ds := &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}
	root := &x509.Certificate{IsCA: true}
	ekuExtension := func(oid asn1.ObjectIdentifier) []byte {
		der, err := asn1.Marshal([]asn1.ObjectIdentifier{oid})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	readerCA := &x509.Certificate{IsCA: true, Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: ekuExtension(asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6})}}}
	if err := mdoc.DefaultDocumentSignerPolicy(ds, [][]*x509.Certificate{{ds, readerCA, root}}); err == nil {
		t.Error("a document signer under a reader-only CA was accepted")
	}
	if err := mdoc.DefaultDocumentSignerPolicy(ds, [][]*x509.Certificate{{ds, readerCA, root}, {ds, root}}); err != nil {
		t.Errorf("a document signer with a path directly under the root: %v", err)
	}
}
