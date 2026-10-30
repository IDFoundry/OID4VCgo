package certchain

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
)

// LeafRole refuses another role's certificates: in Strict mode one
// whose extended key usage lists any other role's purpose, otherwise
// one that lists nothing else.
func TestLeafRole(t *testing.T) {
	private := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	ds := x509.KeyUsageDigitalSignature
	lenient := LeafRole{Name: "the certificate", OtherISOEKUs: []asn1.ObjectIdentifier{ReaderAuthenticationEKU}}
	strict := LeafRole{Name: "the certificate", OtherISOEKUs: []asn1.ObjectIdentifier{MDLDocumentSignerEKU, ReaderAuthenticationEKU}, Strict: true}
	for name, tc := range map[string]struct {
		cert                 *x509.Certificate
		lenientOK, strictOK  bool
		wantInLenientRefusal string
	}{
		"no extensions":          {&x509.Certificate{}, true, true, ""},
		"digitalSignature":       {&x509.Certificate{KeyUsage: ds}, true, true, ""},
		"no digitalSignature":    {&x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}, false, false, "digital signatures"},
		"OCSP signer":            {&x509.Certificate{KeyUsage: ds, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}, false, false, "OCSP"},
		"TLS server":             {&x509.Certificate{KeyUsage: ds, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, false, false, "only other roles"},
		"TLS client and private": {&x509.Certificate{KeyUsage: ds, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{private}}, true, false, ""},
		"any purpose":            {&x509.Certificate{KeyUsage: ds, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}, true, true, ""},
		"private purpose":        {&x509.Certificate{KeyUsage: ds, UnknownExtKeyUsage: []asn1.ObjectIdentifier{private}}, true, true, ""},
		"mdoc reader":            {&x509.Certificate{KeyUsage: ds, UnknownExtKeyUsage: []asn1.ObjectIdentifier{ReaderAuthenticationEKU}}, false, false, "mdoc reader authentication"},
		"mDL document signer":    {&x509.Certificate{KeyUsage: ds, UnknownExtKeyUsage: []asn1.ObjectIdentifier{MDLDocumentSignerEKU}}, true, false, ""},
	} {
		err := lenient.Check(tc.cert, nil)
		if tc.lenientOK != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantInLenientRefusal)) {
			t.Errorf("%s: lenient: %v, want ok %v", name, err, tc.lenientOK)
		}
		if err := strict.Check(tc.cert, nil); tc.strictOK != (err == nil) {
			t.Errorf("%s: strict: %v, want ok %v", name, err, tc.strictOK)
		}
	}
	if err := strict.Check(nil, nil); err == nil {
		t.Error("no leaf accepted")
	}

	leaf := &x509.Certificate{KeyUsage: ds}
	root := &x509.Certificate{IsCA: true}
	tlsCA := &x509.Certificate{IsCA: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	readerCA := &x509.Certificate{IsCA: true, UnknownExtKeyUsage: []asn1.ObjectIdentifier{ReaderAuthenticationEKU}}
	for _, ca := range []*x509.Certificate{tlsCA, readerCA} {
		if err := strict.Check(leaf, [][]*x509.Certificate{{leaf, ca, root}}); err == nil {
			t.Error("a leaf under an intermediate restricted to another role was accepted")
		}
		if err := strict.Check(leaf, [][]*x509.Certificate{{leaf, ca, root}, {leaf, root}}); err != nil {
			t.Errorf("a leaf with a path directly under the root: %v", err)
		}
	}
}

// CheckSigningLeaf names the certificate it refuses.
func TestCheckSigningLeaf(t *testing.T) {
	err := CheckSigningLeaf("the registrar certificate", &x509.Certificate{KeyUsage: x509.KeyUsageCRLSign})
	if err == nil || !strings.HasPrefix(err.Error(), "the registrar certificate") {
		t.Errorf("CheckSigningLeaf = %v", err)
	}
}
