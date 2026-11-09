package proximity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// misusedDocumentSigners are certificates an IACA issued that carry the
// mDL document signer's extended key usage but can't be a document
// signer's: one whose key usage doesn't allow digital signatures, and
// an OCSP signer's.
func misusedDocumentSigners(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) map[string]struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
} {
	t.Helper()
	out := map[string]struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}{}
	for name, tmpl := range map[string]x509.Certificate{
		"key usage without digitalSignature": {KeyUsage: x509.KeyUsageCertSign},
		"an OCSP signer's": {
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		},
	} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SerialNumber, tmpl.Subject = big.NewInt(time.Now().UnixNano()), pkix.Name{CommonName: name, Country: []string{"SG"}}
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{MDLDocumentSignerEKU}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = struct {
			cert *x509.Certificate
			key  *ecdsa.PrivateKey
		}{cert, key}
	}
	return out
}

// RequireMDLDocumentSignerEKU accepts nothing the default refuses: a
// certificate carrying the mDL document signer's extended key usage is
// still refused when it's an OCSP signer's, with the policy as without
// it. (One whose key usage doesn't allow signing is refused before any
// policy runs.)
func TestRequireMDLDocumentSignerEKU_NoLooserThanDefault(t *testing.T) {
	age := map[string][]string{mDLNS: {"age_over_18"}}
	ageOnly := [][2]string{{mDLNS, "age_over_18"}}
	ca, caKey := testIACA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for name, ds := range misusedDocumentSigners(t, ca, caKey) {
		for policy, opts := range map[string][]ReaderOption{
			"default":                     nil,
			"RequireMDLDocumentSignerEKU": {WithDocumentSignerPolicy(RequireMDLDocumentSignerEKU)},
		} {
			fx := issueWith(t, issueFixture(t, mDL), ds.key, ds.cert, nil)
			fx.roots = roots
			f := establishReader(t, mDL, age, opts...)
			_, err := f.reader.Verify(context.Background(), f.respond(t, fx, ageOnly), fx.roots, time.Now())
			if err == nil {
				t.Errorf("%s, %s policy: Verify accepted it", name, policy)
			}
		}
	}
}
