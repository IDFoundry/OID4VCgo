package verifier_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// A revocation list signer's certificate, which ISO/IEC 18013-5 Annex
// B.1.7 lets go without an extended key usage, can't sign mdocs that
// X5ChainIssuerKeyResolver accepts: by default a document signer needs
// the mDL document signer's (Annex B.1.4), so the list signer's online
// key isn't also a credential-forging one. mdoc.LenientDocumentSignerPolicy
// is the explicit opt-in for document signers issued without one.
func TestX5ChainIssuerKeyResolver_RefusesStatusSignerAsDocumentSigner(t *testing.T) {
	const docType = "org.iso.18013.5.1.mDL"
	iaca, iacaKey := testcert.CAWithSubject(t, pkix.Name{CommonName: "Utopia IACA", Country: []string{"UT"}})
	listSigner, listSignerKey := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Utopia revocation list signer", Country: []string{"UT"}}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, iaca, iacaKey)
	now := time.Now()
	issued, err := mdoc.Issue(listSignerKey, cose.ES256, mdoc.Claims{
		DocType:    docType,
		NameSpaces: map[string]map[string]interface{}{mdoc.MDLNameSpace: {"family_name": "Forged", "issuing_country": "UT"}},
		DeviceKey:  &listSignerKey.PublicKey, Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{listSigner.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	r := verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	if _, _, err := r.ResolveMdocIssuerKey(context.Background(), [][]byte{listSigner.Raw}, docType); err == nil || !strings.Contains(err.Error(), mdoc.MDLDocumentSignerEKU.String()) {
		t.Fatalf("ResolveMdocIssuerKey = %v, want the revocation list signer refused as a document signer", err)
	}

	r.LeafPolicy = mdoc.LenientDocumentSignerPolicy
	pub, alg, err := r.ResolveMdocIssuerKey(context.Background(), [][]byte{listSigner.Raw}, docType)
	if err != nil {
		t.Fatalf("LenientDocumentSignerPolicy: %v", err)
	}
	v, err := mdoc.Verify(issued, docType, pub, alg, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.CheckMdocIssuer(context.Background(), r, [][]byte{listSigner.Raw}, docType, pub, v); err != nil {
		t.Errorf("CheckMdocIssuer under LenientDocumentSignerPolicy: %v", err)
	}
}
