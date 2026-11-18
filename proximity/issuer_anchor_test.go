package proximity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// signedMDL is an mDL signed with dsKey, presenting ds.
func signedMDL(t *testing.T, ds *x509.Certificate, dsKey *ecdsa.PrivateKey) fixture {
	t.Helper()
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := time.Now().Add(-time.Minute)
	issuerSigned, err := mdoc.Issue(dsKey, cose.ES256, mdoc.Claims{
		DocType:    mDL,
		NameSpaces: map[string]map[string]interface{}{mDLNS: {"given_name": "Mallory", "family_name": "Forged"}},
		DeviceKey:  &deviceKey.PublicKey, Signed: signed, ValidFrom: signed, ValidUntil: signed.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	return fixture{docType: mDL, issuerSigned: issuerSigned, deviceKey: deviceKey}
}

// Two trusted IACAs share a subject name, as each operator chooses its
// own. The one trusted for a loyalty doctype issues a document signer
// naming the mDL IACA as its issuer, by name and authority key
// identifier, and signs an mDL with it. A WithIssuerAuthorization hook
// deciding by IssuerAnchor refuses it, at either assurance level; the
// mDL IACA's own mDL passes.
func TestVerify_IssuerAuthorizationByAnchor(t *testing.T) {
	const loyaltyDocType = "org.example.loyalty.1"
	shared := pkix.Name{CommonName: "Ecosystem IACA", Organization: []string{"Example Authority"}, Country: []string{"SG"}}
	mdlIACA, mdlKey := testCert(t, shared, nil, nil, true, nil)
	loyaltyIACA, loyaltyKey := testCert(t, shared, nil, nil, true, nil)

	spoofParent := *loyaltyIACA
	spoofParent.SubjectKeyId = mdlIACA.SubjectKeyId
	forgedDS, forgedKey := testDocumentSigner(t, &spoofParent, loyaltyKey, MDLDocumentSignerEKU)
	if !bytes.Equal(forgedDS.RawIssuer, mdlIACA.RawSubject) || !bytes.Equal(forgedDS.AuthorityKeyId, mdlIACA.SubjectKeyId) {
		t.Fatal("the forged document signer doesn't name the mDL IACA")
	}
	forged := signedMDL(t, forgedDS, forgedKey)
	genuineDS, genuineKey := testDocumentSigner(t, mdlIACA, mdlKey, MDLDocumentSignerEKU)
	genuine := signedMDL(t, genuineDS, genuineKey)

	roots := x509.NewCertPool()
	roots.AddCert(mdlIACA)
	roots.AddCert(loyaltyIACA)
	anchorFor := map[string]*x509.Certificate{mDL: mdlIACA, loyaltyDocType: loyaltyIACA}
	authorized := func(_ context.Context, a verifier.IssuerAuthorization) error {
		for _, typ := range a.MatchedTypes {
			if anchor := anchorFor[typ]; anchor == nil || !verifier.AnchorIs(a.IssuerAnchor, anchor) {
				return errors.New("the issuer's IACA isn't authorized for " + typ)
			}
		}
		return nil
	}
	elements := map[string][]string{mDLNS: {"given_name", "family_name"}}
	for name, opts := range map[string][]ReaderOption{
		"development": {WithIssuerAuthorization(authorized)},
		"production":  {WithAssurance(verifier.AssuranceProduction), WithNoStatusCheck(), WithIssuerAuthorization(authorized)},
	} {
		t.Run(name, func(t *testing.T) {
			f := establishReader(t, mDL, elements, opts...)
			v, err := f.reader.Verify(context.Background(), f.respond(t, genuine, f.req.Elements), roots, time.Now())
			if err != nil {
				t.Fatalf("the mDL IACA's own mDL: %v", err)
			}
			if !bytes.Equal(v.Credential().IssuerAnchor, mdlIACA.Raw) {
				t.Error("Verified.Credential().IssuerAnchor isn't the mDL IACA")
			}
			f = establishReader(t, mDL, elements, opts...)
			if _, err := f.reader.Verify(context.Background(), f.respond(t, forged, f.req.Elements), roots, time.Now()); err == nil || !strings.Contains(err.Error(), "issuer authorization") {
				t.Fatalf("the loyalty IACA's mDL: %v, want refused by issuer authorization", err)
			}
		})
	}
}
