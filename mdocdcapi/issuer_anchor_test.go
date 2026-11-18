package mdocdcapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// anchorTestCert is a certificate for subject under parent (self-signed
// when parent is nil), signed by parentKey: a CA, or a document signer
// with ISO/IEC 18013-5's mdlDS extended key usage.
func anchorTestCert(t *testing.T, serial int64, subject pkix.Name, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: ca,
	}
	if ca {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// Two trusted roots share a subject name. The one trusted for a
// loyalty doctype issues a document signer naming the PID root as its
// issuer, by name and authority key identifier, and signs a PID with
// it. An IssuerAuthorized deciding by IssuerAnchor refuses it, at
// either assurance level; the PID root's own PID passes, with
// Verified.IssuerAnchor the PID root.
func TestVerifyResponse_IssuerAuthorizationByAnchor(t *testing.T) {
	const pidType, loyaltyType = "org.example.pid.1", "org.example.loyalty.1"
	shared := pkix.Name{CommonName: "Ecosystem Root", Country: []string{"UT"}}
	pidRoot, pidRootKey := anchorTestCert(t, 1, shared, nil, nil, true)
	loyaltyRoot, loyaltyRootKey := anchorTestCert(t, 2, shared, nil, nil, true)
	spoofParent := *loyaltyRoot
	spoofParent.SubjectKeyId = pidRoot.SubjectKeyId
	signer := pkix.Name{CommonName: "PID Document Signer", Country: []string{"UT"}}
	forgedDS, forgedKey := anchorTestCert(t, 3, signer, &spoofParent, loyaltyRootKey, false)
	if !bytes.Equal(forgedDS.RawIssuer, pidRoot.RawSubject) || !bytes.Equal(forgedDS.AuthorityKeyId, pidRoot.SubjectKeyId) {
		t.Fatal("the forged document signer doesn't name the PID root")
	}
	genuineDS, genuineKey := anchorTestCert(t, 4, signer, pidRoot, pidRootKey, false)
	pid := testmdoc.IssueWith(t, func(c *mdoc.Claims) { c.DocType = pidType })

	readerCert, readerKey := testcert.SelfSignedLeaf(t, "mdocdcapi test reader")
	req, err := BuildRequest(RequestParams{Origin: testOrigin, Documents: []DocumentRequest{{
		DocType: pidType, Elements: map[string]map[string]bool{testmdoc.Namespace: {"given_name": false}},
	}}, Readers: []ReaderKey{{Signer: readerKey, Chain: []*x509.Certificate{readerCert}}}})
	if err != nil {
		t.Fatal(err)
	}
	answer := func(f testmdoc.Fixture) string {
		data, err := json.Marshal(req.Data)
		if err != nil {
			t.Fatal(err)
		}
		incoming, err := ParseRequest(data, testOrigin)
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := incoming.RespondDocuments(context.Background(), []Answer{{
			Document: 0, IssuerSigned: f.IssuerSigned, Holder: f.DeviceKey, Elements: [][2]string{{testmdoc.Namespace, "given_name"}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encrypted)
	}
	genuine := answer(signedUnder(t, pid, genuineKey, [][]byte{genuineDS.Raw}))
	forged := answer(signedUnder(t, pid, forgedKey, [][]byte{forgedDS.Raw}))

	roots := x509.NewCertPool()
	roots.AddCert(pidRoot)
	roots.AddCert(loyaltyRoot)
	anchorFor := map[string]*x509.Certificate{pidType: pidRoot, loyaltyType: loyaltyRoot}
	authorized := func(_ context.Context, a verifier.IssuerAuthorization) error {
		if a.Claims == nil {
			t.Error("IssuerAuthorization.Claims is nil")
		}
		if anchor := anchorFor[a.Type]; anchor == nil || !verifier.AnchorIs(a.IssuerAnchor, anchor) {
			return errors.New("the issuer's root isn't authorized for " + a.Type)
		}
		return nil
	}
	for name, p := range map[string]VerifyParams{
		"development": {Assurance: verifier.AssuranceDevelopment, IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}}},
		"production":  {Assurance: verifier.AssuranceProduction, Origins: []string{testOrigin}, IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}},
	} {
		t.Run(name, func(t *testing.T) {
			p.Pending, p.IssuerAuthorized, p.NoStatusCheck = req.Pending, authorized, true
			p.Response = genuine
			got, err := VerifyResponse(context.Background(), p)
			if err != nil {
				t.Fatalf("the PID root's own PID: %v", err)
			}
			if !bytes.Equal(got.IssuerAnchor, pidRoot.Raw) || !bytes.Equal(got.Credential().IssuerAnchor, pidRoot.Raw) {
				t.Error("Verified.IssuerAnchor isn't the PID root")
			}
			p.Response = forged
			if _, err := VerifyResponse(context.Background(), p); err == nil || !strings.Contains(err.Error(), "issuer authorization") {
				t.Fatalf("the loyalty root's PID: %v, want refused by issuer authorization", err)
			}
		})
	}
}
