package proximity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// issueWith issues the fixture's claims signed by dsKey, with ds as the
// x5chain's document signer and status as the MSO's status list
// reference.
func issueWith(t *testing.T, fx fixture, dsKey *ecdsa.PrivateKey, ds *x509.Certificate, status *mdoc.StatusListRef) fixture {
	t.Helper()
	signed := time.Now().Add(-time.Minute)
	issuerSigned, err := mdoc.Issue(dsKey, cose.ES256, mdoc.Claims{
		DocType:    fx.docType,
		NameSpaces: map[string]map[string]interface{}{mDLNS: {"age_over_18": true}},
		DeviceKey:  &fx.deviceKey.PublicKey,
		Signed:     signed, ValidFrom: signed, ValidUntil: signed.Add(time.Hour),
		Status: status,
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	fx.issuerSigned = issuerSigned
	return fx
}

// Verified carries the MSO's status list reference for the reader to
// check revocation with.
func TestVerifiedCarriesStatus(t *testing.T) {
	ca, caKey := testcert.CA(t, "Test IACA")
	ds, dsKey := testcert.Leaf(t, "Test Document Signer", ca, caKey)
	fx := issueFixture(t, mDL)
	fx.roots = x509.NewCertPool()
	fx.roots.AddCert(ca)
	ref := &mdoc.StatusListRef{Idx: 7, URI: "https://issuer.example/status/1"}
	fx = issueWith(t, fx, dsKey, ds, ref)

	f := establish(t, mDL, map[string][]string{mDLNS: {"age_over_18"}})
	v, err := f.reader.Verify(f.respond(t, fx, f.req.Elements), fx.roots, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Status == nil || v.Status.StatusList == nil || v.Status.StatusList.Idx != ref.Idx || v.Status.StatusList.URI != ref.URI {
		t.Errorf("Status = %+v, want %+v", v.Status, ref)
	}
}

// keyAlg, which Verify takes the issuer algorithm from — the verified
// document signer certificate's key, never IssuerAuth's own header —
// maps the keys credential/mdoc supports and refuses others.
func TestKeyAlg(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if alg, err := keyAlg(&p256.PublicKey); err != nil || alg != cose.ES256 {
		t.Errorf("P-256: %v, %v", alg, err)
	}
	if alg, err := keyAlg(edPub); err != nil || alg != cose.EdDSA {
		t.Errorf("Ed25519: %v, %v", alg, err)
	}
	if _, err := keyAlg(&p384.PublicKey); err == nil {
		t.Error("P-384 was given an algorithm")
	}
}

// issueValidFrom issues the fixture's claims with validFrom from — a
// reader whose clock runs behind the issuer's sees it in the future.
func issueValidFrom(t *testing.T, fx fixture, from time.Time) fixture {
	t.Helper()
	ca, caKey := testcert.CA(t, "Test IACA")
	ds, dsKey := testcert.Leaf(t, "Test Document Signer", ca, caKey)
	issuerSigned, err := mdoc.Issue(dsKey, cose.ES256, mdoc.Claims{
		DocType:    fx.docType,
		NameSpaces: map[string]map[string]interface{}{mDLNS: {"age_over_18": true}},
		DeviceKey:  &fx.deviceKey.PublicKey,
		Signed:     from, ValidFrom: from, ValidUntil: from.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	fx.issuerSigned = issuerSigned
	fx.roots = x509.NewCertPool()
	fx.roots.AddCert(ca)
	return fx
}

// An mdoc issued by a clock 30 seconds ahead is refused as not yet
// valid, unless the reader tolerates that skew.
func TestWithMaxClockSkew(t *testing.T) {
	fx := issueValidFrom(t, issueFixture(t, mDL), time.Now().Add(30*time.Second))
	age := map[string][]string{mDLNS: {"age_over_18"}}
	ageOnly := [][2]string{{mDLNS, "age_over_18"}}

	f := establish(t, mDL, age)
	if _, err := f.reader.Verify(f.respond(t, fx, ageOnly), fx.roots, time.Now()); err == nil {
		t.Error("an MSO valid from 30s from now verified without a skew allowance")
	}
	f = establishReader(t, mDL, age, WithMaxClockSkew(time.Minute))
	if _, err := f.reader.Verify(f.respond(t, fx, ageOnly), fx.roots, time.Now()); err != nil {
		t.Errorf("with a minute's skew allowed: %v", err)
	}
}

// documentSigner is a document signer certificate, under its own IACA,
// with the extended key usages ekus.
func documentSigner(t *testing.T, ekus ...asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	ca, caKey := testcert.CA(t, "Test IACA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "Test Document Signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return cert, key, roots
}

func TestRequireMDLDocumentSignerEKU(t *testing.T) {
	age := map[string][]string{mDLNS: {"age_over_18"}}
	ageOnly := [][2]string{{mDLNS, "age_over_18"}}
	for name, tc := range map[string]struct {
		ekus []asn1.ObjectIdentifier
		ok   bool
	}{
		"mDL document signer EKU": {[]asn1.ObjectIdentifier{MDLDocumentSignerEKU}, true},
		"another EKU":             {[]asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 6}}, false},
		"no EKU":                  {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			ds, dsKey, roots := documentSigner(t, tc.ekus...)
			fx := issueWith(t, issueFixture(t, mDL), dsKey, ds, nil)
			fx.roots = roots
			f := establishReader(t, mDL, age, WithDocumentSignerPolicy(RequireMDLDocumentSignerEKU))
			_, err := f.reader.Verify(f.respond(t, fx, ageOnly), fx.roots, time.Now())
			if tc.ok != (err == nil) {
				t.Errorf("Verify = %v, want ok %v", err, tc.ok)
			}
		})
	}
}
