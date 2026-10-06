package proximity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
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
	ca, caKey := testIACA(t)
	ds, dsKey := testDocumentSigner(t, ca, caKey)
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
	ca, caKey := testIACA(t)
	ds, dsKey := testDocumentSigner(t, ca, caKey)
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
	ca, caKey := testIACA(t)
	cert, key := testDocumentSigner(t, ca, caKey, ekus...)
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

// By default an OCSP signer, or a certificate whose key usage doesn't
// allow digital signatures, doesn't sign mdocs; AnyDocumentSigner turns
// the check off.
func TestDefaultDocumentSignerPolicy(t *testing.T) {
	ds := &x509.Certificate{}
	if err := DefaultDocumentSignerPolicy(ds, nil); err != nil {
		t.Errorf("no extensions: %v", err)
	}
	ds = &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
	if err := DefaultDocumentSignerPolicy(ds, nil); err == nil {
		t.Error("an OCSP signer was accepted")
	}
	ds = &x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}
	if err := DefaultDocumentSignerPolicy(ds, nil); err == nil {
		t.Error("a key usage without digitalSignature was accepted")
	}
	if err := AnyDocumentSigner(ds, nil); err != nil {
		t.Errorf("AnyDocumentSigner: %v", err)
	}
}

func TestMaxReaderClockSkew(t *testing.T) {
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReaderSession(holder.QRCode(), WithMaxClockSkew(MaxReaderClockSkew+time.Second)); err == nil {
		t.Error("a skew allowance over the maximum was accepted")
	}
	if _, err := NewReaderSession(holder.QRCode(), WithMaxClockSkew(MaxReaderClockSkew)); err != nil {
		t.Errorf("the maximum: %v", err)
	}
}
