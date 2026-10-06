package proximity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
