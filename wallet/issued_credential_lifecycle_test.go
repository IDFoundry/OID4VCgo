package wallet_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// The issuer's certificate is checked at Params.Now, as the credential
// is, and against IssuerLeafPolicy when one is set.
func TestVerifyIssuedCredential_CertificateTimeAndPolicy(t *testing.T) {
	ca, caKey := testcert.CA(t, "issued credential test CA")
	leaf, leafKey := testcert.Leaf(t, "issued credential test issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := newIssuedFixture(t, leaf, leafKey, roots)
	refuse := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("not an issuer's certificate") }
	for format, c := range f.byFormat() {
		p := wallet.VerifyIssuedCredentialParams{Configuration: c.conf, Credential: c.credential, HolderKey: &f.holder.PublicKey, IssuerRoots: f.roots}
		p.Now = leaf.NotBefore.Add(-time.Hour)
		if _, err := wallet.VerifyIssuedCredential(context.Background(), p); err == nil {
			t.Errorf("%s: accepted at a time before the issuer's certificate is valid", format)
		}
		p.Now, p.IssuerLeafPolicy = time.Time{}, refuse
		if _, err := wallet.VerifyIssuedCredential(context.Background(), p); err == nil {
			t.Errorf("%s: accepted a certificate IssuerLeafPolicy refused", format)
		}
	}
}

// A status claim using another mechanism than a status list is no
// reason to refuse the credential: only status_list is read. Its status
// is unknown, though, not absent (UnrecognizedStatus).
func TestVerifyIssuedCredential_OtherStatusMechanism(t *testing.T) {
	ca, caKey := testcert.CA(t, "issued credential test CA")
	leaf, leafKey := testcert.Leaf(t, "issued credential test issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := newIssuedFixture(t, leaf, leafKey, roots)
	holderJWK, err := jwk.Marshal(&f.holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: issuedVCT, Exp: &exp, CNF: map[string]any{"jwk": holderJWK},
		Status: map[string]any{"example_mechanism": map[string]any{"uri": "https://status.example/1"}},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	got, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
		Configuration: f.sdjwtConf, Credential: credential, HolderKey: &f.holder.PublicKey, IssuerRoots: roots,
	})
	if err != nil || got.StatusList != nil || !got.UnrecognizedStatus {
		t.Errorf("VerifyIssuedCredential = %+v (unrecognized %v), %v; want accepted with no status list and an unrecognized status", got.StatusList, got.UnrecognizedStatus, err)
	}
}
