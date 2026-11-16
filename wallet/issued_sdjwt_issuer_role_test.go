package wallet_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Without IssuerLeafPolicy, a received SD-JWT VC's issuer certificate
// is held to the check verifier.X5CIssuerKeyResolver makes by default
// (verifier.DefaultSDJWTIssuerLeafPolicy): a certificate under
// IssuerRoots whose key usage denotes another role, such as a TLS
// server's, is refused, as a Verifier would refuse it.
// verifier.AnyIssuerLeaf opts out.
func TestVerifyIssuedCredential_SDJWTDefaultIssuerRole(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer role test CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(tmpl *x509.Certificate) issuedFixture {
		tmpl.Subject = pkix.Name{CommonName: "issuer role test leaf"}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		leaf, leafKey := testcert.Issue(t, tmpl, ca, caKey)
		return newIssuedFixture(t, leaf, leafKey, roots)
	}
	verify := func(f issuedFixture, policy func(*x509.Certificate, [][]*x509.Certificate) error) error {
		_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: f.sdjwtConf, Credential: f.sdjwt, HolderKey: &f.holder.PublicKey,
			IssuerRoots: f.roots, IssuerLeafPolicy: policy,
		})
		return err
	}

	refused := map[string]*x509.Certificate{
		"TLS server only":      {ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		"TLS client only":      {ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		"mdoc reader auth EKU": {UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 6}}},
	}
	for name, tmpl := range refused {
		f := issue(tmpl)
		err := verify(f, nil)
		if err == nil {
			t.Errorf("%s: accepted with no IssuerLeafPolicy", name)
		} else if !strings.Contains(err.Error(), "issuer certificate") {
			t.Errorf("%s: error = %v, want it to name the issuer certificate", name, err)
		}
		if err := verify(f, verifier.DefaultSDJWTIssuerLeafPolicy); err == nil {
			t.Errorf("%s: accepted under verifier.DefaultSDJWTIssuerLeafPolicy", name)
		}
		if err := verify(f, verifier.AnyIssuerLeaf); err != nil {
			t.Errorf("%s: refused under verifier.AnyIssuerLeaf, the explicit opt-out: %v", name, err)
		}
	}

	accepted := map[string]*x509.Certificate{
		"no extended key usage":     {},
		"a private issuer EKU":      {UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}},
		"the mDL document signer's": {UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}},
		"anyExtendedKeyUsage":       {ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
	}
	for name, tmpl := range accepted {
		if err := verify(issue(tmpl), nil); err != nil {
			t.Errorf("%s: refused with no IssuerLeafPolicy: %v", name, err)
		}
	}
}
