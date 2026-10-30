package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// An issued mdoc gets the document signer checks a verifier makes
// (mdoc.CheckDocumentSigner): a document signer naming another country
// than its IACA, or an mDL whose issuing_country isn't its signer's,
// is refused on receipt, not stored to be refused when presented.
func TestVerifyIssuedCredential_MdocDocumentSignerChecks(t *testing.T) {
	iaca, iacaKey := testcert.CAWithSubject(t, pkix.Name{CommonName: "IACA", Country: []string{"SG"}})
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conf := oid4vci.CredentialConfigurationMetadata{Format: mdoc.CredentialFormat, DocType: issuedDocType, CryptographicBindingMethodsSupported: []string{"cose_key"}}
	issue := func(dsCountry, issuingCountry string) string {
		ds, dsKey := testcert.Issue(t, &x509.Certificate{
			Subject:            pkix.Name{CommonName: "document signer", Country: []string{dsCountry}},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU},
		}, iaca, iacaKey)
		now := time.Now()
		signed, err := mdoc.Issue(dsKey, cose.ES256, mdoc.Claims{
			DocType:    issuedDocType,
			NameSpaces: map[string]map[string]interface{}{mdoc.MDLNameSpace: {"given_name": "Alice", "issuing_country": issuingCountry}},
			DeviceKey:  &holder.PublicKey,
			Signed:     now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
		}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := signed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	verify := func(credential string) error {
		_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: conf, Credential: credential, HolderKey: &holder.PublicKey, IssuerRoots: roots,
		})
		return err
	}
	if err := verify(issue("SG", "SG")); err != nil {
		t.Fatalf("a consistent mDL: %v", err)
	}
	for name, c := range map[string]struct{ dsCountry, issuingCountry, want string }{
		"a document signer of another country": {"DE", "DE", "countryName"},
		"another issuing_country":              {"SG", "DE", "issuing_country"},
	} {
		if err := verify(issue(c.dsCountry, c.issuingCountry)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it refused over %s", name, err, c.want)
		}
	}
}
