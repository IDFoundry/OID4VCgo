package mdocdcapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An org-iso-mdoc exchange whose IACA, document signer and device key
// are on P-384 and P-521 — and whose request a P-384 or P-521 reader
// signs — verifies at both ends: the wallet trusts the reader, and the
// reader's VerifyResponse, resolving the issuer key by its chain,
// verifies IssuerAuth with ES384 or ES512 and the device signature
// with its key's algorithm. The Annex C HPKE suite stays DHKEM(P-256).
func TestExchangeNISTCurves(t *testing.T) {
	const (
		origin  = "https://shop.example"
		docType = "org.iso.18013.5.1.mDL"
		ns      = "org.iso.18013.5.1"
	)
	for _, tc := range []struct {
		name                       string
		iaca, signer, device, read elliptic.Curve
		alg                        oid4vci.COSEAlg
	}{
		{"P-384", elliptic.P384(), elliptic.P384(), elliptic.P384(), elliptic.P384(), oid4vci.COSEES384},
		{"P-521", elliptic.P521(), elliptic.P521(), elliptic.P521(), elliptic.P521(), oid4vci.COSEES512},
		{"mixed", elliptic.P256(), elliptic.P384(), elliptic.P521(), elliptic.P521(), oid4vci.COSEES384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iaca, iacaKey := newCertOn(tc.iaca, &x509.Certificate{
				Subject: pkix.Name{CommonName: "Test IACA", Country: []string{"US"}}, IsCA: true, BasicConstraintsValid: true,
				KeyUsage: x509.KeyUsageCertSign,
			}, nil, nil)
			ds, dsKey := newCertOn(tc.signer, &x509.Certificate{
				Subject: pkix.Name{CommonName: "Test Document Signer", Country: []string{"US"}}, KeyUsage: x509.KeyUsageDigitalSignature,
				UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU},
			}, iaca, iacaKey)
			readerCA, readerCAKey := newCA("Test Reader CA")
			readerCert, readerKey := newCertOn(tc.read, &x509.Certificate{
				Subject: pkix.Name{CommonName: "Test Reader"}, KeyUsage: x509.KeyUsageDigitalSignature,
				UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdocdcapi.ReaderAuthenticationEKU},
			}, readerCA, readerCAKey)
			deviceKey, err := ecdsa.GenerateKey(tc.device, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			issuerSigned, err := mdoc.Issue(dsKey, tc.alg, mdoc.Claims{
				DocType: docType, NameSpaces: map[string]map[string]any{ns: {"age_over_18": true}}, DeviceKey: &deviceKey.PublicKey,
				Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
			}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
			if err != nil {
				t.Fatal(err)
			}
			req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
				Origin: origin, DocType: docType, Elements: map[string]map[string]bool{ns: {"age_over_18": false}},
				Readers: []mdocdcapi.ReaderKey{{Signer: readerKey, Chain: []*x509.Certificate{readerCert, readerCA}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(req.Data)
			if err != nil {
				t.Fatal(err)
			}
			in, err := mdocdcapi.ParseRequest(data, origin)
			if err != nil {
				t.Fatal(err)
			}
			readerRoots := x509.NewCertPool()
			readerRoots.AddCert(readerCA)
			if leaf, err := in.VerifyReader(readerRoots, time.Time{}); err != nil || !leaf.Equal(readerCert) {
				t.Fatalf("VerifyReader: %v", err)
			}
			encrypted, err := in.Respond(0, issuerSigned, deviceKey, [][2]string{{ns, "age_over_18"}})
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(iaca)
			got, err := mdocdcapi.VerifyResponse(context.Background(), mdocdcapi.VerifyParams{
				Pending: req.Pending, Response: base64.RawURLEncoding.EncodeToString(encrypted),
				IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}},
				Origins:    []string{origin}, Assurance: verifier.AssuranceDevelopment,
			})
			if err != nil {
				t.Fatalf("VerifyResponse: %v", err)
			}
			if got.NameSpaces[ns]["age_over_18"] != true {
				t.Errorf("Verified = %+v", got)
			}
		})
	}
}
