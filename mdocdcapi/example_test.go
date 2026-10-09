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
	"fmt"
	"math/big"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// The whole org-iso-mdoc exchange over the Digital Credentials API: the
// page builds a signed request, the wallet checks who signed it and
// answers with the one element the holder agreed to, and the page
// verifies the answer. Here both sides run in one process; in a real
// deployment the request goes to navigator.credentials.get and the
// response comes back from it.
func ExampleBuildRequest() {
	const (
		origin  = "https://shop.example"
		docType = "org.iso.18013.5.1.mDL"
		ns      = "org.iso.18013.5.1"
	)

	// An issuer (IACA → document signer) and the mDL it issued to a
	// holder's device key.
	iaca, iacaKey := newCA("Example IACA")
	ds, dsKey := newLeaf("Example Document Signer", iaca, iacaKey)
	deviceKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	now := time.Now()
	issuerSigned := must(mdoc.Issue(dsKey, oid4vci.COSEES256, mdoc.Claims{
		DocType:    docType,
		NameSpaces: map[string]map[string]any{ns: {"given_name": "Alice", "age_over_18": true}},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}}))

	// A reader certificate, with the reader authentication EKU, under a
	// reader CA the wallet trusts.
	readerCA, readerCAKey := newCA("Example Reader CA")
	readerCert, readerKey := newLeaf("Example Shop", readerCA, readerCAKey, mdocdcapi.ReaderAuthenticationEKU)

	// Page (server side): build the request. Keep req.Pending for the
	// response; send req.Data to the page as the request's data.
	req := must(mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin:   origin,
		DocType:  docType,
		Elements: map[string]map[string]bool{ns: {"age_over_18": false}}, // false: not retained
		Readers:  []mdocdcapi.ReaderKey{{Signer: readerKey, Chain: []*x509.Certificate{readerCert, readerCA}}},
	}))
	data := must(json.Marshal(req.Data))

	// Wallet: parse the request with the origin the platform reports,
	// and check the reader's certificate before showing the request.
	in := must(mdocdcapi.ParseRequest(data, origin))
	readerRoots := x509.NewCertPool()
	readerRoots.AddCert(readerCA)
	reader := must(in.VerifyReaderTrust(mdocdcapi.ReaderTrust{
		Roots:      readerRoots,
		LeafPolicy: mdocdcapi.RequireReaderAuthenticationEKU,
		Now:        time.Now(),
	}))
	fmt.Println("reader:", reader.Subject.CommonName)

	// Wallet: answer with what the holder consented to.
	encrypted := must(in.Respond(0, issuerSigned, deviceKey, [][2]string{{ns, "age_over_18"}}))

	// Page (server side): verify the response the page posted back,
	// trusting documents signed under the IACA.
	iacaRoots := x509.NewCertPool()
	iacaRoots.AddCert(iaca)
	verified := must(mdocdcapi.VerifyResponse(context.Background(), mdocdcapi.VerifyParams{
		Pending:    req.Pending,
		Response:   base64.RawURLEncoding.EncodeToString(encrypted),
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: iacaRoots},
	}))
	fmt.Println("docType:", verified.DocType)
	fmt.Println("age_over_18:", verified.NameSpaces[ns]["age_over_18"])
	// Output:
	// reader: Example Shop
	// docType: org.iso.18013.5.1.mDL
	// age_over_18: true
}

// newCA is a throwaway P-256 CA certificate valid for a day.
func newCA(name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	return newCert(&x509.Certificate{
		Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
}

// newLeaf is a throwaway P-256 end-entity certificate under ca, with
// the extended key usages ekus.
func newLeaf(name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ekus ...asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	return newCert(&x509.Certificate{
		Subject: pkix.Name{CommonName: name}, KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: ekus,
	}, ca, caKey)
}

// newCert signs tmpl for a fresh key, by parent (nil: self-signed).
func newCert(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl.SerialNumber = must(rand.Int(rand.Reader, big.NewInt(1<<62)))
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	return must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)))), key
}

// must stands in for error handling: an example has no *testing.T.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
