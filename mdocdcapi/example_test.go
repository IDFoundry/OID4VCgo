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

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/storage"
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
	ds, dsKey := newLeaf("Example Document Signer", iaca, iacaKey, mdoc.MDLDocumentSignerEKU)
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
		Origins:  []string{origin}, // the Verifier's own pages
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
	// trusting documents signed under the IACA, its certificates
	// checked against its current CRL. A deployment's CRLs come from a
	// certrevocation.Refresher (its Checker), fetched from the IACA's
	// distribution points and kept current by its Run; here the IACA
	// signs an empty one.
	crl := must(x509.ParseRevocationList(must(x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
	}, iaca, iacaKey))))
	revocation := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		return []*x509.RevocationList{crl}, nil
	}}
	statusCache := statuslist.NewCache(statuslist.CacheOptions{}) // one for the process
	iacaRoots := x509.NewCertPool()
	iacaRoots.AddCert(iaca)
	verified := must(mdocdcapi.VerifyResponse(context.Background(), mdocdcapi.VerifyParams{
		Pending:    req.Pending,
		Response:   base64.RawURLEncoding.EncodeToString(encrypted),
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: iacaRoots, Revocation: revocation},
		// Every issuer under the IACA may issue the doctype.
		Assurance: verifier.AssuranceProduction, AnyIssuerForAnyType: true,
		// Revocation, checked before any Accept: the document's status
		// list, signed under the IACA (the example document carries no
		// status reference, so there's nothing to fetch).
		Status: &verifier.StatusPolicy{Checker: statuslist.Checker{
			Roots: iacaRoots, Options: statuslist.VerifyOptions{Revocation: revocation}, Cache: statusCache,
		}},
		Origins: []string{origin},
	}))
	fmt.Println("docType:", verified.DocType)
	fmt.Println("age_over_18:", verified.NameSpaces[ns]["age_over_18"])
	// Output:
	// reader: Example Shop
	// docType: org.iso.18013.5.1.mDL
	// age_over_18: true
}

// The same exchange with verifier.Transactions keeping the request: its
// response decryption key stays in the Verifier's TransactionStore,
// bound to the browser that asked and the page's origin, and the
// request completes once.
func ExampleForTransactions() {
	const (
		origin  = "https://shop.example"
		docType = "org.iso.18013.5.1.mDL"
		ns      = "org.iso.18013.5.1"
		// The browser's session cookie: an unguessable random token.
		session = "a-random-session-cookie-value"
	)
	iaca, iacaKey := newCA("Example IACA")
	ds, dsKey := newLeaf("Example Document Signer", iaca, iacaKey, mdoc.MDLDocumentSignerEKU)
	deviceKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	now := time.Now()
	issuerSigned := must(mdoc.Issue(dsKey, oid4vci.COSEES256, mdoc.Claims{
		DocType:    docType,
		NameSpaces: map[string]map[string]any{ns: {"given_name": "Alice", "age_over_18": true}},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}}))
	readerCA, readerCAKey := newCA("Example Reader CA")
	readerCert, readerKey := newLeaf("Example Shop", readerCA, readerCAKey, mdocdcapi.ReaderAuthenticationEKU)

	// The Verifier, and its Transactions for the shop's pages.
	clientCert, clientKey := newLeaf("Example Shop RP", readerCA, readerCAKey)
	responseURI := must(fapi.ParseEndpointURL("https://shop.example/response"))
	v := must(verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: clientCert, ResponseURI: responseURI,
		SigningAlg: oid4vci.ES256, EncValuesSupported: []oid4vci.JWEEnc{oid4vci.A128GCM},
		VPFormatsSupported: map[string]any{"mso_mdoc": map[string]any{}},
	}, verifier.Dependencies{Signer: clientKey, Random: rand.Reader}))
	protocol := must(mdocdcapi.ForTransactions(mdocdcapi.ReaderKey{Signer: readerKey, Chain: []*x509.Certificate{readerCert, readerCA}}))
	iacaRoots := x509.NewCertPool()
	iacaRoots.AddCert(iaca)
	txs := must(verifier.NewTransactions(v, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{
		Origins: []string{origin}, MdocDCAPI: protocol,
		Verify: verifier.VerifyResponseRequest{
			MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: iacaRoots, Revocation: certrevocation.NoCheck{}},
		},
	}))
	ctx := context.Background()

	// Page (server side): begin the request; send begun.ID and
	// begun.Request, as JSON, to the page.
	begun := must(txs.BeginMdocDCAPI(ctx, verifier.MdocDCAPIRequest{
		DocType: docType, Elements: map[string]map[string]bool{ns: {"age_over_18": false}},
	}, session, origin))

	// Wallet, through navigator.credentials.get: answer the request.
	in := must(mdocdcapi.ParseRequest(must(json.Marshal(begun.Request.Data)), origin))
	encrypted := must(in.Respond(0, issuerSigned, deviceKey, [][2]string{{ns, "age_over_18"}}))

	// Page (server side): the page posts the credential's data back,
	// with begun.ID, from the browser holding the session.
	view := must(txs.HandleMdocDCAPIResponse(ctx, begun.ID, session, mdocdcapi.ResponseData(encrypted)))
	fmt.Println("age_over_18:", view.Result.Credentials[0].Claims[ns].(map[string]any)["age_over_18"])
	// Output:
	// age_over_18: true
}

// newCA is a throwaway P-256 CA certificate valid for a day.
func newCA(name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	return newCert(&x509.Certificate{
		Subject: pkix.Name{CommonName: name, Country: []string{"US"}}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, nil)
}

// newLeaf is a throwaway P-256 end-entity certificate under ca, with
// the extended key usages ekus.
func newLeaf(name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ekus ...asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	return newCert(&x509.Certificate{
		Subject: pkix.Name{CommonName: name, Country: []string{"US"}}, KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: ekus,
	}, ca, caKey)
}

// newCert signs tmpl for a fresh P-256 key, by parent (nil:
// self-signed).
func newCert(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	return newCertOn(elliptic.P256(), tmpl, parent, parentKey)
}

// newCertOn is newCert for a key on curve.
func newCertOn(curve elliptic.Curve, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key := must(ecdsa.GenerateKey(curve, rand.Reader))
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
