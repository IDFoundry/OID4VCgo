package proximity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/proximity"
)

// A holder and a reader in one process: the holder shows a QR code, the
// reader scans it and sends a signed request, the holder checks the
// reader and answers with the element the user agreed to, and the
// reader verifies the answer. The messages pass directly between the
// two sessions here; in an app they travel over BLE, which is the
// app's to provide.
func ExampleNewDeviceSession() {
	const (
		docType = "org.iso.18013.5.1.mDL"
		ns      = "org.iso.18013.5.1"
	)

	// An issuer (IACA → document signer, same country) and the mDL it
	// issued to the holder's device key.
	iaca, iacaKey := newCert(pkix.Name{CommonName: "Example IACA", Country: []string{"SG"}}, nil, nil)
	ds, dsKey := newCert(pkix.Name{CommonName: "Example Document Signer", Country: []string{"SG"}}, iaca, iacaKey)
	deviceKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	signed := time.Now()
	issuerSigned := must(mdoc.Issue(dsKey, oid4vci.COSEES256, mdoc.Claims{
		DocType:    docType,
		NameSpaces: map[string]map[string]any{ns: {"given_name": "Alice", "age_over_18": true}},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed, ValidFrom: signed, ValidUntil: signed.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}}))

	// The reader's authentication certificate, under a CA the holder
	// trusts.
	readerCA, readerCAKey := newCert(pkix.Name{CommonName: "Example Reader CA"}, nil, nil)
	readerCert, readerKey := newCert(pkix.Name{CommonName: "Example Venue"}, readerCA, readerCAKey, proximity.ReaderAuthenticationEKU)

	// Holder: start a session and show its QR code.
	holder := must(proximity.NewDeviceSession(rand.Reader))
	qr := holder.QRCode()

	// Reader: scan the QR code and send a signed request.
	reader := must(proximity.NewReaderSession(qr,
		proximity.WithReaderAuth(readerKey, []*x509.Certificate{readerCert, readerCA}),
		proximity.WithMaxClockSkew(5*time.Minute),
	))
	establishment := must(reader.Establishment(docType, map[string][]string{ns: {"age_over_18"}}))

	// Holder: decrypt the request and check who sent it.
	requests := must(proximity.ParseDeviceRequest(must(holder.HandleSessionEstablishment(establishment))))
	req := requests[0]
	readerRoots := x509.NewCertPool()
	readerRoots.AddCert(readerCA)
	auth := holder.VerifyReaderAuth(req, proximity.ReaderTrust{
		Roots:      readerRoots,
		LeafPolicy: proximity.RequireReaderAuthenticationEKU,
	})
	fmt.Println("reader:", auth.Status, auth.Chain[0].Subject.CommonName)

	// Holder: answer with the elements the user consented to.
	response := must(proximity.BuildDeviceResponse(req, issuerSigned, deviceKey, holder.SessionTranscriptBytes(), req.Elements))
	msg := must(holder.Encrypt(response, false))

	// Reader: verify the answer against the IACAs it trusts.
	iacaRoots := x509.NewCertPool()
	iacaRoots.AddCert(iaca)
	verified := must(reader.Verify(msg, iacaRoots, time.Time{}))
	fmt.Println("issuer:", verified.IssuerCN, "under", verified.TrustAnchorCN)
	fmt.Println("age_over_18:", verified.Claims[ns]["age_over_18"])
	// Output:
	// reader: trusted Example Venue
	// issuer: Example Document Signer under Example IACA
	// age_over_18: true
}

// newCert is a throwaway P-256 certificate for subject, valid for a
// day, with the extended key usages ekus: a CA when parent is nil
// (self-signed), else an end-entity certificate signed by parent.
func newCert(subject pkix.Name, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ekus ...asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl := &x509.Certificate{
		SerialNumber: must(rand.Int(rand.Reader, big.NewInt(1<<62))),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: ekus,
	}
	if parent == nil {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
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
