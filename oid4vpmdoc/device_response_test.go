package oid4vpmdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/internal/cose"
)

// mdocFixture is a real, freshly issued IssuerSigned plus a real
// DeviceSigned over it — everything MarshalDeviceResponse/
// UnmarshalDeviceResponse tests need.
type mdocFixture struct {
	issuerKey *ecdsa.PrivateKey
	doc       Document
}

func newMdocFixture(t *testing.T) mdocFixture {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "oid4vpmdoc test issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	signed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	const docType = "org.iso.18013.5.1.mDL"
	issuerSigned, err := mdoc.Issue(issuerKey, cose.ES256, mdoc.Claims{
		DocType: docType,
		NameSpaces: map[string]map[string]interface{}{
			"org.iso.18013.5.1": {"given_name": "Alice", "family_name": "Doe"},
		},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed,
		ValidFrom:  signed,
		ValidUntil: signed.Add(365 * 24 * time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{cert}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}

	sessionTranscriptBytes, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID: "x509_hash:verifier", Nonce: "nonce-1", ResponseURI: "https://verifier.example.com/response",
		ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(deviceKey, cose.ES256, sessionTranscriptBytes, docType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatalf("mdoc.SignDeviceSignature: %v", err)
	}

	return mdocFixture{issuerKey: issuerKey, doc: Document{DocType: docType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned}}
}

func TestMarshalUnmarshalDeviceResponseRoundTrip(t *testing.T) {
	f := newMdocFixture(t)

	encoded, err := MarshalDeviceResponse(f.doc)
	if err != nil {
		t.Fatalf("MarshalDeviceResponse: %v", err)
	}
	decoded, err := UnmarshalDeviceResponse(encoded)
	if err != nil {
		t.Fatalf("UnmarshalDeviceResponse: %v", err)
	}
	if decoded.DocType != f.doc.DocType {
		t.Errorf("DocType = %q, want %q", decoded.DocType, f.doc.DocType)
	}

	verified, err := mdoc.Verify(decoded.IssuerSigned, &f.issuerKey.PublicKey, cose.ES256, mdoc.VerifyOptions{
		Now: func() time.Time { return time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["given_name"]; got != "Alice" {
		t.Errorf("given_name = %v, want Alice", got)
	}
}

func TestUnmarshalDeviceResponseRejectsWrongStatus(t *testing.T) {
	wire := wireDeviceResponse{Version: deviceResponseVersion, Status: 10}
	b, err := cbor.Marshal(wire)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	if _, err := UnmarshalDeviceResponse(b); err == nil {
		t.Fatalf("UnmarshalDeviceResponse = nil error, want error")
	}
}

func TestUnmarshalDeviceResponseRejectsNoDocuments(t *testing.T) {
	wire := wireDeviceResponse{Version: deviceResponseVersion, Status: mdocResponseStatusOK}
	b, err := cbor.Marshal(wire)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	if _, err := UnmarshalDeviceResponse(b); err == nil {
		t.Fatalf("UnmarshalDeviceResponse = nil error, want error")
	}
}

func TestMarshalDeviceResponseRejectsMissingDocType(t *testing.T) {
	f := newMdocFixture(t)
	doc := f.doc
	doc.DocType = ""
	if _, err := MarshalDeviceResponse(doc); err == nil {
		t.Fatalf("MarshalDeviceResponse = nil error, want error")
	}
}
