package oid4vpmdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/testmdoc"
)

// mdocDeviceResponseFixture is a real, freshly issued IssuerSigned
// (via internal/testmdoc, shared with verifier's/wallet's own tests)
// plus a real DeviceSigned over it — everything
// MarshalDeviceResponse/UnmarshalDeviceResponse tests need.
func mdocDeviceResponseFixture(t *testing.T) (testmdoc.Fixture, Document) {
	t.Helper()
	f := testmdoc.Issue(t)

	sessionTranscriptBytes, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID: "x509_hash:verifier", Nonce: "nonce-1", ResponseURI: "https://verifier.example.com/response",
		ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(f.DeviceKey, cose.ES256, sessionTranscriptBytes, testmdoc.DocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatalf("mdoc.SignDeviceSignature: %v", err)
	}

	return f, Document{DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: deviceSigned}
}

func TestMarshalUnmarshalDeviceResponseRoundTrip(t *testing.T) {
	f, doc := mdocDeviceResponseFixture(t)

	encoded, err := MarshalDeviceResponse(doc)
	if err != nil {
		t.Fatalf("MarshalDeviceResponse: %v", err)
	}
	decoded, err := UnmarshalDeviceResponse(encoded)
	if err != nil {
		t.Fatalf("UnmarshalDeviceResponse: %v", err)
	}
	if decoded.DocType != doc.DocType {
		t.Errorf("DocType = %q, want %q", decoded.DocType, doc.DocType)
	}

	verified, err := mdoc.Verify(decoded.IssuerSigned, &f.IssuerKey.PublicKey, cose.ES256, mdoc.VerifyOptions{})
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
	_, doc := mdocDeviceResponseFixture(t)
	doc.DocType = ""
	if _, err := MarshalDeviceResponse(doc); err == nil {
		t.Fatalf("MarshalDeviceResponse = nil error, want error")
	}
}
