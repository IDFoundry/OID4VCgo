package oid4vpmdoc_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// TestUnmarshalDeviceResponseRejectsOversizedResponse builds a real,
// well-formed (if oversized) DeviceResponse — padding IssuerSigned
// with an extra data element rather than hand-crafting bytes, since
// Marshal derives that item's own encoding fresh (IssuerSigned's own
// doc comment on rawItems) with no need to re-sign anything;
// UnmarshalDeviceResponse itself never verifies IssuerAuth/digests
// either way.
func TestUnmarshalDeviceResponseRejectsOversizedResponse(t *testing.T) {
	f := testmdoc.Issue(t)
	f.IssuerSigned.NameSpaces["org.iso.18013.5.1"] = append(f.IssuerSigned.NameSpaces["org.iso.18013.5.1"], mdoc.IssuerSignedItem{
		ElementIdentifier: "padding", ElementValue: strings.Repeat("a", oid4vpmdoc.MaxBytes),
	})

	sessionTranscriptBytes, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: "x509_hash:verifier", Nonce: "nonce-1", ResponseURI: "https://verifier.example.com/response",
		ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(f.DeviceKey, cose.ES256, sessionTranscriptBytes, testmdoc.DocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatalf("SignDeviceSignature: %v", err)
	}

	raw, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{
		DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: deviceSigned,
	})
	if err != nil {
		t.Fatalf("MarshalDeviceResponse: %v", err)
	}
	if len(raw) <= oid4vpmdoc.MaxBytes {
		t.Fatalf("device response is %d bytes, want > oid4vpmdoc.MaxBytes (%d)", len(raw), oid4vpmdoc.MaxBytes)
	}

	if _, err := oid4vpmdoc.UnmarshalDeviceResponse(raw); err == nil {
		t.Error("UnmarshalDeviceResponse = nil error, want error (oversized device response)")
	}

	// UnmarshalDeviceResponseMax with a raised ceiling accepts the
	// same input UnmarshalDeviceResponse rejects.
	if _, err := oid4vpmdoc.UnmarshalDeviceResponseMax(raw, len(raw)); err != nil {
		t.Errorf("UnmarshalDeviceResponseMax with a raised ceiling: %v", err)
	}
}
