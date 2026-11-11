package oid4vpmdoc_test

import (
	"encoding/base64"
	"maps"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// TestMarshalUnmarshalDeviceResponseRoundTrip drives a real round
// trip via testmdoc.Present (which itself calls
// oid4vpmdoc.MarshalDeviceResponse internally) — an external test
// package specifically so it can import internal/testmdoc, which
// itself imports oid4vpmdoc; an internal (white-box) test file
// couldn't do that without a real import cycle.
func TestMarshalUnmarshalDeviceResponseRoundTrip(t *testing.T) {
	f := testmdoc.Issue(t)
	presented := testmdoc.Present(t, f, oid4vpmdoc.HandoverParams{
		ClientID: "x509_hash:verifier", Nonce: "nonce-1", ResponseURI: "https://verifier.example.com/response",
		ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})

	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		t.Fatalf("UnmarshalDeviceResponse: %v", err)
	}
	if decoded.DocType != testmdoc.DocType {
		t.Errorf("DocType = %q, want %q", decoded.DocType, testmdoc.DocType)
	}

	verified, err := mdoc.Verify(decoded.IssuerSigned, testmdoc.DocType, &f.IssuerKey.PublicKey, cose.ES256, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["given_name"]; got != "Alice" {
		t.Errorf("given_name = %v, want Alice", got)
	}
}

// A DeviceResponse of a version other than 1.x is refused, as
// internal/mdocresponse refuses one; any 1.x is taken.
func TestUnmarshalDeviceResponseChecksVersion(t *testing.T) {
	f := testmdoc.Issue(t)
	presented := testmdoc.Present(t, f, oid4vpmdoc.HandoverParams{
		ClientID: "x509_hash:verifier", Nonce: "nonce-1", ResponseURI: "https://verifier.example.com/response",
		ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})
	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	withVersion := func(v any) []byte {
		t.Helper()
		edited := maps.Clone(wire)
		if v == nil {
			delete(edited, "version")
		} else {
			b, err := cbor.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			edited["version"] = b
		}
		b, err := cbor.Marshal(edited)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range []any{"1.0", "1.1"} {
		if _, err := oid4vpmdoc.UnmarshalDeviceResponse(withVersion(v)); err != nil {
			t.Errorf("version %v: %v", v, err)
		}
	}
	for _, v := range []any{"2.0", "1", "", "01.0", nil} {
		if _, err := oid4vpmdoc.UnmarshalDeviceResponse(withVersion(v)); err == nil || (v != nil && !strings.Contains(err.Error(), "version")) {
			t.Errorf("version %v: %v, want refused", v, err)
		}
	}
}

func TestMarshalDeviceResponseRejectsMissingDocType(t *testing.T) {
	f := testmdoc.Issue(t)
	doc := oid4vpmdoc.Document{DocType: "", IssuerSigned: f.IssuerSigned, DeviceSigned: mdoc.DeviceSigned{}}
	if _, err := oid4vpmdoc.MarshalDeviceResponse(doc); err == nil {
		t.Fatalf("MarshalDeviceResponse = nil error, want error")
	}
}
