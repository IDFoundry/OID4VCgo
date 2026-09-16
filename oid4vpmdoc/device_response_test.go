package oid4vpmdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// These two tests exercise unexported wire internals directly
// (wireDeviceResponse/deviceResponseVersion/mdocResponseStatusOK), so
// they stay in this package's own internal test file — everything
// else that needs a real issued credential lives in
// device_response_external_test.go (package oid4vpmdoc_test), since
// internal/testmdoc (the shared fixture both verifier's and wallet's
// own tests also use) itself imports this package, and an internal
// test file importing it back would be a real import cycle.

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
