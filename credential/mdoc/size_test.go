package mdoc

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// TestUnmarshalIssuerSignedRejectsOversizedInput builds a real,
// well-formed (if oversized) IssuerSigned — padding with an extra data
// element rather than hand-crafting bytes, the same approach
// oid4vpmdoc's own equivalent size test takes for the same reason:
// Marshal derives that item's own encoding fresh, with no need to
// re-sign anything.
func TestUnmarshalIssuerSignedRejectsOversizedInput(t *testing.T) {
	f := newFixture(t)
	f.signed.NameSpaces["org.iso.18013.5.1"] = append(f.signed.NameSpaces["org.iso.18013.5.1"], IssuerSignedItem{
		ElementIdentifier: "padding", ElementValue: strings.Repeat("a", MaxBytes),
	})

	raw, err := f.signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(raw) <= MaxBytes {
		t.Fatalf("IssuerSigned is %d bytes, want > MaxBytes (%d)", len(raw), MaxBytes)
	}

	if _, err := UnmarshalIssuerSigned(raw); err == nil {
		t.Error("UnmarshalIssuerSigned = nil error, want error (oversized input)")
	}

	// UnmarshalIssuerSignedMax with a raised ceiling accepts the same
	// input UnmarshalIssuerSigned rejects.
	if _, err := UnmarshalIssuerSignedMax(raw, len(raw)); err != nil {
		t.Errorf("UnmarshalIssuerSignedMax with a raised ceiling: %v", err)
	}
}

// TestUnmarshalDeviceSignedRejectsOversizedInput is
// TestUnmarshalIssuerSignedRejectsOversizedInput's DeviceSigned
// counterpart: a real, well-formed (if oversized) signed DeviceSigned,
// padding its own DeviceNameSpaces rather than IssuerSigned's own
// NameSpaces.
func TestUnmarshalDeviceSignedRejectsOversizedInput(t *testing.T) {
	f := newSigFixture(t)
	nameSpaces := testDeviceNameSpaces()
	nameSpaces["org.iso.18013.5.1"]["padding"] = strings.Repeat("a", MaxBytes)
	deviceSigned, err := SignDeviceSignature(f.key, cose.ES256, f.st, testDeviceDocType, nameSpaces)
	if err != nil {
		t.Fatalf("SignDeviceSignature: %v", err)
	}

	raw, err := deviceSigned.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(raw) <= MaxBytes {
		t.Fatalf("DeviceSigned is %d bytes, want > MaxBytes (%d)", len(raw), MaxBytes)
	}

	if _, err := UnmarshalDeviceSigned(raw); err == nil {
		t.Error("UnmarshalDeviceSigned = nil error, want error (oversized input)")
	}

	// UnmarshalDeviceSignedMax with a raised ceiling accepts the same
	// input UnmarshalDeviceSigned rejects.
	if _, err := UnmarshalDeviceSignedMax(raw, len(raw)); err != nil {
		t.Errorf("UnmarshalDeviceSignedMax with a raised ceiling: %v", err)
	}
}
