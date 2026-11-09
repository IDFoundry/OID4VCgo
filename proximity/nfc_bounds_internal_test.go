package proximity

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testbounds"
)

// Every NFC message and field parser refuses, without panicking, any
// truncation of a valid message and survives any one-byte change, on
// input with no spare capacity: a reader or tag in the field chooses
// every byte and length.
func TestNFCParsers_Bounds(t *testing.T) {
	ble, err := NewNFCDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := NewNFCDataDeviceSession(nil, NFCDataParameters{MaxCommand: 255, MaxResponse: 256})
	if err != nil {
		t.Fatal(err)
	}
	hr, err := NewNFCHandoverRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	dataHR, err := NewNFCHandoverRequestWithNFCData(nil, NFCDataParameters{MaxCommand: 255, MaxResponse: 65536})
	if err != nil {
		t.Fatal(err)
	}
	ignore := func(_ any, err error) error { return err }

	testbounds.Check(t, "BLE Handover Select", ble.HandoverSelect(), true, func(b []byte) error {
		_, _, _, err := parseNFCSelect(b)
		return err
	})
	testbounds.Check(t, "NFC data Handover Select", data.HandoverSelect(), true, func(b []byte) error {
		return ignore(ParseNFCDataHandover(b))
	})
	testbounds.Check(t, "BLE Handover Request", hr, true, func(b []byte) error { return ignore(parseNFCRequest(b)) })
	testbounds.Check(t, "NFC data Handover Request", dataHR, true, func(b []byte) error {
		carriers, err := parseNFCRequestCarriers(b)
		if err != nil {
			return err
		}
		return ignore(parseNFCDataCarriers(carriers, false))
	})
	testbounds.Check(t, "NDEF message", ble.HandoverSelect(), true, func(b []byte) error { return ignore(parseNDEF(b)) })

	// A field's own parser sees a record's payload, which a shorter one
	// may still form validly: those must not panic, nor be read past.
	testbounds.Check(t, "alternative carrier", []byte{1, 1, '0', 1, 4, 'm', 'd', 'o', 'c'}, false, func(b []byte) error {
		_, _, err := parseAlternativeCarrier(b)
		return err
	})
	uuid := make([]byte, 16)
	for i := range uuid {
		uuid[i] = byte(i + 1)
	}
	testbounds.Check(t, "BLE OOB data", nfcBLEPayload(0, uuid), false, func(b []byte) error {
		_, _, err := readNFCBLE(b)
		return err
	})
	testbounds.Check(t, "NFC data carrier", nfcDataPayload(NFCDataParameters{MaxCommand: 65535, MaxResponse: 65536}), false, func(b []byte) error {
		return ignore(parseNFCDataCarriers([]ndefRecord{{tnf: 4, typ: []byte(nfcDataType), payload: b}}, false))
	})
}

// A negotiated holder refuses, without panicking, every truncation of a
// reader's Handover Request.
func TestHandleHandoverRequest_Bounds(t *testing.T) {
	hr, err := NewNFCHandoverRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	testbounds.Check(t, "Handover Request to a holder", hr, true, func(b []byte) error {
		s, err := NewNFCNegotiatedDeviceSession(nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.HandleHandoverRequest(b)
		return err
	})
}
