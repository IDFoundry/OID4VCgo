package nfcapdu

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/proximity"
)

// FuzzHolderStaticHandover is FuzzHolder for the holders that don't
// negotiate: a static handover offering NFC data retrieval, and a
// static BLE handover. A sequence of arbitrary commands, with the
// messages they carry answered (with arbitrary bytes) or refused and
// the field dropped now and then, never panics, and every command not
// carrying a message gets a response with a status word.
func FuzzHolderStaticHandover(f *testing.F) {
	data, err := proximity.NewNFCDataDeviceSession(nil, proximity.NFCDataParameters{MaxCommand: 255, MaxResponse: 256})
	if err != nil {
		f.Fatal(err)
	}
	ble, err := proximity.NewNFCDeviceSession(nil)
	if err != nil {
		f.Fatal(err)
	}
	selectData := concat([]byte{0, insSelect, 4, 0, 7}, DataApplication, []byte{0})
	envelope := []byte{0, insEnvelope, 0, 0, 3, 0x53, 1, 7, 0}
	f.Add(concat([]byte{byte(len(selectData))}, selectData, []byte{byte(len(envelope))}, envelope), true, true)
	f.Add(concat([]byte{byte(len(selectNDEF))}, selectNDEF, []byte{byte(len(selectNDEFFile))}, selectNDEFFile, []byte{5, 0, insReadBinary, 0, 0, 2}), false, false)
	f.Fuzz(func(t *testing.T, b []byte, useData, respond bool) {
		opts := HolderOptions{HandoverSelect: ble.HandoverSelect()}
		if useData {
			opts = HolderOptions{HandoverSelect: data.HandoverSelect(), Data: true}
		}
		h, err := NewHolder(opts)
		if err != nil {
			t.Fatal(err)
		}
		for i, apdu := range splitAPDUs(b) {
			step := h.Process(apdu)
			switch {
			case step.Message != nil && respond:
				if _, err := h.Respond(append(step.Message, step.Message...)); err != nil {
					t.Fatal(err)
				}
			case step.Message != nil:
				h.RefuseMessage()
			case len(step.Response) < 2:
				t.Fatalf("Process(%X) = %X", apdu, step.Response)
			}
			if i%5 == 4 {
				h.Deactivate(i%2 == 0, i%3 == 0)
			}
		}
	})
}
