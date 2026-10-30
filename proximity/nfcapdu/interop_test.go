package nfcapdu

import (
	"bytes"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// TestHandoverWithProximitySessions reads each kind of Handover Select
// proximity builds through a Holder, and starts the reader session from
// what the reader read.
func TestHandoverWithProximitySessions(t *testing.T) {
	data := proximity.NFCDataParameters{MaxCommand: 255, MaxResponse: 256}
	reader := []proximity.ReaderOption{proximity.WithAssurance(verifier.AssuranceDevelopment), proximity.WithIssuerRevocation(certrevocation.NoCheck{})}
	for _, tc := range []struct {
		name       string
		holder     func() (*proximity.DeviceSession, error)
		negotiated bool
		data       bool
	}{
		{"static BLE", func() (*proximity.DeviceSession, error) { return proximity.NewNFCDeviceSession(nil) }, false, false},
		{"negotiated BLE", func() (*proximity.DeviceSession, error) { return proximity.NewNFCNegotiatedDeviceSession(nil) }, true, false},
		{"static NFC data", func() (*proximity.DeviceSession, error) { return proximity.NewNFCDataDeviceSession(nil, data) }, false, true},
		{"negotiated NFC data", func() (*proximity.DeviceSession, error) {
			return proximity.NewNFCNegotiatedDataDeviceSession(nil, data)
		}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := tc.holder()
			if err != nil {
				t.Fatal(err)
			}
			opts := HolderOptions{Data: tc.data}
			var hr []byte
			switch {
			case tc.negotiated && tc.data:
				hr, err = proximity.NewNFCHandoverRequestWithNFCData(nil, data, proximity.PeripheralServer)
			case tc.negotiated:
				hr, err = proximity.NewNFCHandoverRequest(nil, proximity.PeripheralServer)
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.negotiated {
				opts.Negotiate = s.HandleHandoverRequest
			} else {
				opts.HandoverSelect = s.HandoverSelect()
			}
			h, err := NewHolder(opts)
			if err != nil {
				t.Fatal(err)
			}
			read := false
			r := ReadHandover(261, hr)
			hs, _, err := drive(t, r.Exchange, func(c []byte) []byte {
				step := h.Process(c)
				read = read || step.HandoverRead
				return step.Response
			})
			if err != nil || !read || r.Negotiated() != tc.negotiated {
				t.Fatalf("ReadHandover: %v, HandoverRead %v, Negotiated %v", err, read, r.Negotiated())
			}
			switch {
			case tc.negotiated && tc.data:
				_, err = proximity.NewNFCNegotiatedDataReaderSession(hs, hr, reader...)
			case tc.negotiated:
				_, err = proximity.NewNFCNegotiatedReaderSession(hs, hr, reader...)
			case tc.data:
				_, err = proximity.NewNFCDataReaderSession(hs, reader...)
			default:
				_, err = proximity.NewNFCReaderSession(hs, reader...)
			}
			if err != nil {
				t.Fatalf("reader session from the Hs read: %v", err)
			}
			if !tc.data {
				return
			}
			p, err := proximity.ParseNFCDataHandover(hs)
			if err != nil {
				t.Fatal(err)
			}
			step := h.Process(SelectDataApplication())
			if err := CheckDataApplicationSelected(step.Response); err != nil || !step.DataSelected {
				t.Fatalf("selecting the data application: %v", err)
			}
			got, _, err := drive(t, Transact(261, p, []byte("request")), func(c []byte) []byte {
				step := h.Process(c)
				if step.Message == nil {
					return step.Response
				}
				first, err := h.Respond(bytes.ToUpper(step.Message))
				if err != nil {
					t.Fatal(err)
				}
				return first.Response
			})
			if err != nil || string(got) != "REQUEST" {
				t.Errorf("Transact = %q, %v", got, err)
			}
		})
	}
}

func TestNegotiateErrorRefusesTheWrite(t *testing.T) {
	h, err := NewHolder(HolderOptions{Negotiate: func([]byte) ([]byte, error) { return nil, errTest }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := drive(t, ReadHandover(261, fixture(5)).Exchange, holderTag(t, h)); err == nil {
		t.Error("a refused Handover Request was read")
	}
}

func TestDataNeedsShortAPDUs(t *testing.T) {
	s, err := proximity.NewNFCDataDeviceSession(nil, proximity.NFCDataParameters{MaxCommand: 1000, MaxResponse: 256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHolder(HolderOptions{HandoverSelect: s.HandoverSelect(), Data: true}); err == nil {
		t.Error("extended-APDU limits were accepted")
	}
	if _, err := NewHolder(HolderOptions{HandoverSelect: []byte{1}, Negotiate: func([]byte) ([]byte, error) { return nil, nil }}); err == nil {
		t.Error("a static Handover Select with negotiation was accepted")
	}
}

var errTest = bytes.ErrTooLarge
