package proximity

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testbounds"
)

func TestNFCDataPresentation(t *testing.T) {
	fx := issueFixture(t, mDL)
	key, chain, roots := testReader(t, ReaderAuthenticationEKU)
	for _, parameters := range []NFCDataParameters{{255, 256}, {65535, 65536}} {
		for _, negotiated := range []bool{false, true} {
			var h *DeviceSession
			var err error
			if negotiated {
				h, err = NewNFCNegotiatedDataDeviceSession(nil, parameters)
			} else {
				h, err = NewNFCDataDeviceSession(nil, parameters)
			}
			if err != nil {
				t.Fatal(err)
			}
			hs := h.HandoverSelect()
			var hr []byte
			if negotiated {
				hr, err = NewNFCHandoverRequestWithNFCData(nil, parameters)
				if err != nil {
					t.Fatal(err)
				}
				hs, err = h.HandleHandoverRequest(hr)
				if err != nil {
					t.Fatal(err)
				}
				repeated, e := h.HandleHandoverRequest(hr)
				if e != nil || !bytes.Equal(repeated, hs) {
					t.Fatal("negotiated NFC data is not idempotent")
				}
			}
			got, err := ParseNFCDataHandover(hs)
			if err != nil || got != parameters {
				t.Fatalf("carrier: %+v, %v", got, err)
			}
			if h.QRCode() != "" || h.ServiceUUID() != "" {
				t.Fatal("NFC data advertises QR/BLE")
			}
			var r *ReaderSession
			if negotiated {
				r, err = NewNFCNegotiatedDataReaderSession(hs, hr, devReader(WithReaderAuth(key, chain))...)
			} else {
				r, err = NewNFCDataReaderSession(hs, devReader(WithReaderAuth(key, chain))...)
			}
			if err != nil {
				t.Fatal(err)
			}
			establishment, err := r.Establishment(mDL, ageOver18)
			if err != nil {
				t.Fatal(err)
			}
			request, err := h.HandleSessionEstablishment(establishment)
			if err != nil {
				t.Fatal(err)
			}
			requests, err := ParseDeviceRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			if h.VerifyReaderAuth(requests[0], ReaderTrust{Roots: roots, LeafPolicy: RequireReaderAuthenticationEKU}).Status != ReaderTrusted {
				t.Fatal("reader authentication failed")
			}
			if !bytes.Equal(h.SessionTranscriptBytes(), r.SessionTranscriptBytes()) {
				t.Fatal("transcript mismatch")
			}
			f := flow{holder: h, reader: r, req: requests[0]}
			v, err := r.Verify(context.Background(), f.respond(t, fx, requests[0].Elements), fx.roots, time.Now())
			if err != nil || v.Claims[mDLNS]["age_over_18"] != true {
				t.Fatalf("verification: %+v %v", v, err)
			}
		}
	}
}

func TestNFCDataNegotiatedRejectsUnofferedCarrier(t *testing.T) {
	h, err := NewNFCNegotiatedDataDeviceSession(nil, NFCDataParameters{255, 256})
	if err != nil {
		t.Fatal(err)
	}
	hr, err := NewNFCHandoverRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.HandleHandoverRequest(hr); err == nil {
		t.Fatal("accepted BLE-only request for NFC data")
	}
}

// TestNFCDataRequestCarriesNoLimits: ISO/IEC 18013-5 (second edition)
// §9.2.2 Table 1 has the data-field limits be the mdoc's, not used by the
// reader. Our Hr's NFC
// carrier is its version alone; the mdoc answers a reader's, with or without
// limits (as earlier readers sent them), with its own.
func TestNFCDataRequestCarriesNoLimits(t *testing.T) {
	own := NFCDataParameters{1000, 2000}
	hr, err := NewNFCHandoverRequestWithNFCData(nil, NFCDataParameters{255, 256})
	if err != nil {
		t.Fatal(err)
	}
	carriers, err := parseNFCRequestCarriers(hr)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range carriers {
		if string(c.typ) == nfcDataType && !bytes.Equal(c.payload, []byte{1}) {
			t.Errorf("Hr NFC carrier = %X, want its version alone", c.payload)
		}
	}
	legacy := func(payload []byte) []byte {
		embedded, err := encodeNDEF([]ndefRecord{
			{tnf: 1, typ: []byte("cr"), payload: []byte{1, 2}},
			{tnf: 1, typ: []byte("ac"), payload: []byte{1, 3, 'n', 'f', 'c', 0}},
		})
		if err != nil {
			t.Fatal(err)
		}
		hr, err := encodeNDEF([]ndefRecord{
			{tnf: 1, typ: []byte("Hr"), payload: append([]byte{0x15}, embedded...)},
			{tnf: 4, typ: []byte(nfcDataType), id: []byte("nfc"), payload: payload},
		})
		if err != nil {
			t.Fatal(err)
		}
		return hr
	}
	for name, hr := range map[string][]byte{
		"ours":         hr,
		"version only": legacy([]byte{1}),
		"with limits":  legacy(nfcDataPayload(NFCDataParameters{255, 256})),
	} {
		h, err := NewNFCNegotiatedDataDeviceSession(nil, own)
		if err != nil {
			t.Fatal(err)
		}
		hs, err := h.HandleHandoverRequest(hr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, err := ParseNFCDataHandover(hs); err != nil || got != own {
			t.Errorf("%s: selected %+v, %v; want the mdoc's own %+v", name, got, err, own)
		}
		if _, err := NewNFCNegotiatedDataReaderSession(hs, hr, devReader()...); err != nil {
			t.Errorf("%s: reader: %v", name, err)
		}
	}
	h, err := NewNFCNegotiatedDataDeviceSession(nil, own)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandleHandoverRequest(legacy([]byte{2})); err == nil {
		t.Error("accepted an NFC carrier of another version")
	}
}

func TestNFCDataInvalidLimits(t *testing.T) {
	for _, p := range []NFCDataParameters{{0, 256}, {256, 0}, {254, 256}, {255, 255}, {65536, 256}, {255, 65537}, {-1, 1}} {
		if _, err := NewNFCDataDeviceSession(nil, p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	h, err := NewNFCDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNFCDataReaderSession(h.HandoverSelect(), devReader()...); err == nil {
		t.Fatal("BLE accepted as NFC data")
	}
}

func FuzzNFCDataHandover(f *testing.F) {
	h, err := NewNFCDataDeviceSession(nil, NFCDataParameters{255, 256})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(h.HandoverSelect())
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseNFCDataHandover(testbounds.Exact(b)) })
}

func FuzzNFCDataRequest(f *testing.F) {
	hr, err := NewNFCHandoverRequestWithNFCData(nil, NFCDataParameters{255, 256})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hr)
	f.Fuzz(func(t *testing.T, b []byte) {
		carriers, err := parseNFCRequestCarriers(testbounds.Exact(b))
		if err == nil {
			_, _ = parseNFCDataCarriers(carriers, false)
		}
	})
}
