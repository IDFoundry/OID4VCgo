package proximity

import (
	"bytes"
	"context"
	"testing"
	"time"
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

func TestNFCDataInvalidLimits(t *testing.T) {
	for _, p := range []NFCDataParameters{{0, 256}, {256, 0}, {65536, 256}, {255, 65537}, {-1, 1}} {
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
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseNFCDataHandover(b) })
}

func FuzzNFCDataRequest(f *testing.F) {
	hr, err := NewNFCHandoverRequestWithNFCData(nil, NFCDataParameters{255, 256})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hr)
	f.Fuzz(func(t *testing.T, b []byte) {
		carriers, err := parseNFCRequestCarriers(b)
		if err == nil {
			_, _ = parseNFCDataCarriers(carriers)
		}
	})
}
