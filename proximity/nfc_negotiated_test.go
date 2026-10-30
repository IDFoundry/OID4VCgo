package proximity

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Reader/writer TNEP already assigns requester/selector roles. An Hr may
// start with Alternative Carrier records rather than peer-mode collision data.
func TestNFCNegotiationWithoutCollisionResolution(t *testing.T) {
	for _, mode := range []BLEMode{PeripheralServer, CentralClient} {
		t.Run(mode.String(), func(t *testing.T) {
			hr, err := NewNFCHandoverRequest(nil, mode)
			if err != nil {
				t.Fatal(err)
			}
			records, err := parseNDEF(hr)
			if err != nil {
				t.Fatal(err)
			}
			embedded, err := parseNDEF(records[0].payload[1:])
			if err != nil {
				t.Fatal(err)
			}
			withoutCR, err := encodeNDEF(embedded[1:])
			if err != nil {
				t.Fatal(err)
			}
			records[0].payload = append([]byte{0x15}, withoutCR...)
			hr, err = encodeNDEF(records)
			if err != nil {
				t.Fatal(err)
			}
			holder, err := NewNFCNegotiatedDeviceSession(nil, WithBLEMode(mode))
			if err != nil {
				t.Fatal(err)
			}
			hs, err := holder.HandleHandoverRequest(hr)
			if err != nil {
				t.Fatalf("TNEP Hr without collision record: %v", err)
			}
			reader, err := NewNFCNegotiatedReaderSession(hs, hr, devReader()...)
			if err != nil {
				t.Fatal(err)
			}
			request, err := reader.Establishment(mDL, ageOver18)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := holder.HandleSessionEstablishment(request); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(holder.SessionTranscriptBytes(), reader.sessionTranscriptBytes) {
				t.Fatal("handover transcript changed")
			}
		})
	}
}

func TestNFCRequestCollisionRecordValidation(t *testing.T) {
	hr, err := NewNFCHandoverRequest(nil, PeripheralServer)
	if err != nil {
		t.Fatal(err)
	}
	records, err := parseNDEF(hr)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := parseNDEF(records[0].payload[1:])
	if err != nil {
		t.Fatal(err)
	}
	cr, ac := embedded[0], embedded[1]
	shortCR := cr
	shortCR.payload = []byte{0}
	for name, invalid := range map[string][]ndefRecord{
		"short collision record":     {shortCR, ac},
		"duplicate collision record": {cr, cr, ac},
		"late collision record":      {ac, cr},
		"no carriers":                {cr},
	} {
		t.Run(name, func(t *testing.T) {
			payload, err := encodeNDEF(invalid)
			if err != nil {
				t.Fatal(err)
			}
			outer := append([]ndefRecord(nil), records...)
			outer[0].payload = append([]byte{0x15}, payload...)
			request, err := encodeNDEF(outer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseNFCRequestCarriers(request); err == nil {
				t.Fatal("accepted malformed embedded records")
			}
		})
	}
}

func TestNFCDataNegotiationWithoutCollisionResolution(t *testing.T) {
	parameters := NFCDataParameters{255, 256}
	hr, err := NewNFCHandoverRequestWithNFCData(nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	records, err := parseNDEF(hr)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := parseNDEF(records[0].payload[1:])
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeNDEF(embedded[1:])
	if err != nil {
		t.Fatal(err)
	}
	records[0].payload = append([]byte{0x15}, payload...)
	hr, err = encodeNDEF(records)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := NewNFCNegotiatedDataDeviceSession(nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := holder.HandleHandoverRequest(hr)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewNFCNegotiatedDataReaderSession(hs, hr, devReader()...)
	if err != nil {
		t.Fatal(err)
	}
	request, err := reader.Establishment(mDL, ageOver18)
	if err != nil {
		t.Fatal(err)
	}
	deviceRequest, err := holder.HandleSessionEstablishment(request)
	if err != nil {
		t.Fatal(err)
	}
	fx := issueFixture(t, mDL)
	requests, err := ParseDeviceRequest(deviceRequest)
	if err != nil {
		t.Fatal(err)
	}
	f := flow{holder: holder, reader: reader, req: requests[0]}
	if _, err := reader.Verify(context.Background(), f.respond(t, fx, requests[0].Elements), fx.roots, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(holder.SessionTranscriptBytes(), reader.sessionTranscriptBytes) {
		t.Fatal("handover transcript changed")
	}
}

func TestNFCNegotiatedPresentation(t *testing.T) {
	fx := issueFixture(t, mDL)
	for _, mode := range []BLEMode{PeripheralServer, CentralClient} {
		t.Run(mode.String(), func(t *testing.T) {
			h, err := NewNFCNegotiatedDeviceSession(nil, WithBLEMode(mode))
			if err != nil {
				t.Fatal(err)
			}
			if h.HandoverSelect() != nil || h.QRCode() != "" {
				t.Fatal("unselected engagement exposed")
			}
			if _, err := h.HandleSessionEstablishment([]byte{}); err == nil {
				t.Fatal("accepted establishment before handover")
			}
			hr, err := NewNFCHandoverRequest(nil, mode)
			if err != nil {
				t.Fatal(err)
			}
			hs, err := h.HandleHandoverRequest(hr)
			if err != nil {
				t.Fatal(err)
			}
			again, err := h.HandleHandoverRequest(hr)
			if err != nil || !bytes.Equal(hs, again) {
				t.Fatal("repeated Hr changed engagement")
			}
			other, err := NewNFCHandoverRequest(nil, mode)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.HandleHandoverRequest(other); err == nil {
				t.Fatal("accepted replacement Hr")
			}
			r, err := NewNFCNegotiatedReaderSession(hs, hr, devReader()...)
			if err != nil {
				t.Fatal(err)
			}
			if r.BLEMode() != mode || r.ServiceUUID() != h.ServiceUUID() {
				t.Fatal("selected mode/UUID mismatch")
			}
			msg, err := r.Establishment(mDL, ageOver18)
			if err != nil {
				t.Fatal(err)
			}
			req, err := h.HandleSessionEstablishment(msg)
			if err != nil {
				t.Fatal(err)
			}
			reqs, err := ParseDeviceRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			f := flow{holder: h, reader: r, req: reqs[0]}
			v, err := r.Verify(context.Background(), f.respond(t, fx, reqs[0].Elements), fx.roots, time.Now())
			if err != nil || v.Claims[mDLNS]["age_over_18"] != true {
				t.Fatalf("verification: %+v %v", v, err)
			}
			if !bytes.Equal(h.SessionTranscriptBytes(), r.sessionTranscriptBytes) {
				t.Fatal("negotiated transcript mismatch")
			}
		})
	}
}

func TestNFCNegotiatedAnnexD(t *testing.T) {
	de, _, handover := annexDTranscriptParts(t)
	var messages [][]byte
	if err := decMode.Unmarshal(handover, &messages); err != nil || len(messages) != 2 {
		t.Fatalf("Annex D handover: %v", err)
	}
	gotDE, mode, uuid, err := parseNFCSelectWithRequest(messages[0], messages[1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(de, gotDE) || mode != CentralClient || formatUUID(uuid) != "3a82d455-d5fc-4db3-bea0-6fd2f6ff32c8" {
		t.Fatalf("Annex D selection: %v %s", mode, formatUUID(uuid))
	}
	encoded, err := nfcHandover(messages[0], messages[1])
	if err != nil || !bytes.Equal(encoded, handover) {
		t.Fatal("Annex D Handover bytes changed")
	}
	// Use the published reader key to verify the entire transcript, not
	// just a self-generated request/response round trip.
	key := annexDKey(t, annexDEphemeralReaderKeyD, annexDEphemeralReaderKeyX, annexDEphemeralReaderKeyY)
	r, err := newReaderSession(key, gotDE, cbor.RawMessage(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.sessionTranscriptBytes, mustHex(t, annexDSessionTranscriptBytes)) {
		t.Fatal("Annex D NFC SessionTranscriptBytes differ")
	}
	if _, err := NewNFCReaderSession(messages[0], devReader()...); err == nil {
		t.Fatal("accepted negotiated Hs without Hr UUID")
	}
}

func TestNFCNegotiationRejectsUnofferedRole(t *testing.T) {
	h, err := NewNFCNegotiatedDeviceSession(nil, WithBLEMode(PeripheralServer))
	if err != nil {
		t.Fatal(err)
	}
	centralOnly, err := NewNFCHandoverRequest(nil, CentralClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.HandleHandoverRequest(centralOnly); err == nil {
		t.Fatal("selected unsupported holder role")
	}
	peripheralOnly, err := NewNFCHandoverRequest(nil, PeripheralServer)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := h.HandleHandoverRequest(peripheralOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNFCNegotiatedReaderSession(hs, centralOnly, devReader()...); err == nil {
		t.Fatal("accepted Hs role absent from Hr")
	}
}

func TestNFCBLEBothRolePreferences(t *testing.T) {
	uuid := make([]byte, 16)
	uuid[0] = 1
	for _, tc := range []struct {
		role byte
		want BLEMode
	}{{2, PeripheralServer}, {3, CentralClient}} {
		got, _, err := selectNFCBLE(nfcBLEPayload(tc.role, uuid), nil)
		if err != nil || got != tc.want {
			t.Fatalf("role %d: %v %v", tc.role, got, err)
		}
	}
	hr, err := NewNFCHandoverRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	records, err := parseNDEF(hr)
	if err != nil {
		t.Fatal(err)
	}
	records[1].payload = nfcBLEPayload(3, uuid) // reader prefers central, so mdoc is peripheral.
	hr, err = encodeNDEF(records)
	if err != nil {
		t.Fatal(err)
	}
	offers, err := parseNFCRequest(hr)
	if err != nil || len(offers) != 2 || offers[0].mode != PeripheralServer {
		t.Fatalf("preferred complement: %+v %v", offers, err)
	}
}

func FuzzNFCRequest(f *testing.F) {
	hr, err := NewNFCHandoverRequest(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hr)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseNFCRequest(b) })
}
