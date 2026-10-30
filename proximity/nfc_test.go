package proximity

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestNFCStaticPresentation(t *testing.T) {
	fx := issueFixture(t, mDL)
	key, chain, roots := testReader(t, ReaderAuthenticationEKU)
	for _, modes := range [][]BLEMode{{PeripheralServer}, {CentralClient}, {PeripheralServer, CentralClient}} {
		t.Run(modes[0].String()+string(rune('0'+len(modes))), func(t *testing.T) {
			h, err := NewNFCDeviceSession(nil, WithBLEModes(modes...))
			if err != nil {
				t.Fatal(err)
			}
			hs := h.HandoverSelect()
			var de map[int]cbor.RawMessage
			if err := decMode.Unmarshal(h.DeviceEngagementBytes(), &de); err != nil {
				t.Fatal(err)
			}
			if _, exists := de[2]; exists {
				t.Fatal("NFC engagement contains retrieval methods")
			}
			r, err := NewNFCReaderSession(hs, devReader(WithReaderAuth(key, chain))...)
			if err != nil {
				t.Fatal(err)
			}
			wantMode := modes[len(modes)-1]
			if r.BLEMode() != wantMode || r.ServiceUUID() != h.ServiceUUID() {
				t.Fatal("BLE role/UUID mismatch")
			}
			if wantMode == CentralClient && !bytes.Equal(r.BLEIdent(), h.BLEIdent()) {
				t.Fatal("BLE Ident mismatch")
			}
			// Neither caller mutations nor repeated reads can replace the transcript.
			hs[0] ^= 1
			if bytes.Equal(hs, h.HandoverSelect()) {
				t.Fatal("HandoverSelect aliases session bytes")
			}
			msg, err := r.Establishment(mDL, ageOver18)
			if err != nil {
				t.Fatal(err)
			}
			request, err := h.HandleSessionEstablishment(msg)
			if err != nil {
				t.Fatal(err)
			}
			reqs, err := ParseDeviceRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.VerifyReaderAuth(reqs[0], ReaderTrust{Roots: roots, LeafPolicy: RequireReaderAuthenticationEKU}); got.Status != ReaderTrusted {
				t.Fatalf("reader authentication: %+v", got)
			}
			if !bytes.Equal(h.SessionTranscriptBytes(), r.sessionTranscriptBytes) {
				t.Fatal("transcript mismatch")
			}
			f := flow{holder: h, reader: r, req: reqs[0]}
			v, err := r.Verify(context.Background(), f.respond(t, fx, reqs[0].Elements), fx.roots, time.Now())
			if err != nil || v.Claims[mDLNS]["age_over_18"] != true {
				t.Fatalf("credential verification: %+v, %v", v, err)
			}
		})
	}
}

func TestNFCReaderPolicy(t *testing.T) {
	h, err := NewNFCDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNFCReaderSession(h.HandoverSelect(), devReader(WithMaxClockSkew(2*time.Hour))...); err == nil {
		t.Fatal("accepted excessive clock skew")
	}
	if _, err := NewNFCReaderSession(h.HandoverSelect(), devReader(WithReaderAuth(nil, nil))...); err == nil {
		t.Fatal("accepted invalid reader signer")
	}
	denied := errors.New("test signer denied")
	r, err := NewNFCReaderSession(h.HandoverSelect(), devReader(WithDocumentSignerPolicy(func(*x509.Certificate, [][]*x509.Certificate) error { return denied }))...)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(r.signerPolicy(nil, nil), denied) {
		t.Fatal("NFC omitted custom signer policy")
	}
	pool := x509.NewCertPool()
	r, err = NewNFCReaderSession(h.HandoverSelect(), devReader(WithIssuerRootsByDocType(map[string]*x509.CertPool{mDL: pool}))...)
	if err != nil || r.rootsByDocType[mDL] != pool {
		t.Fatal("NFC omitted document trust roots")
	}
}

func TestNFCSelectRejectsAmbiguousCarriers(t *testing.T) {
	h, err := NewNFCDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	records, err := parseNDEF(h.HandoverSelect())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]ndefRecord) []ndefRecord{
		"duplicate id":       func(rs []ndefRecord) []ndefRecord { return append(rs, rs[1]) },
		"missing engagement": func(rs []ndefRecord) []ndefRecord { return rs[:2] },
		"dangling carrier":   func(rs []ndefRecord) []ndefRecord { rs[1].id = []byte("other"); return rs },
		"missing UUID":       func(rs []ndefRecord) []ndefRecord { rs[1].payload = []byte{2, 0x1c, 0}; return rs },
		"invalid role":       func(rs []ndefRecord) []ndefRecord { rs[1].payload = []byte{2, 0x1c, 4}; return rs },
		"QR engagement": func(rs []ndefRecord) []ndefRecord {
			qr, e := NewDeviceSession(nil)
			if e != nil {
				t.Fatal(e)
			}
			rs[2].payload = qr.DeviceEngagementBytes()
			return rs
		},
	} {
		t.Run(name, func(t *testing.T) {
			rs := append([]ndefRecord(nil), records...)
			encoded, e := encodeNDEF(mutate(rs))
			if e != nil {
				t.Fatal(e)
			}
			if _, e := NewNFCReaderSession(encoded, devReader()...); e == nil {
				t.Fatal("accepted malformed handover")
			}
		})
	}
}

func TestNDEFLengthEncodings(t *testing.T) {
	for _, size := range []int{0, 255, 256, 4096} {
		payload := bytes.Repeat([]byte{0x42}, size)
		encoded, err := encodeNDEF([]ndefRecord{{tnf: 4, typ: []byte("test:record"), id: []byte("id"), payload: payload}})
		if err != nil {
			t.Fatal(err)
		}
		rs, err := parseNDEF(encoded)
		if err != nil || len(rs) != 1 || !bytes.Equal(rs[0].payload, payload) {
			t.Fatalf("size %d: %v", size, err)
		}
		for end := 0; end < len(encoded); end++ {
			if _, err := parseNDEF(encoded[:end]); err == nil {
				t.Fatalf("accepted truncated record at %d", end)
			}
		}
	}
	for _, raw := range [][]byte{{0xd1, 1, 0, 'x', 0}, {0x51, 1, 0, 'x'}, {0xf1, 1, 0, 'x'}, {0xc1, 1, 0xff, 0xff, 0xff, 0xff, 'x'}} {
		if _, err := parseNDEF(raw); err == nil {
			t.Fatalf("accepted invalid record %x", raw)
		}
	}
}

func FuzzNFCSelect(f *testing.F) {
	h, err := NewNFCDeviceSession(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(h.HandoverSelect())
	f.Add([]byte{})
	f.Add([]byte{0xd1, 2, 0, 'H', 's'})
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _, _ = parseNFCSelect(b) })
}
