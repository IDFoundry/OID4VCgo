package proximity

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCombinedRoundTrips(t *testing.T) {
	fx := issueFixture(t, mDL)
	for _, negotiated := range []bool{false, true} {
		for _, carrier := range []string{"peripheral", "central", "nfc"} {
			var transcripts [][]byte
			for _, nfcWins := range []bool{false, true} {
				t.Run(fmt.Sprintf("negotiated=%t/%s/nfc=%t", negotiated, carrier, nfcWins), func(t *testing.T) {
					options := CombinedOptions{Negotiated: negotiated}
					mode := PeripheralServer
					if carrier == "central" {
						mode = CentralClient
					}
					if carrier == "nfc" {
						options.NFCData = &NFCDataParameters{MaxCommand: 255, MaxResponse: 256}
					}
					c, err := NewCombinedDeviceSession(nil, options, WithBLEMode(mode))
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					if bytes.Equal(c.qr.DeviceEngagementBytes(), c.nfc.DeviceEngagementBytes()) || c.qr.eDeviceKey.Equal(c.nfc.eDeviceKey) {
						t.Fatal("offers share key or engagement")
					}
					h, err := c.Select(nfcWins)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := c.Select(!nfcWins); err == nil {
						t.Fatal("loser attached")
					}
					if again, err := c.Select(nfcWins); err != nil || again != h {
						t.Fatal("winning selection changed")
					}
					var r *ReaderSession
					if !nfcWins {
						r, err = NewReaderSession(c.qr.QRCode(), devReader()...)
					} else {
						hs := h.HandoverSelect()
						var hr []byte
						if negotiated {
							if options.NFCData != nil {
								hr, err = NewNFCHandoverRequestWithNFCData(nil, *options.NFCData, mode)
							} else {
								hr, err = NewNFCHandoverRequest(nil, mode)
							}
							if err != nil {
								t.Fatal(err)
							}
							hs, err = h.HandleHandoverRequest(hr)
							if err != nil {
								t.Fatal(err)
							}
						}
						switch {
						case options.NFCData != nil && negotiated:
							r, err = NewNFCNegotiatedDataReaderSession(hs, hr, devReader()...)
						case options.NFCData != nil:
							r, err = NewNFCDataReaderSession(hs, devReader()...)
						case negotiated:
							r, err = NewNFCNegotiatedReaderSession(hs, hr, devReader()...)
						default:
							r, err = NewNFCReaderSession(hs, devReader()...)
						}
					}
					if err != nil {
						t.Fatal(err)
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
					if !bytes.Equal(h.SessionTranscriptBytes(), r.SessionTranscriptBytes()) {
						t.Fatal("transcript mismatch")
					}
					transcripts = append(transcripts, append([]byte(nil), h.SessionTranscriptBytes()...))
					f := flow{holder: h, reader: r, req: reqs[0]}
					response := f.respond(t, fx, reqs[0].Elements)
					// Keep the correct decryption keys but verify device authentication
					// against the wrong handover, isolating transcript binding itself.
					wrong := *r
					wrongCipher := *r.cipher
					wrong.cipher = &wrongCipher
					handover := nullHandover
					if !nfcWins {
						handover = []byte{0x82, 0x40, 0xf6}
					}
					wrong.sessionTranscriptBytes, err = buildSessionTranscriptBytes(h.DeviceEngagementBytes(), r.eReaderKeyBytes, handover)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := wrong.Verify(context.Background(), response, fx.roots, time.Now()); err == nil {
						t.Fatal("wrong handover verified")
					}
					v, err := r.Verify(context.Background(), response, fx.roots, time.Now())
					if err != nil || v.Claims[mDLNS]["age_over_18"] != true {
						t.Fatalf("verification: %v %v", v, err)
					}
				})
			}
			if len(transcripts) == 2 && bytes.Equal(transcripts[0], transcripts[1]) {
				t.Fatal("QR and NFC transcripts identical")
			}
		}
	}
}

func TestCombinedOmittedQRAndClose(t *testing.T) {
	c, err := NewCombinedDeviceSession(nil, CombinedOptions{OmitQR: true, NFCData: &NFCDataParameters{MaxCommand: 255, MaxResponse: 256}})
	if err != nil {
		t.Fatal(err)
	}
	if c.QROffer() != nil {
		t.Fatal("omitted QR exposed")
	}
	if _, err := c.Select(false); err == nil {
		t.Fatal("omitted QR selected")
	}
	if _, err := c.Select(true); err != nil {
		t.Fatal(err)
	}
	if c.SelectedEngagement() != "nfc_data" {
		t.Fatal("wrong carrier")
	}
	c.Close()
	if _, err := c.Select(true); err == nil {
		t.Fatal("closed owner revived")
	}
}
