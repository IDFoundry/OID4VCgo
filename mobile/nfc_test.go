//go:build mobiletest

package mobile

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

func TestNFCMobilePresentation(t *testing.T) {
	h := newHarness(t, false)
	h.receive(t)
	p, err := h.w.StartNFCProximityPresentationWithModes(`["peripheral_server","central_client"]`)
	if err != nil {
		t.Fatal(err)
	}
	hs := p.HandoverSelect()
	r, err := proximity.NewNFCReaderSession(hs, devReader()...)
	if err != nil {
		t.Fatal(err)
	}
	eng := decode[struct {
		QRCode string `json:"qr_code"`
	}](t, p.Engagement())
	if eng.QRCode != "" {
		t.Fatal("NFC session exposed unusable QR engagement")
	}
	hs[0] ^= 1
	if bytes.Equal(hs, p.HandoverSelect()) {
		t.Fatal("mobile NFC bytes alias holder session")
	}
	request, err := r.Establishment(walletflowtest.DocType, map[string][]string{walletflowtest.NameSpace: {"family_name"}})
	if err != nil {
		t.Fatal(err)
	}
	event := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), request))
	if event.Event != "request" {
		t.Fatalf("NFC request: %+v", event)
	}
	// Explicit decline uses the same wallet state machine and closes it.
	termination := decode[struct{ Send string }](t, p.Terminate())
	msg, err := base64.StdEncoding.DecodeString(termination.Send)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Verify(context.Background(), msg, nil, time.Time{})
	if !errors.Is(err, proximity.ErrDeclined) {
		t.Fatalf("NFC termination: %v", err)
	}
}

func TestNFCBindingsEndToEnd(t *testing.T) {
	reader := newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, reader)
	var credentialID string
	for _, credential := range h.receive(t) {
		if credential.Format == "mso_mdoc" {
			credentialID = credential.ID
		}
	}
	if credentialID == "" {
		t.Fatal("test issuer supplied no mdoc")
	}
	cfg, ks := readerConfig(t, h, &reader, nil)
	rd, err := NewProximityReader(cfg, ks)
	if err != nil {
		t.Fatal(err)
	}
	for _, negotiated := range []bool{false, true} {
		for _, mode := range []string{"peripheral_server", "central_client", "nfc_data"} {
			t.Run(fmt.Sprintf("negotiated=%t/%s", negotiated, mode), func(t *testing.T) {
				modes := fmt.Sprintf(`["%s"]`, mode)
				var holder *ProximityPresentation
				var session *ProximityReaderSession
				if mode == "nfc_data" {
					if negotiated {
						holder, err = h.w.StartNFCNegotiatedDataProximityPresentation(255, 256)
					} else {
						holder, err = h.w.StartNFCDataProximityPresentation(255, 256)
					}
					if err != nil {
						t.Fatal(err)
					}
					hs := holder.HandoverSelect()
					var hr []byte
					if negotiated {
						hr, err = NewNFCHandoverRequestWithNFCData(`["peripheral_server","central_client"]`, 255, 256)
						if err != nil {
							t.Fatal(err)
						}
						hs, err = holder.HandleHandoverRequest(hr)
						if err != nil {
							t.Fatal(err)
						}
					}
					if _, e := ParseNfcDataParameters(hs); e != nil {
						t.Fatal(e)
					}
					if negotiated {
						session, err = rd.StartFromNegotiatedNFCDataHandover(hs, hr)
					} else {
						session, err = rd.StartFromNFCDataHandover(hs)
					}
				} else if negotiated {
					holder, err = h.w.StartNFCNegotiatedProximityPresentationWithModes(modes)
					if err != nil {
						t.Fatal(err)
					}
					hr, e := NewNFCHandoverRequest(modes)
					if e != nil {
						t.Fatal(e)
					}
					hs, e := holder.HandleHandoverRequest(hr)
					if e != nil {
						t.Fatal(e)
					}
					session, err = rd.StartFromNegotiatedHandover(hs, hr)
				} else {
					holder, err = h.w.StartNFCProximityPresentationWithModes(modes)
					if err != nil {
						t.Fatal(err)
					}
					session, err = rd.StartFromHandover(holder.HandoverSelect())
				}
				if err != nil {
					t.Fatal(err)
				}
				request, e := session.Request(walletflowtest.DocType, `{"org.example.test.1":["family_name"]}`)
				if e != nil {
					t.Fatal(e)
				}
				event := decode[proximityEvent](t, holder.HandleMessage(NewOperation(0), sent(t, decode[struct{ Send string }](t, request).Send)))
				if event.Event != "request" {
					t.Fatalf("request: %+v", event)
				}
				identity := decode[struct{ Reader struct{ Status string } }](t, holder.Request())
				if identity.Reader.Status != "trusted" {
					t.Fatal("NFC lost reader authentication")
				}
				out, e := holder.Respond(NewOperation(0), 0, credentialID, `[["org.example.test.1","family_name"]]`)
				if e != nil {
					t.Fatal(e)
				}
				verified := decode[readerEvent](t, session.HandleMessage(sent(t, decode[struct{ Send string }](t, out).Send)))
				if verified.Event != "verified" || verified.Verified == nil || verified.Verified.Claims[walletflowtest.NameSpace]["family_name"] != walletflowtest.FamilyName {
					t.Fatalf("verification: %+v", verified)
				}
			})
		}
	}
}
