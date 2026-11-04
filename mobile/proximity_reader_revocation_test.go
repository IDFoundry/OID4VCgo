//go:build mobiletest

package mobile

import (
	"strings"
	"testing"
)

// A reader checking the document signer against its CA's CRL refuses a
// document whose signer the list names, and one whose CA it holds no
// current list from: HandleMessage's error carries the detail
// certificate_revoked or no_current_crl, for an app to say why.
func TestSessions_ProximityReaderRevocationDetail(t *testing.T) {
	h := newHarness(t, false)
	var mdocID string
	for _, c := range h.receive(t) {
		if c.Format == "mso_mdoc" {
			mdocID = c.ID
		}
	}
	revoked, err := h.env.IssuerCRL(true)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		crls, want string
	}{
		"signer revoked": {revoked, "[" + CodeProtocol + ":" + DetailCertificateRevoked + "]"},
		"no CRL":         {"", "[" + CodeProtocol + ":" + DetailNoCurrentCRL + "]"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := readerConfig(t, h, nil, map[string]any{
				"revocation": []string{"issuer"}, "no_revocation_check": []string{"status"}, "crls": tc.crls,
			})
			rd, err := NewProximityReader(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			holder, err := h.w.StartProximityPresentation()
			if err != nil {
				t.Fatal(err)
			}
			s, err := rd.Start(decode[struct {
				QRCode string `json:"qr_code"`
			}](t, holder.Engagement()).QRCode)
			if err != nil {
				t.Fatal(err)
			}
			req, err := s.Request("org.example.test.1", `{"org.example.test.1": ["family_name"]}`)
			if err != nil {
				t.Fatal(err)
			}
			if ev := decode[proximityEvent](t, holder.HandleMessage(NewOperation(0), sent(t, decode[struct{ Send string }](t, req).Send))); ev.Event != "request" {
				t.Fatalf("holder: %+v", ev)
			}
			out, err := holder.Respond(NewOperation(0), 0, mdocID, `[["org.example.test.1","family_name"]]`)
			if err != nil {
				t.Fatal(err)
			}
			got := decode[readerEvent](t, s.HandleMessage(sent(t, decode[struct{ Send string }](t, out).Send)))
			if got.Event != "ended" || got.Reason != "error" || !strings.HasPrefix(got.Error, tc.want) {
				t.Errorf("HandleMessage = %+v, want an error starting %s", got, tc.want)
			}
		})
	}
}
