//go:build mobiletest

package mobile

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// proximityEvent is HandleMessage's result.
type proximityEvent struct {
	ABI    int
	Event  string
	Send   string
	Reason string
	Error  string
}

// startProximity starts a ProximityPresentation and has a reader,
// signing with reader's key if it isn't nil, scan its QR code and ask
// for family_name and given_name.
func startProximity(t *testing.T, h harness, reader *testReader) (*ProximityPresentation, *proximity.ReaderSession, []byte) {
	t.Helper()
	p, err := h.w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	eng := decode[struct {
		ABI         int
		QRCode      string `json:"qr_code"`
		ServiceUUID string `json:"service_uuid"`
		BLEMode     string `json:"ble_mode"`
	}](t, p.Engagement())
	if eng.ABI != ABIVersion || !strings.HasPrefix(eng.QRCode, "mdoc:") || eng.BLEMode != "peripheral_server" {
		t.Fatalf("Engagement = %s", p.Engagement())
	}
	var opts []proximity.ReaderOption
	if reader != nil {
		opts = append(opts, proximity.WithReaderAuth(reader.key.Signer, reader.key.Chain))
	}
	r, err := proximity.NewReaderSession(eng.QRCode, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if r.ServiceUUID() != eng.ServiceUUID {
		t.Fatalf("reader UUID %s, holder %s", r.ServiceUUID(), eng.ServiceUUID)
	}
	msg, err := r.Establishment(walletflowtest.DocType, map[string][]string{walletflowtest.NameSpace: {"family_name", "given_name"}})
	if err != nil {
		t.Fatal(err)
	}
	return p, r, msg
}

func sent(t *testing.T, b64 string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) == 0 {
		t.Fatalf("send %q: %v", b64, err)
	}
	return b
}

func TestSessions_ProximityPresentation(t *testing.T) {
	reader := newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, reader)
	var mdocID string
	for _, c := range h.receive(t) {
		if c.Format == "mso_mdoc" {
			mdocID = c.ID
		}
	}
	p, r, msg := startProximity(t, h, &reader)
	ev := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), msg))
	if ev.ABI != ABIVersion || ev.Event != "request" || ev.Send != "" {
		t.Fatalf("HandleMessage = %+v", ev)
	}
	type element struct {
		Namespace, Identifier string
		Retain                bool
	}
	req := decode[struct {
		Reader struct {
			Status, Name, Error string
			Chain               []string
			Certificates        []struct {
				Subject, Issuer, Serial, SHA256 string
				NotBefore                       string   `json:"not_before"`
				IsCA                            bool     `json:"is_ca"`
				KeyUsages                       []string `json:"key_usages"`
			}
		}
		Documents []struct {
			DocType     string `json:"doctype"`
			Elements    []element
			Credentials []struct {
				ID              string
				ShownToVerifier *bool `json:"shown_to_verifier"`
				LinkableHere    *bool `json:"linkable_here"`
			}
		}
	}](t, p.Request())
	if req.Reader.Status != "trusted" || req.Reader.Name != "Test Shop" || len(req.Reader.Chain) != 2 || req.Reader.Error != "" {
		t.Errorf("reader = %+v", req.Reader)
	}
	if leaf, err := x509.ParseCertificate(sent(t, req.Reader.Chain[0])); err != nil || !leaf.Equal(reader.key.Chain[0]) {
		t.Errorf("chain[0] isn't the reader's certificate: %v", err)
	}
	if cs := req.Reader.Certificates; len(cs) != 2 || cs[0].Subject != "CN=Test Shop" || cs[0].Issuer != "CN=mobile test reader CA" ||
		cs[0].IsCA || !cs[1].IsCA || len(cs[0].SHA256) != 64 || cs[0].Serial == "" || len(cs[0].KeyUsages) == 0 {
		t.Errorf("certificates = %+v", cs)
	} else if _, err := time.Parse(time.RFC3339, cs[0].NotBefore); err != nil {
		t.Errorf("not_before: %v", err)
	}
	if len(req.Documents) != 1 || len(req.Documents[0].Elements) != 2 || len(req.Documents[0].Credentials) != 1 {
		t.Fatalf("Request = %d documents", len(req.Documents))
	}
	d := req.Documents[0]
	if d.DocType != walletflowtest.DocType || d.Elements[0] != (element{walletflowtest.NameSpace, "given_name", false}) ||
		d.Credentials[0].ID != mdocID || d.Credentials[0].ShownToVerifier == nil || *d.Credentials[0].ShownToVerifier ||
		d.Credentials[0].LinkableHere == nil || *d.Credentials[0].LinkableHere {
		t.Fatalf("document = %+v", d)
	}

	if _, err := p.Respond(NewOperation(0), 0, mdocID, `[["`+walletflowtest.NameSpace+`","portrait"]]`); code(err) != CodeInvalidSelection {
		t.Errorf("an unrequested element: %v, want %s", err, CodeInvalidSelection)
	}
	if _, err := p.Respond(NewOperation(0), 0, mdocID, `{`); code(err) != CodeInvalidInput {
		t.Errorf("malformed elements: %v, want %s", err, CodeInvalidInput)
	}
	out, err := p.Respond(NewOperation(0), 0, mdocID, `[["`+walletflowtest.NameSpace+`","family_name"]]`)
	if err != nil {
		t.Fatal(err)
	}
	resp := decode[struct {
		ABI      int
		Send     string
		Linkable bool
	}](t, out)
	if resp.ABI != ABIVersion || resp.Linkable {
		t.Fatalf("Respond = %s", out)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(issuerRootsPEM(t, h))) {
		t.Fatal("no issuer roots")
	}
	v, err := r.Verify(sent(t, resp.Send), roots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if v.Claims[walletflowtest.NameSpace]["family_name"] != walletflowtest.FamilyName || len(v.Claims[walletflowtest.NameSpace]) != 1 {
		t.Errorf("disclosed %v", v.Claims)
	}
	if _, err := p.Respond(NewOperation(0), 0, mdocID, `[["`+walletflowtest.NameSpace+`","family_name"]]`); code(err) != CodeWrongStep {
		t.Errorf("a second Respond: %v, want %s", err, CodeWrongStep)
	}
}

// Declining sends status 20; a reader ending the session first is
// reader_ended; a bad message, or a reader require_trusted_mdoc_reader
// refuses, is an error with its code.
func TestSessions_ProximityPresentationEnds(t *testing.T) {
	reader := newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, reader)

	t.Run("declined", func(t *testing.T) {
		p, r, msg := startProximity(t, h, &reader)
		decode[proximityEvent](t, p.HandleMessage(NewOperation(0), msg))
		send := decode[struct{ Send string }](t, p.Terminate()).Send
		if _, err := r.Verify(sent(t, send), x509.NewCertPool(), time.Now()); err != proximity.ErrDeclined {
			t.Errorf("reader: %v, want declined", err)
		}
	})
	t.Run("reader ended", func(t *testing.T) {
		p, r, msg := startProximity(t, h, &reader)
		decode[proximityEvent](t, p.HandleMessage(NewOperation(0), msg))
		ev := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), r.Termination()))
		if ev.Event != "ended" || ev.Reason != "reader_ended" || ev.Send != "" || ev.Error != "" {
			t.Errorf("HandleMessage = %+v", ev)
		}
	})
	t.Run("not CBOR", func(t *testing.T) {
		p, _, _ := startProximity(t, h, &reader)
		ev := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), []byte{0x01}))
		if ev.Event != "ended" || ev.Reason != "error" || !strings.HasPrefix(ev.Error, "["+CodeProtocol+"]") {
			t.Errorf("HandleMessage = %+v", ev)
		}
		if string(sent(t, ev.Send)) != string(proximity.StatusMessage(proximity.StatusCBORDecodingError)) {
			t.Error("not status 11")
		}
	})
	t.Run("untrusted reader refused", func(t *testing.T) {
		strict := h.withConfig(t, map[string]any{"mdoc_reader_roots": reader.caPEM, "require_trusted_mdoc_reader": true})
		p, _, msg := startProximity(t, strict, nil)
		ev := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), msg))
		if ev.Event != "ended" || ev.Reason != "error" || !strings.HasPrefix(ev.Error, "["+CodeUntrustedVerifier+"]") || ev.Send == "" {
			t.Errorf("HandleMessage = %+v", ev)
		}
	})
}
