//go:build mobiletest

package mobile

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/proximity"
)

// readerConfig is a ProximityReader's configuration accepting h's
// issuer, signing as reader when it isn't nil, and the KeyStore holding
// its key.
func readerConfig(t *testing.T, h harness, reader *testReader, extra map[string]any) (string, KeyStore) {
	t.Helper()
	cfg := map[string]any{"issuer_roots": issuerRootsPEM(t, h)}
	var ks KeyStore
	if reader != nil {
		keys := newGoKeyStore()
		keys.keys["reader"] = reader.key.Signer.(*ecdsa.PrivateKey)
		var chain strings.Builder
		for _, c := range reader.key.Chain {
			chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
		cfg["reader_key_id"], cfg["reader_chain"], ks = "reader", chain.String(), keys
	}
	for k, v := range extra {
		cfg[k] = v
	}
	text, _ := json.Marshal(cfg)
	return string(text), ks
}

type readerEvent struct {
	ABI      int
	Event    string
	Send     string
	Reason   string
	Error    string
	Verified *struct {
		DocType     string `json:"doctype"`
		Claims      map[string]map[string]any
		Issuer      string
		TrustAnchor string `json:"trust_anchor"`
		ValidFrom   string `json:"valid_from"`
		DeviceAuth  string `json:"device_auth"`
		Status      *struct {
			URI string
			Idx uint64
		}
	}
}

// The holder's and the reader's bindings, end to end, as two apps use
// them: QR code, request, consent, response, verification.
func TestSessions_ProximityReader(t *testing.T) {
	reader := newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, reader)
	var mdocID string
	for _, c := range h.receive(t) {
		if c.Format == "mso_mdoc" {
			mdocID = c.ID
		}
	}
	cfg, ks := readerConfig(t, h, &reader, nil)
	rd, err := NewProximityReader(cfg, ks)
	if err != nil {
		t.Fatal(err)
	}

	holder, err := h.w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	qr := decode[struct {
		QRCode string `json:"qr_code"`
	}](t, holder.Engagement()).QRCode
	s, err := rd.Start(qr)
	if err != nil {
		t.Fatal(err)
	}
	eng := decode[struct {
		ServiceUUID string `json:"service_uuid"`
		BLEMode     string `json:"ble_mode"`
		Ident       string
		Signed      bool
	}](t, s.Engagement())
	holderUUID := decode[struct {
		ServiceUUID string `json:"service_uuid"`
	}](t, holder.Engagement()).ServiceUUID
	if eng.ServiceUUID != holderUUID || eng.BLEMode != "peripheral_server" || eng.Ident == "" || !eng.Signed {
		t.Errorf("Engagement = %s", s.Engagement())
	}

	if _, err := s.Request("", `{}`); code(err) != CodeInvalidInput {
		t.Errorf("an empty request: %v, want %s", err, CodeInvalidInput)
	}
	req, err := s.Request("org.example.test.1", `{"org.example.test.1": ["family_name", "given_name"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Request("org.example.test.1", `{"org.example.test.1": ["family_name"]}`); code(err) != CodeWrongStep {
		t.Errorf("a second Request: %v, want %s", err, CodeWrongStep)
	}
	ev := decode[proximityEvent](t, holder.HandleMessage(NewOperation(0), sent(t, decode[struct{ Send string }](t, req).Send)))
	if ev.Event != "request" {
		t.Fatalf("holder: %+v", ev)
	}
	if got := decode[struct{ Reader struct{ Status, Name string } }](t, holder.Request()).Reader; got.Status != "trusted" || got.Name != "Test Shop" {
		t.Errorf("the holder sees the reader as %+v", got)
	}
	out, err := holder.Respond(NewOperation(0), 0, mdocID, `[["org.example.test.1","family_name"]]`)
	if err != nil {
		t.Fatal(err)
	}

	got := decode[readerEvent](t, s.HandleMessage(sent(t, decode[struct{ Send string }](t, out).Send)))
	if got.ABI != ABIVersion || got.Event != "verified" || got.Verified == nil {
		t.Fatalf("HandleMessage = %+v", got)
	}
	v := got.Verified
	if v.DocType != "org.example.test.1" || v.Claims["org.example.test.1"]["family_name"] != "Doe" || len(v.Claims["org.example.test.1"]) != 1 ||
		v.DeviceAuth != "signature" || v.Issuer == "" || v.TrustAnchor == "" || v.ValidFrom == "" || v.Status == nil || v.Status.URI == "" {
		t.Errorf("verified = %+v", v)
	}
}

func TestSessions_ProximityReaderEnds(t *testing.T) {
	h := newHarness(t, false)
	cfg, _ := readerConfig(t, h, nil, nil)
	rd, err := NewProximityReader(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T) (*ProximityPresentation, *ProximityReaderSession) {
		t.Helper()
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
		if decode[struct{ Signed bool }](t, s.Engagement()).Signed {
			t.Error("a reader without a key signs")
		}
		req, err := s.Request("org.example.test.1", `{"org.example.test.1": ["family_name"]}`)
		if err != nil {
			t.Fatal(err)
		}
		if ev := decode[proximityEvent](t, holder.HandleMessage(NewOperation(0), sent(t, decode[struct{ Send string }](t, req).Send))); ev.Event != "request" {
			t.Fatalf("holder: %+v", ev)
		}
		return holder, s
	}

	t.Run("declined", func(t *testing.T) {
		holder, s := start(t)
		got := decode[readerEvent](t, s.HandleMessage(sent(t, decode[struct{ Send string }](t, holder.Terminate()).Send)))
		if got.Event != "ended" || got.Reason != "declined" || got.Verified != nil {
			t.Errorf("HandleMessage = %+v", got)
		}
	})
	t.Run("not a response", func(t *testing.T) {
		_, s := start(t)
		got := decode[readerEvent](t, s.HandleMessage([]byte{0x01}))
		if got.Event != "ended" || got.Reason != "error" || !strings.HasPrefix(got.Error, "["+CodeProtocol+"]") || got.Send == "" {
			t.Errorf("HandleMessage = %+v", got)
		}
	})
	t.Run("terminated", func(t *testing.T) {
		holder, s := start(t)
		ev := decode[proximityEvent](t, holder.HandleMessage(NewOperation(0), sent(t, decode[struct{ Send string }](t, s.Terminate()).Send)))
		if ev.Event != "ended" || ev.Reason != "reader_ended" {
			t.Errorf("holder: %+v", ev)
		}
		if _, err := s.Request("org.example.test.1", `{"org.example.test.1": ["family_name"]}`); code(err) != CodeWrongStep {
			t.Errorf("Request after Terminate: %v", err)
		}
	})
}

func TestNewProximityReader_Refuses(t *testing.T) {
	h := newHarness(t, false)
	reader := newTestReader(t)
	other := newTestReader(t)
	good, ks := readerConfig(t, h, &reader, nil)
	_, otherKS := readerConfig(t, h, &other, nil)
	for name, tc := range map[string]struct {
		cfg string
		ks  KeyStore
	}{
		"not JSON":           {`{`, nil},
		"no issuer roots":    {`{}`, nil},
		"a key and no chain": {`{"issuer_roots": ` + mustJSON(issuerRootsPEM(t, h)) + `, "reader_key_id": "reader"}`, ks},
		"no KeyStore":        {good, nil},
		"another key":        {good, otherKS},
		"skew over an hour":  {`{"issuer_roots": ` + mustJSON(issuerRootsPEM(t, h)) + `, "max_clock_skew_seconds": 7200}`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewProximityReader(tc.cfg, tc.ks); code(err) != CodeInvalidInput {
				t.Errorf("NewProximityReader: %v, want %s", err, CodeInvalidInput)
			}
		})
	}
	rd, err := NewProximityReader(good, ks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Start("mdoc:AAAA"); code(err) != CodeInvalidInput {
		t.Errorf("Start with a bad QR code: %v, want %s", err, CodeInvalidInput)
	}
}

// A holder offering only central client mode — another wallet's
// choice — has the reader be the GATT server, serving its Ident.
func TestProximityReader_CentralClient(t *testing.T) {
	h := newHarness(t, false)
	cfg, _ := readerConfig(t, h, nil, nil)
	rd, err := NewProximityReader(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := proximity.NewDeviceSession(nil, proximity.WithBLEMode(proximity.CentralClient))
	if err != nil {
		t.Fatal(err)
	}
	s, err := rd.Start(holder.QRCode())
	if err != nil {
		t.Fatal(err)
	}
	eng := decode[struct {
		BLEMode string `json:"ble_mode"`
		Ident   string
	}](t, s.Engagement())
	if eng.BLEMode != "central_client" || eng.Ident != base64.StdEncoding.EncodeToString(holder.BLEIdent()) {
		t.Errorf("Engagement = %s", s.Engagement())
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestEnv.ProximityReader's reader signs, and a wallet given its roots
// recognizes it.
func TestTestEnv_ProximityReader(t *testing.T) {
	h := newHarness(t, false)
	keys := newGoKeyStore()
	setup := decode[struct {
		ReaderConfig    string `json:"reader_config"`
		MdocReaderRoots string `json:"mdoc_reader_roots"`
	}](t, func() string {
		text, err := h.env.ProximityReader(keys)
		if err != nil {
			t.Fatal(err)
		}
		return text
	}())
	rd, err := NewProximityReader(setup.ReaderConfig, keys)
	if err != nil {
		t.Fatal(err)
	}
	h = h.withConfig(t, map[string]any{"mdoc_reader_roots": setup.MdocReaderRoots, "mdoc_reader_require_eku": true})
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
	if got := decode[struct{ Reader struct{ Status, Name string } }](t, holder.Request()).Reader; got.Status != "trusted" || got.Name != "Test Reader" {
		t.Errorf("the holder sees the reader as %+v", got)
	}
}
