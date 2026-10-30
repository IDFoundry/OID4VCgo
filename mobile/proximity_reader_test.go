//go:build mobiletest

package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/proximity"
)

// readerDecisions are the decisions a production reader's configuration
// makes, as JSON object members: any IACA in issuer_roots for any
// document type, and no revocation checks.
const readerDecisions = `"any_issuer_for_any_type": true, "no_revocation_check": ["issuer", "status"]`

// readerConfig is a production ProximityReader's configuration
// accepting h's issuer, signing as reader when it isn't nil, and the
// KeyStore holding its key.
func readerConfig(t *testing.T, h harness, reader *testReader, extra map[string]any) (string, KeyStore) {
	t.Helper()
	cfg := map[string]any{
		"issuer_roots": issuerRootsPEM(t, h), "any_issuer_for_any_type": true, "no_revocation_check": []string{"issuer", "status"},
	}
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
		IssuerChain []string `json:"issuer_chain"`
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
	if _, err := s.CheckStatus(NewOperation(0)); code(err) != CodeWrongStep {
		t.Errorf("CheckStatus before a verified mdoc: %v, want %s", err, CodeWrongStep)
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
	// issuer_chain is the verified path, leaf first, ending at the root.
	if len(v.IssuerChain) < 2 {
		t.Fatalf("issuer_chain = %v", v.IssuerChain)
	}
	certs := make([]*x509.Certificate, len(v.IssuerChain))
	for i, b64 := range v.IssuerChain {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatal(err)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			t.Fatal(err)
		}
	}
	if certs[0].Subject.CommonName != v.Issuer || certs[len(certs)-1].Subject.CommonName != v.TrustAnchor ||
		!strings.Contains(issuerRootsPEM(t, h), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[len(certs)-1].Raw}))) {
		t.Errorf("issuer_chain runs from %q to %q", certs[0].Subject.CommonName, certs[len(certs)-1].Subject.CommonName)
	}

	// CheckStatus reads the status list the MSO names, and sees a
	// revocation.
	checkStatus := func() string {
		t.Helper()
		got := decode[struct {
			ABI    int
			Status string
		}](t, mustText(t)(s.CheckStatus(NewOperation(0))))
		if got.ABI != ABIVersion {
			t.Errorf("CheckStatus abi = %d", got.ABI)
		}
		return got.Status
	}
	if got := checkStatus(); got != "valid" {
		t.Errorf("CheckStatus = %q, want valid", got)
	}
	h.env.Revoke()
	if got := checkStatus(); got != "invalid" {
		t.Errorf("CheckStatus after Revoke = %q, want invalid", got)
	}
	cancelled := NewOperation(0)
	cancelled.Cancel()
	if _, err := s.CheckStatus(cancelled); code(err) != CodeCancelled {
		t.Errorf("CheckStatus cancelled: %v, want %s", err, CodeCancelled)
	}
}

// A document without a status list, or with an identifier list, which
// the reader can't check, isn't fetched. A status naming no mechanism
// the reader knows (decoded with neither member) is unknown, not none:
// it may revoke the document.
func TestProximityReader_CheckStatusWithoutList(t *testing.T) {
	r := &ProximityReader{clock: time.Now}
	for name, tc := range map[string]struct {
		status *mdoc.Status
		want   string
	}{
		"no status":                        {nil, "none"},
		"status naming no known mechanism": {&mdoc.Status{}, "unknown"},
		"identifier list":                  {&mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{ID: []byte{1}, URI: "https://status.example/ids"}}, "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := r.checkStatus(context.Background(), proximity.Verified{Status: tc.status})
			if err != nil || got != tc.want {
				t.Errorf("checkStatus = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	// A status list with no issuer chain to bind its signer to fails
	// rather than trusting any signer.
	ref := &mdoc.Status{StatusList: &mdoc.StatusListRef{URI: "https://status.example/list", Idx: 1}}
	if _, err := r.checkStatus(context.Background(), proximity.Verified{Status: ref}); err == nil {
		t.Error("checkStatus without an issuer chain succeeded")
	}
}

// A status list is read as ISO/IEC 18013-5 §12.3.6.3 has it: a token
// without exp, or with its x5chain outside the protected header, is
// refused. One on which the document is valid, beside an identifier
// list the reader can't check, leaves it unknown.
func TestProximityReader_CheckStatusListForm(t *testing.T) {
	signer := teststatuslist.NewSigner(t)
	saved := testHTTP.Load()
	defer testHTTP.Store(saved)
	r := &ProximityReader{clock: time.Now}
	ids := &mdoc.IdentifierListRef{ID: []byte{1}, URI: "https://status.example/ids"}
	for name, tc := range map[string]struct {
		variant teststatuslist.Variant
		ids     *mdoc.IdentifierListRef
		want    string // "" for refused
	}{
		"well-formed":          {teststatuslist.WellFormed, nil, "valid"},
		"no exp":               {teststatuslist.NoExp, nil, ""},
		"unprotected x5chain":  {teststatuslist.UnprotectedX5Chain, nil, ""},
		"with identifier list": {teststatuslist.WellFormed, ids, "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			uri, client := signer.Serve(t, tc.variant)
			testHTTP.Store(client)
			got, err := r.checkStatus(context.Background(), proximity.Verified{
				Status:      &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 3, URI: uri, Certificate: signer.CA.Raw}, IdentifierList: tc.ids},
				IssuerChain: signer.Chain,
			})
			switch {
			case tc.want == "" && err == nil:
				t.Errorf("checkStatus = %q, want it refused", got)
			case tc.want != "" && (err != nil || got != tc.want):
				t.Errorf("checkStatus = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// The status list fetcher, outside the test build, connects to public
// addresses only.
func TestProximityReader_StatusFetcherDefaults(t *testing.T) {
	saved := testHTTP.Load()
	testHTTP.Store(nil)
	defer testHTTP.Store(saved)
	if f := statusFetcher(); f.AllowLoopback || f.AllowPrivate || f.AllowProxy || f.UncheckedTransport || f.HTTP != nil {
		t.Errorf("statusFetcher = %+v", f)
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
		"a key and no chain": {`{"issuer_roots": ` + mustJSON(issuerRootsPEM(t, h)) + `, "reader_key_id": "reader", ` + readerDecisions + `}`, ks},
		"no KeyStore":        {good, nil},
		"another key":        {good, otherKS},
		"skew over an hour":  {`{"issuer_roots": ` + mustJSON(issuerRootsPEM(t, h)) + `, "max_clock_skew_seconds": 7200, ` + readerDecisions + `}`, nil},
		"bad by-doctype PEM": {`{"issuer_roots_by_doctype": {"org.example.test.1": "not PEM"}, ` + readerDecisions + `}`, nil},
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

// issuer_roots_by_doctype alone is a configuration: issuer_roots is
// optional with it, and it decides which IACAs issue which document
// types, so a production reader needs no any_issuer_for_any_type.
func TestNewProximityReader_RootsByDocType(t *testing.T) {
	h := newHarness(t, false)
	cfg := `{"issuer_roots_by_doctype": {"org.example.test.1": ` + mustJSON(issuerRootsPEM(t, h)) + `}, "no_revocation_check": ["issuer", "status"]}`
	if _, err := NewProximityReader(cfg, nil); err != nil {
		t.Errorf("NewProximityReader with issuer_roots_by_doctype only: %v", err)
	}
}

// Outside development, a reader's configuration decides each role's
// revocation and which IACAs issue which document types; in
// development, it may leave them out. "production", which opted in to
// these checks within ABI 12, is gone: the checks are the default.
func TestNewProximityReader_Decisions(t *testing.T) {
	h := newHarness(t, false)
	roots := `"issuer_roots": ` + mustJSON(issuerRootsPEM(t, h))
	for name, tc := range map[string]struct {
		cfg     string
		refused string
	}{
		"undecided":                       {`{` + roots + `}`, "any_issuer_for_any_type"},
		"no issuer revocation":            {`{` + roots + `, "any_issuer_for_any_type": true, "no_revocation_check": ["status"]}`, `"issuer"`},
		"no status revocation":            {`{` + roots + `, "any_issuer_for_any_type": true, "revocation": ["issuer"]}`, `"status"`},
		"by doctype, no revocation":       {`{"issuer_roots_by_doctype": {"org.example.test.1": ` + mustJSON(issuerRootsPEM(t, h)) + `}}`, `"issuer"`},
		"named and declined":              {`{` + roots + `, "any_issuer_for_any_type": true, "revocation": ["issuer", "status"], "no_revocation_check": ["issuer"]}`, "both"},
		"an unknown role":                 {`{` + roots + `, "any_issuer_for_any_type": true, "no_revocation_check": ["issuer", "status", "verifier"]}`, "verifier"},
		"the removed production":          {`{` + roots + `, ` + readerDecisions + `, "production": true}`, `"production"`},
		"decided":                         {`{` + roots + `, ` + readerDecisions + `}`, ""},
		"development, explicitly off":     {`{` + roots + `, ` + readerDecisions + `, "development": false}`, ""},
		"development":                     {`{` + roots + `, "development": true}`, ""},
		"development, partly":             {`{` + roots + `, "development": true, "revocation": ["issuer"]}`, ""},
		"development, named and declined": {`{` + roots + `, "development": true, "revocation": ["issuer"], "no_revocation_check": ["issuer"]}`, "both"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewProximityReader(tc.cfg, nil)
			switch {
			case tc.refused == "" && err != nil:
				t.Errorf("NewProximityReader: %v", err)
			case tc.refused != "" && (code(err) != CodeInvalidInput || !strings.Contains(err.Error(), tc.refused)):
				t.Errorf("NewProximityReader: %v, want invalid_input naming %s", err, tc.refused)
			}
		})
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
