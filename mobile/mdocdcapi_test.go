//go:build mobiletest

package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

const readerOrigin = "https://shop.example"

// testReader is an mdoc reader with a certificate from its own CA.
type testReader struct {
	key   mdocdcapi.ReaderKey
	caPEM string
}

func newTestReader(t *testing.T) testReader {
	t.Helper()
	cert := func(name string, isCA bool, pub *ecdsa.PublicKey, parent *x509.Certificate, signer *ecdsa.PrivateKey) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := cert("mobile test reader CA", true, &caKey.PublicKey, nil, caKey)
	leaf := cert("Test Shop", false, &leafKey.PublicKey, ca, caKey)
	return testReader{
		key:   mdocdcapi.ReaderKey{Signer: leafKey, Chain: []*x509.Certificate{leaf, ca}},
		caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
	}
}

// ask is a request for the test mdoc's family_name (kept) and
// given_name.
func (r testReader) ask(t *testing.T) ([]byte, mdocdcapi.Pending) {
	t.Helper()
	req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin: readerOrigin, DocType: walletflowtest.DocType, Readers: []mdocdcapi.ReaderKey{r.key},
		Elements: map[string]map[string]bool{walletflowtest.NameSpace: {"family_name": true, "given_name": false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(req.Data)
	if err != nil {
		t.Fatal(err)
	}
	return data, req.Pending
}

// withReaderRoots is h with a wallet recognizing r.
func (h harness) withReaderRoots(t *testing.T, r testReader) harness {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(h.env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["mdoc_reader_roots"] = r.caPEM
	text, _ := json.Marshal(cfg)
	w, err := NewWallet(string(text), h.keys, h.creds, h.env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	h.w = w
	return h
}

func TestSessions_MdocPresentation(t *testing.T) {
	reader := newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, reader)
	var mdocID string
	for _, c := range h.receive(t) {
		if c.Format == "mso_mdoc" {
			mdocID = c.ID
		}
	}
	data, pending := reader.ask(t)
	p, err := h.w.StartMdocPresentation(NewOperation(0), data, readerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	type element struct {
		Namespace, Identifier string
		Retain                bool
	}
	req := decode[struct {
		ABI       int
		Origin    string
		Reader    string
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
	if req.ABI != ABIVersion || req.Origin != readerOrigin || req.Reader != "Test Shop" || len(req.Documents) != 1 {
		t.Fatalf("Request = %s", p.Request())
	}
	d := req.Documents[0]
	if d.DocType != walletflowtest.DocType || len(d.Elements) != 2 ||
		d.Elements[0] != (element{walletflowtest.NameSpace, "family_name", true}) ||
		len(d.Credentials) != 1 || d.Credentials[0].ID != mdocID ||
		d.Credentials[0].ShownToVerifier == nil || *d.Credentials[0].ShownToVerifier ||
		d.Credentials[0].LinkableHere == nil || *d.Credentials[0].LinkableHere {
		t.Fatalf("Request = %s", p.Request())
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
		Response string
		Linkable bool
	}](t, out)
	encrypted, err := base64.StdEncoding.DecodeString(resp.Response)
	if err != nil || resp.ABI != ABIVersion || resp.Linkable {
		t.Fatalf("Respond = %s", out)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(issuerRootsPEM(t, h))) {
		t.Fatal("no issuer roots")
	}
	got, err := mdocdcapi.VerifyResponse(t.Context(), mdocdcapi.VerifyParams{
		Pending: pending, Response: base64.RawURLEncoding.EncodeToString(encrypted),
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.NameSpaces[walletflowtest.NameSpace]["family_name"] != walletflowtest.FamilyName || len(got.NameSpaces[walletflowtest.NameSpace]) != 1 {
		t.Errorf("disclosed %v", got.NameSpaces)
	}
	if _, err := p.Respond(NewOperation(0), 0, mdocID, `[["`+walletflowtest.NameSpace+`","family_name"]]`); code(err) != CodeWrongStep {
		t.Errorf("a second Respond: %v, want %s", err, CodeWrongStep)
	}
}

func issuerRootsPEM(t *testing.T, h harness) string {
	t.Helper()
	var cfg struct {
		IssuerRoots string `json:"issuer_roots"`
	}
	if err := json.Unmarshal([]byte(h.env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.IssuerRoots
}

// Without mdoc_reader_roots, the request is shown by its origin only.
func TestSessions_MdocPresentationUnrecognizedReader(t *testing.T) {
	h := newHarness(t, false)
	data, _ := newTestReader(t).ask(t)
	p, err := h.w.StartMdocPresentation(NewOperation(0), data, readerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if req := decode[struct{ Reader string }](t, p.Request()); req.Reader != "" {
		t.Errorf("Reader = %q, want none", req.Reader)
	}
	if _, err := h.w.StartMdocPresentation(NewOperation(0), []byte("{}"), readerOrigin); code(err) == "" {
		t.Error("an empty request parsed")
	}
}

func TestNewWallet_RefusesBadMdocReaderRoots(t *testing.T) {
	h := newHarness(t, false)
	var cfg map[string]any
	_ = json.Unmarshal([]byte(h.env.ConfigJSON()), &cfg)
	cfg["mdoc_reader_roots"] = "not PEM"
	text, _ := json.Marshal(cfg)
	if _, err := NewWallet(string(text), h.keys, h.creds, h.env.Provider()); code(err) != CodeInvalidInput {
		t.Errorf("NewWallet = %v, want %s", err, CodeInvalidInput)
	}
}

// require_trusted_mdoc_reader refuses an unrecognized reader as
// untrusted_verifier; mdoc_reader_require_eku stops recognizing a
// reader certificate without the reader authentication EKU (the test
// reader's has none).
func TestSessions_MdocReaderTrustSettings(t *testing.T) {
	reader := newTestReader(t)
	data, _ := reader.ask(t)
	h := newHarness(t, false)
	withSettings := func(settings map[string]any) *Wallet {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(h.env.ConfigJSON()), &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["mdoc_reader_roots"] = reader.caPEM
		for k, v := range settings {
			cfg[k] = v
		}
		text, _ := json.Marshal(cfg)
		w, err := NewWallet(string(text), h.keys, h.creds, h.env.Provider())
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	if _, err := withSettings(map[string]any{"require_trusted_mdoc_reader": true}).StartMdocPresentation(NewOperation(0), data, readerOrigin); err != nil {
		t.Errorf("recognized reader, required: %v", err)
	}
	p, err := withSettings(map[string]any{"mdoc_reader_require_eku": true}).StartMdocPresentation(NewOperation(0), data, readerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if req := decode[struct{ Reader string }](t, p.Request()); req.Reader != "" {
		t.Errorf("a reader certificate without the EKU was recognized as %q", req.Reader)
	}
	_, err = withSettings(map[string]any{"mdoc_reader_require_eku": true, "require_trusted_mdoc_reader": true}).
		StartMdocPresentation(NewOperation(0), data, readerOrigin)
	if code(err) != CodeUntrustedVerifier {
		t.Errorf("unrecognized reader, required: %v, want %s", err, CodeUntrustedVerifier)
	}
}
