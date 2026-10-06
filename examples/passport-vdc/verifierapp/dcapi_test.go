package verifierapp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gmrtd/gmrtd/cms"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

const dcapiOrigin = "https://verifier.example"

// dcapiIssuer is an issuer CA and a document signer it certified.
type dcapiIssuer struct {
	ca        *x509.Certificate
	signer    *ecdsa.PrivateKey
	signerDER []byte
}

func newDCAPIIssuer(t *testing.T) dcapiIssuer {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dcapi test issuer CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}, &x509.Certificate{Subject: pkix.Name{CommonName: "dcapi test issuer CA"}, SubjectKeyId: []byte{1, 2, 3, 4}}, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dcapi test document signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, &signer.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return dcapiIssuer{ca: ca, signer: signer, signerDER: der}
}

// passportMdoc is a passport mdoc disclosing elements, and its device key.
func (iss dcapiIssuer) passportMdoc(t *testing.T, elements map[string]any) (mdoc.IssuerSigned, *ecdsa.PrivateKey) {
	t.Helper()
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	signed, err := mdoc.Issue(iss.signer, oid4vci.COSEES256, mdoc.Claims{
		DocType: credential.DocType, NameSpaces: map[string]map[string]interface{}{credential.ISONamespace: elements},
		DeviceKey: &device.PublicKey, Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{iss.signerDER}})
	if err != nil {
		t.Fatal(err)
	}
	return signed, device
}

// answerDCAPI answers an org-iso-mdoc request as an mdoc would for
// origin (ISO/IEC TS 18013-7 Annex C): the device signs over the
// session transcript, and the DeviceResponse is HPKE sealed to the
// request's key.
func answerDCAPI(t *testing.T, data map[string]string, origin string, issuerSigned mdoc.IssuerSigned, device *ecdsa.PrivateKey) string {
	t.Helper()
	rawInfo, err := base64.RawURLEncoding.DecodeString(data["encryptionInfo"])
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		_        struct{} `cbor:",toarray"`
		Protocol string
		Params   struct {
			Nonce []byte       `cbor:"nonce"`
			Key   mdoc.CoseKey `cbor:"recipientPublicKey"`
		}
	}
	if err := cbor.Unmarshal(rawInfo, &info); err != nil {
		t.Fatal(err)
	}
	dcapiInfo, _ := cbor.Marshal([]string{data["encryptionInfo"], origin})
	hash := sha256.Sum256(dcapiInfo)
	transcript, _ := cbor.Marshal([]any{nil, nil, []any{"dcapi", hash[:]}})
	stBytes, _ := cbor.Marshal(cbor.Tag{Number: 24, Content: transcript})

	deviceSigned, err := mdoc.SignDeviceSignature(device, oid4vci.COSEES256, stBytes, credential.DocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{DocType: credential.DocType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := info.Params.Key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ecdhPub, _ := pub.(*ecdsa.PublicKey).ECDH()
	pkR, _ := hpke.NewDHKEMPublicKey(ecdhPub)
	enc, sender, err := hpke.NewSender(pkR, hpke.HKDFSHA256(), hpke.AES128GCM(), transcript)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := sender.Seal(nil, response)
	out, _ := cbor.Marshal([]any{"dcapi", map[string][]byte{"enc": enc, "cipherText": ct}})
	return base64.RawURLEncoding.EncodeToString(out)
}

// dcapiClient is a browser on the demo verifier's pages: it keeps the
// page's session cookie.
type dcapiClient struct {
	t      *testing.T
	srv    *httptest.Server
	cookie *http.Cookie
	app    *verifierapp.App
}

func (c *dcapiClient) do(method, path, contentType string, body io.Reader) *http.Response {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

// startPage creates scenario's request page, returning its path.
func (c *dcapiClient) startPage(scenario verifierapp.Scenario) string {
	c.t.Helper()
	resp := c.do(http.MethodPost, "/demo/requests", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"scenario": {string(scenario)}}.Encode()))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		c.t.Fatalf("create request: status %d", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		c.cookie = ck
	}
	return resp.Header.Get("Location")
}

// askInBrowser starts the page's Digital Credentials API request.
func (c *dcapiClient) askInBrowser(page string) map[string]string {
	c.t.Helper()
	resp := c.do(http.MethodPost, page+"/dcapi", "", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.t.Fatalf("start the DC API request: status %d: %s", resp.StatusCode, body)
	}
	var req struct {
		Protocol string            `json:"protocol"`
		Data     map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		c.t.Fatal(err)
	}
	if req.Protocol != "org-iso-mdoc" || req.Data["deviceRequest"] == "" || req.Data["encryptionInfo"] == "" {
		c.t.Fatalf("request = %+v, want org-iso-mdoc with a deviceRequest and encryptionInfo", req)
	}
	return req.Data
}

func (c *dcapiClient) postResponse(page, response string) (int, string) {
	c.t.Helper()
	body, _ := json.Marshal(map[string]string{"response": response})
	resp := c.do(http.MethodPost, page+"/dcapi/response", "application/json", strings.NewReader(string(body)))
	defer func() { _ = resp.Body.Close() }()
	text, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(text)
}

func (c *dcapiClient) pageText(page string) string {
	c.t.Helper()
	resp := c.do(http.MethodGet, page, "", nil)
	defer func() { _ = resp.Body.Close() }()
	text, _ := io.ReadAll(resp.Body)
	return string(text)
}

func newDCAPIApp(t *testing.T, iss dcapiIssuer) *dcapiClient {
	t.Helper()
	app, err := verifierapp.New(verifierapp.Config{
		VerifierURL: dcapiOrigin, IssuerVCT: "https://issuer.example/vct", IssuerCAs: []*x509.Certificate{iss.ca}, CSCAPool: &cms.GenericCertPool{},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)
	return &dcapiClient{t: t, srv: srv, app: app}
}

// The age check, asked in the browser: the page offers it, the answer
// verifies into the scenario's decision, and the page shows it.
func TestDCAPI_AgeCheck(t *testing.T) {
	iss := newDCAPIIssuer(t)
	c := newDCAPIApp(t, iss)
	page := c.startPage(verifierapp.ScenarioAge)
	if !strings.Contains(c.pageText(page), `id="dcapi"`) {
		t.Fatal("the request page doesn't offer asking in the browser")
	}
	data := c.askInBrowser(page)
	issuerSigned, device := iss.passportMdoc(t, map[string]any{"age_over_18": true})
	if status, body := c.postResponse(page, answerDCAPI(t, data, dcapiOrigin, issuerSigned, device)); status != http.StatusNoContent {
		t.Fatalf("response: status %d: %s", status, body)
	}
	if text := c.pageText(page); !strings.Contains(text, "Sale allowed") {
		t.Errorf("the page doesn't show the decision:\n%s", text)
	}
}

// An answer bound to another origin doesn't verify, and spends the
// request: a second answer needs a new one.
func TestDCAPI_RefusesAnotherOriginAndSpendsTheRequest(t *testing.T) {
	iss := newDCAPIIssuer(t)
	c := newDCAPIApp(t, iss)
	page := c.startPage(verifierapp.ScenarioAge)
	data := c.askInBrowser(page)
	issuerSigned, device := iss.passportMdoc(t, map[string]any{"age_over_18": true})
	if status, _ := c.postResponse(page, answerDCAPI(t, data, "https://attacker.example", issuerSigned, device)); status != http.StatusBadRequest {
		t.Errorf("an answer for another origin: status %d, want 400", status)
	}
	if status, _ := c.postResponse(page, answerDCAPI(t, data, dcapiOrigin, issuerSigned, device)); status != http.StatusConflict {
		t.Errorf("a second answer to a spent request: status %d, want 409", status)
	}
}

// An mdoc from an issuer the verifier doesn't trust is refused.
func TestDCAPI_RefusesAnUntrustedIssuer(t *testing.T) {
	c := newDCAPIApp(t, newDCAPIIssuer(t))
	page := c.startPage(verifierapp.ScenarioAge)
	data := c.askInBrowser(page)
	issuerSigned, device := newDCAPIIssuer(t).passportMdoc(t, map[string]any{"age_over_18": true})
	if status, body := c.postResponse(page, answerDCAPI(t, data, dcapiOrigin, issuerSigned, device)); status != http.StatusBadRequest {
		t.Errorf("an untrusted issuer's mdoc: status %d: %s", status, body)
	}
}

// Another browser can't start or answer a page's request.
func TestDCAPI_OnlyThePagesBrowser(t *testing.T) {
	c := newDCAPIApp(t, newDCAPIIssuer(t))
	page := c.startPage(verifierapp.ScenarioAge)
	other := &dcapiClient{t: t, srv: c.srv}
	resp := other.do(http.MethodPost, page+"/dcapi", "", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("another browser starting the request: status %d, want 404", resp.StatusCode)
	}
}

// The request is signed with the scenario's mdoc reader authentication
// certificate: a wallet trusting the reader CA, and requiring the
// reader authentication EKU, names the scenario's relying party.
func TestDCAPI_SignedAsAReader(t *testing.T) {
	c := newDCAPIApp(t, newDCAPIIssuer(t))
	data := c.askInBrowser(c.startPage(verifierapp.ScenarioAge))
	raw, _ := json.Marshal(data)
	in, err := mdocdcapi.ParseRequest(raw, dcapiOrigin)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.app.ReaderCACertificate())
	reader, err := in.VerifyReaderTrust(mdocdcapi.ReaderTrust{Roots: roots, LeafPolicy: mdocdcapi.RequireReaderAuthenticationEKU})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := verifierapp.ScenarioAge.Info()
	if reader.Subject.CommonName != info.Verifier {
		t.Errorf("reader %q, want %q", reader.Subject.CommonName, info.Verifier)
	}
	verifierRoots := x509.NewCertPool()
	verifierRoots.AddCert(c.app.VerifierCACertificate())
	if _, err := in.VerifyReader(verifierRoots, time.Time{}); err == nil {
		t.Error("the request verifies under the OpenID4VP verifier CA: its reader certificate isn't separate")
	}
}
