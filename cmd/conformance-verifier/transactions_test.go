package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// txTestSetup is a transactions engine configuration whose issuer CA
// issued held, an SD-JWT VC of the configured vct with the configured
// claims, which a wallet can present.
type txTestSetup struct {
	cfg  Config
	held wallet.HeldCredential
}

func newTxTestSetup(t *testing.T) txTestSetup {
	t.Helper()
	issuerKey, _, issuerCertPEM, caPEM, err := conformancecert.GenerateSignerAndCert("tx issuer", "tx issuer CA")
	if err != nil {
		t.Fatal(err)
	}
	clientKey, clientKeyPEM, clientCertPEM, _, err := conformancecert.GenerateSignerAndCert("tx client", "tx client CA")
	if err != nil || clientKey == nil {
		t.Fatal(err)
	}
	issuerCert, err := conformancecert.ParseCertificatePEM(issuerCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Jean"), "family_name": sdjwtvc.SD("Dupont")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		t.Fatal(err)
	}
	cfg := baseTestConfig(t)
	cfg.ClientCertificatePEM, cfg.ClientPrivateKeyPEM = clientCertPEM, clientKeyPEM
	cfg.CredentialIssuerJWK = nil
	cfg.CredentialIssuerTrustAnchorsPEM = caPEM
	cfg.RejectUnverifiedResponses = true
	cfg.Engine = engineTransactions
	return txTestSetup{cfg: cfg, held: wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}}
}

// txBrowser is a browser against the transactions engine's routes: it
// keeps the binding cookie /authorize sets.
type txBrowser struct {
	t      *testing.T
	mux    http.Handler
	cookie *http.Cookie
}

func (b *txBrowser) do(method, target string, body url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body.Encode()))
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if b.cookie != nil {
		req.AddCookie(b.cookie)
	}
	rec := httptest.NewRecorder()
	b.mux.ServeHTTP(rec, req)
	return rec
}

// begin begins a request at /authorize, keeping its cookie, and
// returns its ID and the Wallet's view of its Request Object.
func (b *txBrowser) begin() (string, wallet.AuthorizationRequest) {
	b.t.Helper()
	rec := b.do(http.MethodGet, "/authorize", nil)
	if rec.Code != http.StatusFound {
		b.t.Fatalf("GET /authorize = %d: %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == bindingCookie {
			if !c.Secure || !c.HttpOnly || len(c.Value) < verifier.MinBrowserBindingLength {
				b.t.Fatalf("binding cookie = %+v, want a long Secure HttpOnly one", c)
			}
			b.cookie = c
		}
	}
	if b.cookie == nil {
		b.t.Fatal("GET /authorize set no binding cookie")
	}
	link, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || link.Scheme != "openid4vp" {
		b.t.Fatalf("Location = %q, want an openid4vp:// link", rec.Header().Get("Location"))
	}
	requestURI, err := url.Parse(link.Query().Get("request_uri"))
	if err != nil || !strings.HasPrefix(requestURI.Path, "/request/") || link.Query().Get("request_uri_method") != "post" {
		b.t.Fatalf("link = %q, want a /request/{id} request_uri and request_uri_method=post", link)
	}
	// Fetched as the suite's Wallet fetches it (OpenID4VP 1.0 §5.10).
	const walletNonce = "wallet-nonce"
	object := b.do(http.MethodPost, requestURI.Path, url.Values{
		"wallet_nonce": {walletNonce}, "wallet_metadata": {`{"vp_formats_supported":{"dc+sd-jwt":{},"mso_mdoc":{}}}`},
	})
	if object.Code != http.StatusOK || object.Header().Get("Content-Type") != "application/oauth-authz-req+jwt" {
		b.t.Fatalf("POST %s = %d %q", requestURI.Path, object.Code, object.Header().Get("Content-Type"))
	}
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object.Body.String(), ClientID: link.Query().Get("client_id"), VerifierTrust: wallet.NoVerifierTrust{}, WalletNonce: walletNonce,
	})
	if err != nil {
		b.t.Fatalf("ParseAuthorizationRequest: %v", err)
	}
	return strings.TrimPrefix(requestURI.Path, "/request/"), req
}

// answer posts the wallet's direct_post.jwt answer to req, presenting
// held, to the response endpoint.
func (b *txBrowser) answer(req wallet.AuthorizationRequest, held wallet.HeldCredential, nonce string) *httptest.ResponseRecorder {
	b.t.Helper()
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: req.Query, Credentials: []wallet.HeldCredential{held}, Audience: req.ClientID, Nonce: nonce,
	})
	if err != nil {
		b.t.Fatalf("PresentCredentials: %v", err)
	}
	response, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: req.State, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		b.t.Fatalf("BuildDirectPostResponse: %v", err)
	}
	return b.do(http.MethodPost, "/response", url.Values{"response": {response}})
}

// checkTransactionsFlow runs the suite's two kinds of module against
// cfg's transactions engine: a presentation it must accept, redeemed
// by the bound browser alone, and one it must refuse.
func checkTransactionsFlow(t *testing.T, s txTestSetup) {
	t.Helper()
	mux, _, err := newHandler(s.cfg)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	b := &txBrowser{t: t, mux: mux}

	id, req := b.begin()
	// A Wallet that doesn't support POST fetches by GET (OpenID4VP 1.0 §5.1).
	if rec := b.do(http.MethodGet, "/request/"+id, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /request/%s = %d, want 200", id, rec.Code)
	}
	if page := b.do(http.MethodGet, "/result/"+id, nil); !strings.Contains(page.Body.String(), "<h1>Pending</h1>") {
		t.Fatalf("result page before an answer = %s, want Pending", page.Body)
	}
	answered := b.answer(req, s.held, req.Nonce)
	if answered.Code != http.StatusOK {
		t.Fatalf("POST /response = %d: %s", answered.Code, answered.Body)
	}
	redirect := decodeRedirectURI(t, answered.Body.String())
	if redirect.Path != "/result" || redirect.Query().Get("response_code") == "" {
		t.Fatalf("redirect_uri = %q, want /result with a response_code", redirect)
	}
	if page := b.do(http.MethodGet, "/result/"+id, nil); !strings.Contains(page.Body.String(), "<h1>Pending</h1>") {
		t.Fatalf("result page before the redirect back = %s, want Pending", page.Body)
	}
	if page := b.do(http.MethodGet, redirect.RequestURI(), nil); page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Verification succeeded") || !strings.Contains(page.Body.String(), "Jean") {
		t.Fatalf("redirect back = %d %s, want the verified claims", page.Code, page.Body)
	}
	if page := b.do(http.MethodGet, redirect.RequestURI(), nil); page.Code != http.StatusForbidden {
		t.Fatalf("redeeming the response_code again = %d, want 403", page.Code)
	}
	if page := b.do(http.MethodGet, "/result/"+id, nil); !strings.Contains(page.Body.String(), "Verification succeeded") {
		t.Fatalf("result page = %s, want succeeded", page.Body)
	}
	other := &txBrowser{t: t, mux: mux}
	if page := other.do(http.MethodGet, "/result/"+id, nil); page.Code != http.StatusForbidden {
		t.Fatalf("result page in another browser = %d, want 403", page.Code)
	}
	if rec := b.answer(req, s.held, req.Nonce); rec.Code != http.StatusBadRequest {
		t.Fatalf("a second answer = %d, want 400", rec.Code)
	}

	// A presentation bound to another nonce is refused, recorded, and
	// the request stays open.
	id, req = b.begin()
	if rec := b.answer(req, s.held, "another nonce"); rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "redirect_uri") {
		t.Fatalf("a presentation with the wrong nonce = %d %s, want 400 without a redirect_uri", rec.Code, rec.Body)
	}
	// The page shows LastError's fixed description, then the refusal's
	// verifier.Reason and its own text (OnRefused), which the drivers
	// grade by.
	page := b.do(http.MethodGet, "/result/"+id, nil).Body.String()
	for _, want := range []string{"<h1>Verification failed</h1>", "(holder_binding)</pre>", "<pre>reason: holder_binding</pre>", "nonce"} {
		if !strings.Contains(page, want) {
			t.Fatalf("result page = %s, want it to hold %q", page, want)
		}
	}
}

func decodeRedirectURI(t *testing.T, body string) *url.URL {
	t.Helper()
	var answer struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	u, err := url.Parse(answer.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTransactionsEngine_Flow(t *testing.T) {
	checkTransactionsFlow(t, newTxTestSetup(t))
}

func TestTransactionsEngine_RedirectBack(t *testing.T) {
	mux, _, err := newHandler(newTxTestSetup(t).cfg)
	if err != nil {
		t.Fatal(err)
	}
	b := &txBrowser{t: t, mux: mux}
	if page := b.do(http.MethodGet, "/result?error=access_denied", nil); !strings.Contains(page.Body.String(), "Verification failed") || !strings.Contains(page.Body.String(), "access_denied") {
		t.Fatalf("an error redirect = %s, want failed with the error", page.Body)
	}
	if page := b.do(http.MethodGet, "/result?response_code=unknown", nil); page.Code != http.StatusForbidden {
		t.Fatalf("an unknown response_code = %d, want 403", page.Code)
	}
	if page := b.do(http.MethodGet, "/result/unknown", nil); page.Code != http.StatusNotFound {
		t.Fatalf("an unknown request = %d, want 404", page.Code)
	}
	if rec := b.do(http.MethodGet, "/response", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /response = %d, want 405", rec.Code)
	}
}

func TestWriteView(t *testing.T) {
	cases := []struct {
		view verifier.TransactionView
		want string
	}{
		{verifier.TransactionView{ID: "a", Status: verifier.TransactionPending}, "<h1>Pending</h1>"},
		{verifier.TransactionView{ID: "a", Status: verifier.TransactionAwaitingRedirect}, "<h1>Pending</h1>"},
		{verifier.TransactionView{ID: "a", Status: verifier.TransactionPending, LastError: "<refused>"}, "&lt;refused&gt;"},
		{verifier.TransactionView{ID: "a", Status: verifier.TransactionClosed}, "<h1>Verification failed</h1>"},
		{verifier.TransactionView{ID: "a", Status: verifier.TransactionExpired}, "<h1>Verification failed</h1>"},
		{verifier.TransactionView{ID: "a", Status: verifier.TransactionDone}, "<h1>Verification succeeded</h1>"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		(&txServer{}).writeView(rec, c.view)
		if !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("writeView(%+v) = %s, want %s", c.view, rec.Body, c.want)
		}
	}
}

func TestNewHandler(t *testing.T) {
	if _, clientID, err := newHandler(baseTestConfig(t)); err != nil || !strings.HasPrefix(clientID, "x509_hash:") {
		t.Fatalf("newHandler(sessions) = %q, %v", clientID, err)
	}
	broken := baseTestConfig(t)
	broken.ClientCertificatePEM = ""
	if _, _, err := newHandler(broken); err == nil {
		t.Fatal("newHandler(sessions, no client certificate) = nil error")
	}
	for name, mutate := range map[string]func(*Config){
		"client_certificate_pem":              func(c *Config) { c.ClientCertificatePEM = "" },
		"credential_issuer_trust_anchors_pem": func(c *Config) { c.CredentialIssuerTrustAnchorsPEM = "not a certificate" },
		"status_list_trust_anchors_pem":       func(c *Config) { c.StatusListTrustAnchorsPEM = "not a certificate" },
		"credential_format":                   func(c *Config) { c.CredentialFormat = "jwt_vc_json" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := newTxTestSetup(t).cfg
			mutate(&cfg)
			if _, _, err := newHandler(cfg); err == nil {
				t.Fatalf("newHandler(transactions) = nil error, want one for %s", name)
			}
		})
	}
}

func TestLoadConfig_Engine(t *testing.T) {
	production := &ProductionConfig{DatabasePath: "/tmp/v.sqlite", SealingKey: "a2V5"}
	for name, c := range map[string]struct {
		mutate func(*Config)
		ok     bool
	}{
		"sessions":                         {func(c *Config) { c.Engine = engineSessions }, true},
		"transactions":                     {func(c *Config) { c.Engine = engineTransactions }, true},
		"transactions production":          {func(c *Config) { c.Engine, c.Production = engineTransactions, production }, true},
		"unknown":                          {func(c *Config) { c.Engine = "other" }, false},
		"production without engine":        {func(c *Config) { c.Production = production }, false},
		"production without a key":         {func(c *Config) { c.Engine, c.Production = engineTransactions, &ProductionConfig{DatabasePath: "x"} }, false},
		"transactions with dc_api_origins": {func(c *Config) { c.Engine, c.DCAPIOrigins = engineTransactions, []string{testOrigin} }, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			c.mutate(&cfg)
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); (err == nil) != c.ok {
				t.Fatalf("loadConfig = %v, want ok %v", err, c.ok)
			}
		})
	}
}

func TestConfig_IssuerAuthorized(t *testing.T) {
	sdjwt := baseTestConfig(t).issuerAuthorized()
	mdoc := mdocTestConfig(t).issuerAuthorized()
	ctx := context.Background()
	for name, c := range map[string]struct {
		authorize func(context.Context, verifier.IssuerAuthorization) error
		types     []string
		ok        bool
	}{
		"the vct":          {sdjwt, []string{"urn:eudi:pid:1"}, true},
		"another vct":      {sdjwt, []string{"urn:eudi:pid:1", "urn:other"}, false},
		"no type":          {sdjwt, nil, false},
		"the doctype":      {mdoc, []string{"org.iso.18013.5.1.mDL"}, true},
		"the vct for mdoc": {mdoc, []string{"urn:eudi:pid:1"}, false},
	} {
		if err := c.authorize(ctx, verifier.IssuerAuthorization{MatchedTypes: c.types}); (err == nil) != c.ok {
			t.Errorf("%s: issuerAuthorized = %v, want ok %v", name, err, c.ok)
		}
	}
}

func TestSetStatusCheck(t *testing.T) {
	var none verifier.TransactionsConfig
	setStatusCheck(&none, nil, verifier.AssuranceProduction)
	if !none.NoStatusCheck || none.Status != nil || none.Accept != nil {
		t.Fatalf("without a policy = %+v, want NoStatusCheck", none)
	}

	hardened := &verifier.StatusPolicy{Checker: statuslist.Checker{}}
	var direct verifier.TransactionsConfig
	setStatusCheck(&direct, hardened, verifier.AssuranceProduction)
	if direct.Status != hardened || direct.NoStatusCheck || direct.Accept != nil {
		t.Fatalf("a hardened policy under production = %+v, want it as Status", direct)
	}

	private := &verifier.StatusPolicy{Checker: statuslist.Checker{Fetcher: statuslist.Fetcher{AllowPrivate: true}}}
	var dev verifier.TransactionsConfig
	setStatusCheck(&dev, private, verifier.AssuranceDevelopment)
	if dev.Status != private {
		t.Fatalf("a private-address policy under development = %+v, want it as Status", dev)
	}

	// Under production, a policy reaching private addresses runs as the
	// Accept: a credential without a status reference the policy
	// requires is refused there.
	private.RequireReference = true
	var prod verifier.TransactionsConfig
	setStatusCheck(&prod, private, verifier.AssuranceProduction)
	if prod.Status != nil || !prod.NoStatusCheck || prod.Accept == nil {
		t.Fatalf("a private-address policy under production = %+v, want NoStatusCheck and an Accept", prod)
	}
	err := prod.Accept(context.Background(), "id", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{CredentialQueryID: "cred1"}}})
	if err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("Accept = %v, want the status policy's refusal of a credential without the status reference it requires", err)
	}
}
