package verifier_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const txBase = "https://verifier.example.com/request-objects"

// txFixture is a verifier with Transactions, and a wallet holding one
// SD-JWT VC it can answer with.
type txFixture struct {
	t     *testing.T
	v     *verifier.Verifier
	txs   *verifier.Transactions
	query dcql.Query
	held  wallet.HeldCredential
	now   time.Time
}

func newTxFixture(t *testing.T, tweak func(*verifier.TransactionsConfig)) *txFixture {
	t.Helper()
	ca, caKey := testcert.CA(t, "tx issuer CA")
	issuerCert, issuerKey := testcert.Leaf(t, "tx issuer", ca, caKey)
	holderKey := testP256Key(t)
	holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:tx:1", CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:tx:1"}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	f := &txFixture{
		t: t, v: newTestVerifier(t), now: time.Now(),
		query: dcql.Query{Credentials: []dcql.CredentialQuery{{
			ID: "cred", Format: sdjwtvc.CredentialFormat, Meta: meta,
			Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
		}}},
		held: wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256},
	}
	cfg := verifier.TransactionsConfig{
		RequestURIBase: txBase, RedirectURI: "https://verifier.example.com/continue?x=1",
		Verify: verifier.VerifyResponseRequest{
			IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: roots}, MaxKeyBindingAge: time.Hour,
			Now: func() time.Time { return f.now },
		},
	}
	if tweak != nil {
		tweak(&cfg)
	}
	if f.txs, err = verifier.NewTransactions(f.v, storage.NewVerifierTransactionStore(), cfg); err != nil {
		t.Fatalf("NewTransactions: %v", err)
	}
	return f
}

// answer is the wallet's direct_post.jwt answer to begun, optionally
// altered before it's encrypted.
func (f *txFixture) answer(begun verifier.Begun, alter func(*wallet.AuthorizationRequest)) string {
	f.t.Helper()
	object, err := f.txs.RequestObject(context.Background(), begun.ID)
	if err != nil {
		f.t.Fatalf("RequestObject: %v", err)
	}
	link, err := url.Parse(begun.Link)
	if err != nil {
		f.t.Fatal(err)
	}
	if want := txBase + "/" + begun.ID; link.Query().Get("request_uri") != want {
		f.t.Fatalf("request_uri = %q, want %q", link.Query().Get("request_uri"), want)
	}
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object, ClientID: link.Query().Get("client_id"), VerifierTrust: wallet.NoVerifierTrust{},
	})
	if err != nil {
		f.t.Fatalf("ParseAuthorizationRequest: %v", err)
	}
	if alter != nil {
		alter(&req)
	}
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: req.Query, Credentials: []wallet.HeldCredential{f.held}, Audience: req.ClientID, Nonce: req.Nonce,
	})
	if err != nil {
		f.t.Fatalf("PresentCredentials: %v", err)
	}
	jwe, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: req.State, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		f.t.Fatalf("BuildDirectPostResponse: %v", err)
	}
	return jwe
}

// errorAnswer is a Wallet error response to begun (OpenID4VP §8.5) —
// which anyone holding the request's public key can send.
func (f *txFixture) errorAnswer(begun verifier.Begun, code, description string) string {
	f.t.Helper()
	object, err := f.txs.RequestObject(context.Background(), begun.ID)
	if err != nil {
		f.t.Fatalf("RequestObject: %v", err)
	}
	link, _ := url.Parse(begun.Link)
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object, ClientID: link.Query().Get("client_id"), VerifierTrust: wallet.NoVerifierTrust{},
	})
	if err != nil {
		f.t.Fatalf("ParseAuthorizationRequest: %v", err)
	}
	payload, err := json.Marshal(map[string]string{"error": code, "error_description": description, "state": req.State})
	if err != nil {
		f.t.Fatal(err)
	}
	compact, err := jwe.Encrypt(req.ResponseEncryptionKey, jwe.Enc(req.ResponseEncryptionEnc), payload, jwe.EncryptOptions{KeyID: req.ResponseEncryptionKeyID})
	if err != nil {
		f.t.Fatalf("Encrypt: %v", err)
	}
	return compact
}

func (f *txFixture) begin(binding string, sameDevice bool) verifier.Begun {
	f.t.Helper()
	begun, err := f.txs.Begin(context.Background(), f.query, binding, sameDevice)
	if err != nil {
		f.t.Fatalf("Begin: %v", err)
	}
	return begun
}

func TestTransactions_CrossDevice(t *testing.T) {
	f := newTxFixture(t, nil)
	ctx := context.Background()
	begun := f.begin("browser-A", false)
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-A"); err != nil || view.Status != verifier.TransactionPending {
		t.Fatalf("Lookup before answer = %+v, %v", view, err)
	}

	jwe := f.answer(begun, nil)
	answered, err := f.txs.HandleResponse(ctx, jwe)
	if err != nil || answered.ID != begun.ID || answered.RedirectURI != "" {
		t.Fatalf("HandleResponse = %+v, %v", answered, err)
	}
	view, err := f.txs.Lookup(ctx, begun.ID, "browser-A")
	if err != nil || view.Status != verifier.TransactionDone || view.Result == nil || view.Result.Credentials[0].Claims["given_name"] != "Jean" {
		t.Fatalf("Lookup after answer = %+v, %v", view, err)
	}
	if _, err := f.txs.Lookup(ctx, begun.ID, "browser-B"); !errors.Is(err, verifier.ErrWrongBrowser) {
		t.Errorf("Lookup from another browser: %v, want ErrWrongBrowser", err)
	}
	if _, err := f.txs.HandleResponse(ctx, jwe); !errors.Is(err, verifier.ErrTransactionAnswered) {
		t.Errorf("replayed answer: %v, want ErrTransactionAnswered", err)
	}
	if _, err := f.txs.RequestObject(ctx, begun.ID); err == nil {
		t.Error("the request object is still served after the request completed")
	}
}

func TestTransactions_SameDevice(t *testing.T) {
	ctx := context.Background()
	redirectCode := func(t *testing.T, f *txFixture, begun verifier.Begun) string {
		t.Helper()
		answered, err := f.txs.HandleResponse(ctx, f.answer(begun, nil))
		if err != nil {
			t.Fatalf("HandleResponse: %v", err)
		}
		u, err := url.Parse(answered.RedirectURI)
		if err != nil || !strings.HasPrefix(answered.RedirectURI, "https://verifier.example.com/continue?") || u.Query().Get("x") != "1" {
			t.Fatalf("redirect_uri %q doesn't extend TransactionsConfig.RedirectURI", answered.RedirectURI)
		}
		return u.Query().Get("response_code")
	}

	t.Run("released to the browser that asked, once", func(t *testing.T) {
		f := newTxFixture(t, nil)
		begun := f.begin("browser-A", true)
		code := redirectCode(t, f, begun)
		if view, _ := f.txs.Lookup(ctx, begun.ID, "browser-A"); view.Status != verifier.TransactionAwaitingRedirect || view.Result != nil {
			t.Fatalf("before redeem: %+v, want awaiting redirect and no result", view)
		}
		view, err := f.txs.Redeem(ctx, code, "browser-A")
		if err != nil || view.Status != verifier.TransactionDone || view.Result == nil {
			t.Fatalf("Redeem = %+v, %v", view, err)
		}
		if _, err := f.txs.Redeem(ctx, code, "browser-A"); !errors.Is(err, verifier.ErrTransactionUnknown) {
			t.Errorf("second Redeem: %v, want ErrTransactionUnknown", err)
		}
	})
	t.Run("another browser closes it", func(t *testing.T) {
		f := newTxFixture(t, nil)
		begun := f.begin("browser-A", true)
		code := redirectCode(t, f, begun)
		if _, err := f.txs.Redeem(ctx, code, "attacker-browser"); !errors.Is(err, verifier.ErrWrongBrowser) {
			t.Fatalf("Redeem from another browser: %v, want ErrWrongBrowser", err)
		}
		view, err := f.txs.Lookup(ctx, begun.ID, "browser-A")
		if err != nil || view.Status != verifier.TransactionClosed || view.Result != nil || view.LastError == "" {
			t.Errorf("after a wrong-browser redirect: %+v, %v; want closed with no result", view, err)
		}
		if _, err := f.txs.Redeem(ctx, code, "browser-A"); err == nil {
			t.Error("the code redeemed after a wrong-browser attempt")
		}
	})
	t.Run("needs a binding and a redirect URI", func(t *testing.T) {
		f := newTxFixture(t, nil)
		for _, sameDevice := range []bool{false, true} {
			if _, err := f.txs.Begin(ctx, f.query, "", sameDevice); err == nil {
				t.Errorf("a request (same-device %v) began without a browser binding", sameDevice)
			}
		}
		g := newTxFixture(t, func(c *verifier.TransactionsConfig) { c.RedirectURI = "" })
		if _, err := g.txs.Begin(ctx, g.query, "b", true); err == nil {
			t.Error("a same-device request began without a RedirectURI")
		}
	})
}

// TestTransactions_RefusedAnswersLeaveItOpen: a wrong nonce, a wrong
// state, the Wallet's error response and an Accept refusal are all
// recorded, and the request can still be answered.
func TestTransactions_RefusedAnswersLeaveItOpen(t *testing.T) {
	ctx := context.Background()
	var refuse bool
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) {
		c.Accept = func(context.Context, string, verifier.VerifyResponseResult) error {
			if refuse {
				return errors.New("revoked")
			}
			return nil
		}
	})
	begun := f.begin("browser-A", false)

	refusals := map[string]string{
		"wrong nonce": f.answer(begun, func(r *wallet.AuthorizationRequest) { r.Nonce = "not-the-nonce" }),
		"wrong state": f.answer(begun, func(r *wallet.AuthorizationRequest) { r.State = "not-the-state" }),
	}
	for name, jwe := range refusals {
		if _, err := f.txs.HandleResponse(ctx, jwe); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	refuse = true
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("Accept refusal: %v", err)
	}
	view, err := f.txs.Lookup(ctx, begun.ID, "browser-A")
	if err != nil || view.Status != verifier.TransactionPending || !strings.Contains(view.LastError, "revoked") {
		t.Fatalf("after refusals: %+v, %v; want still pending, with the last reason", view, err)
	}
	refuse = false
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
		t.Fatalf("a valid answer after refusals: %v", err)
	}
}

func TestTransactions_ExpiryAndClose(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) { c.Lifetime = time.Minute })
	expired := f.begin("browser-A", false)
	jwe := f.answer(expired, nil)
	f.now = f.now.Add(2 * time.Minute)
	if _, err := f.txs.HandleResponse(ctx, jwe); !errors.Is(err, verifier.ErrTransactionExpired) {
		t.Errorf("answer after expiry: %v, want ErrTransactionExpired", err)
	}
	if view, _ := f.txs.Lookup(ctx, expired.ID, "browser-A"); view.Status != verifier.TransactionExpired {
		t.Errorf("Lookup after expiry: %v, want expired", view.Status)
	}

	f.now = time.Now()
	closed := f.begin("browser-A", false)
	jwe = f.answer(closed, nil)
	if err := f.txs.Close(ctx, closed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.txs.HandleResponse(ctx, jwe); !errors.Is(err, verifier.ErrTransactionClosed) {
		t.Errorf("answer after Close: %v, want ErrTransactionClosed", err)
	}
}

// TestTransactions_CompletesOnce: of concurrent valid answers to one
// request, exactly one completes it.
func TestTransactions_CompletesOnce(t *testing.T) {
	f := newTxFixture(t, nil)
	begun := f.begin("browser-A", false)
	answers := make([]string, 8)
	for i := range answers {
		answers[i] = f.answer(begun, nil)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	completed := 0
	for _, jwe := range answers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.txs.HandleResponse(context.Background(), jwe); err == nil {
				mu.Lock()
				completed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if completed != 1 {
		t.Errorf("%d concurrent answers completed the request, want exactly 1", completed)
	}
}

func TestTransactions_Handlers(t *testing.T) {
	f := newTxFixture(t, nil)
	mux := http.NewServeMux()
	mux.Handle("GET /request-objects/{id}", f.txs.RequestObjectHandler())
	mux.Handle("POST /response", f.txs.ResponseHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	begun := f.begin("browser-A", true)
	resp, err := http.Get(srv.URL + "/request-objects/" + begun.ID)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/oauth-authz-req+jwt" {
		t.Fatalf("GET request object: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	if resp, _ := http.Get(srv.URL + "/request-objects/unknown"); resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown request object: %v, want 404", resp)
	}

	post := func(jwe string) (int, map[string]string) {
		resp, err := http.PostForm(srv.URL+"/response", url.Values{"response": {jwe}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}
	status, body := post(f.answer(begun, func(r *wallet.AuthorizationRequest) { r.Nonce = "wrong" }))
	if status != http.StatusBadRequest || body["error"] != "invalid_request" || strings.Contains(body["error_description"], "nonce") {
		t.Errorf("refused answer: %d %v; want 400 with a generic description", status, body)
	}
	status, body = post(f.answer(begun, nil))
	if status != http.StatusOK || !strings.Contains(body["redirect_uri"], "response_code=") {
		t.Errorf("valid answer: %d %v; want a redirect_uri with a response_code", status, body)
	}
}

func TestNewTransactions_Validates(t *testing.T) {
	v := newTestVerifier(t)
	store := storage.NewVerifierTransactionStore()
	for name, cfg := range map[string]verifier.TransactionsConfig{
		"no request_uri base":       {},
		"relative request_uri base": {RequestURIBase: "/request-objects"},
		"http request_uri base":     {RequestURIBase: "http://verifier.example.com/r"},
		"http redirect_uri":         {RequestURIBase: txBase, RedirectURI: "http://verifier.example.com/c"},
		"negative lifetime":         {RequestURIBase: txBase, Lifetime: -time.Second},
		"per-request fields set":    {RequestURIBase: txBase, Verify: verifier.VerifyResponseRequest{ExpectedNonce: "n"}},
	} {
		if _, err := verifier.NewTransactions(v, store, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := verifier.NewTransactions(v, store, verifier.TransactionsConfig{RequestURIBase: "http://127.0.0.1:9443/r"}); err != nil {
		t.Errorf("loopback http under development: %v", err)
	}

	cfg, deps := validConfig(t)
	cfg.Assurance = verifier.AssuranceProduction
	prod, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.NewTransactions(prod, store, verifier.TransactionsConfig{RequestURIBase: txBase}); err == nil {
		t.Error("an in-memory store was accepted under AssuranceProduction")
	}
}

func TestTransactions_HandlerEdges(t *testing.T) {
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) { c.Verify.Now = nil }) // the real clock
	reqObj := httptest.NewServer(f.txs.RequestObjectHandler())                        // no {id} pattern: last path segment
	defer reqObj.Close()
	resp := httptest.NewServer(f.txs.ResponseHandler())
	defer resp.Close()

	begun := f.begin("browser-A", false)
	if r, err := http.Get(reqObj.URL + "/any/prefix/" + begun.ID); err != nil || r.StatusCode != http.StatusOK {
		t.Errorf("request object by last path segment: %v %v", r, err)
	}
	if r, err := http.Post(reqObj.URL+"/"+begun.ID, "text/plain", nil); err != nil || r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST to the request object handler: %v %v", r, err)
	}
	if r, err := http.Get(resp.URL); err != nil || r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET to the response handler: %v %v", r, err)
	}
	if r, err := http.Post(resp.URL, "application/x-www-form-urlencoded", strings.NewReader("%zz")); err != nil || r.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed form: %v %v", r, err)
	}

	jwe := f.answer(begun, nil)
	for i, want := range []int{http.StatusOK, http.StatusBadRequest} {
		r, err := http.PostForm(resp.URL, url.Values{"response": {jwe}})
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = r.Body.Close()
		if r.StatusCode != want {
			t.Errorf("answer %d: status %d, want %d", i+1, r.StatusCode, want)
		}
		if i == 1 && !strings.Contains(body["error_description"], "already been answered") {
			t.Errorf("replayed answer: %v", body)
		}
	}
	if _, err := f.txs.Lookup(context.Background(), "unknown", ""); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Lookup of an unknown request: %v", err)
	}
	if _, err := f.txs.Redeem(context.Background(), "", ""); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Redeem with no code: %v", err)
	}
	if _, err := f.txs.HandleResponse(context.Background(), "not-a-jwe"); err == nil {
		t.Error("a non-JWE answer was accepted")
	}
}

// TestTransactions_LookupNeedsTheBinding: the request's ID is public —
// it's in the request_uri — so a result is released only with the
// binding the request began with.
func TestTransactions_LookupNeedsTheBinding(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-A", false)
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
		t.Fatalf("HandleResponse: %v", err)
	}
	for _, binding := range []string{"", "browser-B"} {
		if view, err := f.txs.Lookup(ctx, begun.ID, binding); !errors.Is(err, verifier.ErrWrongBrowser) || view.Result != nil {
			t.Errorf("Lookup(binding %q) = %+v, %v; want ErrWrongBrowser and no result", binding, view, err)
		}
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-A"); err != nil || view.Result == nil {
		t.Errorf("Lookup with the binding = %+v, %v; want the result", view, err)
	}
}

// TestTransactions_LastErrorFromAWalletErrorIsItsCodeOnly: an error
// response's description is the sender's text, so LastError keeps only
// a plain error code.
func TestTransactions_LastErrorFromAWalletErrorIsItsCodeOnly(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-A", false)
	for _, c := range []struct{ code, want string }{
		{"access_denied", "the wallet returned an error: access_denied"},
		{"Call +1 555 0100 <b>now</b>", "the wallet returned an error"},
	} {
		if _, err := f.txs.HandleResponse(ctx, f.errorAnswer(begun, c.code, "Your account is locked, call +1 555 0100")); err == nil {
			t.Fatal("an error response was accepted")
		}
		view, err := f.txs.Lookup(ctx, begun.ID, "browser-A")
		if err != nil || view.Status != verifier.TransactionPending || view.LastError != c.want {
			t.Errorf("code %q: LastError = %q (%+v, %v); want %q and still pending", c.code, view.LastError, view, err, c.want)
		}
	}
}

// TestTransactions_LastErrorIsShortAndPrintable: a refusal's text is
// cut to a bounded length and unprintable characters are replaced.
func TestTransactions_LastErrorIsShortAndPrintable(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) {
		c.Accept = func(context.Context, string, verifier.VerifyResponseResult) error {
			return errors.New("line one\nline two\x00" + strings.Repeat("x", 1000))
		}
	})
	begun := f.begin("browser-A", false)
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err == nil {
		t.Fatal("refused answer was accepted")
	}
	view, err := f.txs.Lookup(ctx, begun.ID, "browser-A")
	if err != nil {
		t.Fatal(err)
	}
	if len(view.LastError) > 300 || strings.ContainsAny(view.LastError, "\n\x00") || !strings.HasPrefix(view.LastError, "line one?line two?") {
		t.Errorf("LastError = %q (%d bytes), want at most ~256 printable bytes", view.LastError, len(view.LastError))
	}
}
