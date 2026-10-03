package webwallet_test

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// browser is an HTTP client that, like a person clicking through the
// pages, sees each redirect rather than following it automatically.
// browser is a browser for env: it keeps cookies, and stops at each
// redirect so a test can follow the flow step by step.
func browser(env *demotest.Env) *http.Client {
	c := *env.HTTP
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	c.Jar = jar
	return &c
}

// approvalTag is the interaction tag in the issuer's approval page, as a
// holder's browser posts it back.
func approvalTag(t *testing.T, page string) string {
	t.Helper()
	tag, err := walletapp.ApprovalTag([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

func read(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	// html/template escapes characters like "+" (dc+sd-jwt → dc&#43;sd-jwt).
	return html.UnescapeString(string(b))
}

func mustRedirect(t *testing.T, resp *http.Response, err error, step string) *url.URL {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", step, err)
	}
	_ = resp.Body.Close()
	loc, locErr := resp.Location()
	if locErr != nil {
		t.Fatalf("%s: status %d, no redirect", step, resp.StatusCode)
	}
	return loc
}

// receiveViaBrowser clicks through receiving an offer in the web
// wallet: wallet → issuer approval page → approve → back to the wallet.
func receiveViaBrowser(t *testing.T, env *demotest.Env, b *http.Client) {
	t.Helper()
	offer, err := env.Issuer.CreateTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	// The confirmation page (GET) must not start anything by itself.
	resp, err := b.Get(env.WebWalletURL + "/receive?offer=" + url.QueryEscape(offer.URI))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /receive: %v %v", resp, err)
	}
	if page := read(t, resp); !strings.Contains(page, env.IssuerURL) {
		t.Error("confirmation page doesn't name the issuer")
	}

	resp, err = b.PostForm(env.WebWalletURL+"/receive", url.Values{"offer": {offer.URI}})
	authorize := mustRedirect(t, resp, err, "POST /receive")
	if !strings.HasPrefix(authorize.String(), env.IssuerURL+"/authorize") {
		t.Fatalf("wallet redirected to %s, want the issuer's authorization endpoint", authorize)
	}
	resp, err = b.Get(authorize.String())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	page := read(t, resp)
	tag := approvalTag(t, page)
	// The approval page is shown before the confirmation code is checked,
	// so it must not show the passport's data.
	if strings.Contains(page, "DOE") || strings.Contains(page, "K0000000A") {
		t.Error("the issuer's approval page shows passport data before the confirmation code")
	}
	resp, err = b.PostForm(env.IssuerURL+"/authorize/decision", url.Values{"interaction": {tag}, "decision": {"approve"}, "code": {offer.ConfirmationCode}})
	callback := mustRedirect(t, resp, err, "approve")
	if !strings.HasPrefix(callback.String(), env.WebWalletURL+"/callback") {
		t.Fatalf("issuer redirected to %s, want the web wallet's callback", callback)
	}
	resp, err = b.Get(callback.String())
	home := mustRedirect(t, resp, err, "GET /callback")
	if home.Query().Get("received") != "2" {
		t.Fatalf("wallet reported %q received, want 2", home.Query().Get("received"))
	}
}

// openConsent follows a web wallet /present link: the GET shows a
// confirmation page (fetching nothing), whose form POSTs the request
// for review. It returns the consent page.
func openConsent(t *testing.T, env *demotest.Env, b *http.Client, presentURL string) string {
	t.Helper()
	resp, err := b.Get(presentURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /present: %v %v", resp, err)
	}
	m := regexp.MustCompile(`name="request" value="([^"]+)"`).FindStringSubmatch(read(t, resp))
	if m == nil {
		t.Fatal("the /present confirmation page has no review form")
	}
	resp, err = b.PostForm(env.WebWalletURL+"/present", url.Values{"request": {html.UnescapeString(m[1])}})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /present: %v %v", resp, err)
	}
	return read(t, resp)
}

// reviewRequest opens a verifier request in the web wallet and returns
// the consent page and its decision URL.
// credentialOption is the consent page's first option for sharing a
// credential of format: its input's value.
func credentialOption(t *testing.T, page, format string) string {
	t.Helper()
	return credentialOptions(t, page, format)[0]
}

// credentialOptions are the consent page's options for sharing a
// credential of format.
func credentialOptions(t *testing.T, page, format string) []string {
	t.Helper()
	ms := regexp.MustCompile(`name="credential" value="([^"]+)"[^>]*>[^<]*(?:<strong>[^<]*</strong>[^<]*)? as <span class="fmt">`+regexp.QuoteMeta(format)+`<`).FindAllStringSubmatch(page, -1)
	if ms == nil {
		t.Fatalf("the consent page offers no %s credential", format)
	}
	var out []string
	for _, m := range ms {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

func reviewRequest(t *testing.T, env *demotest.Env, b *http.Client, mode verifierapp.Mode) (id, page, decisionURL string) {
	t.Helper()
	id, link, err := env.Verifier.CreateRequest(mode)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	page = openConsent(t, env, b, env.WebWalletURL+"/present?request="+url.QueryEscape(link))
	m := regexp.MustCompile(`action="(/present/[^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("consent page has no decision form")
	}
	return id, page, env.WebWalletURL + m[1]
}

func TestWebWallet_ReceiveThenShareWithConsent(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	store := walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")}
	env.StartWebWallet(t, store)
	b := browser(env)

	receiveViaBrowser(t, env, b)

	resp, err := b.Get(env.WebWalletURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	home := read(t, resp)
	if strings.Count(home, "DOE") < 2 || !strings.Contains(home, "mso_mdoc") || !strings.Contains(home, "dc+sd-jwt") {
		t.Error("home page doesn't show both received credentials")
	}
	if strings.Count(home, `<img src="data:image/jpeg;base64,`) != 2 {
		t.Error("home page doesn't show the portrait on both credentials")
	}

	// The consent screen shows what's asked for, in each format the
	// wallet can answer with — and nothing is sent yet.
	id, page, decision := reviewRequest(t, env, b, verifierapp.ModeICAO)
	for _, want := range []string{"passport-vdc demo verifier", "gmrtd_verifiable_doc", `as <span class="fmt">mso_mdoc`, `as <span class="fmt">dc+sd-jwt`, "JANE DOE"} {
		if !strings.Contains(page, want) {
			t.Errorf("consent page is missing %q", want)
		}
	}
	if strings.Contains(page, "family_name") {
		t.Error("consent page offers to disclose family_name, which wasn't requested")
	}
	if _, answered := env.Verifier.Outcome(id); answered {
		t.Fatal("the verifier got an answer before the holder consented")
	}

	resp, err = b.PostForm(decision, url.Values{"decision": {"share"}, "credential": {credentialOption(t, page, "dc+sd-jwt")}})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if done := read(t, resp); !strings.Contains(done, "Shared passport_sdjwt") {
		t.Errorf("share result page: status %d", resp.StatusCode)
	}
	outcome, ok := env.Verifier.Outcome(id)
	if !ok || outcome.Format != "dc+sd-jwt" {
		t.Fatalf("verifier outcome = %+v (ok %v), want a verified dc+sd-jwt presentation", outcome, ok)
	}
}

func TestWebWallet_DeclineSendsNothing(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	store := walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")}
	env.StartWebWallet(t, store)
	b := browser(env)
	receiveViaBrowser(t, env, b)

	id, _, decision := reviewRequest(t, env, b, verifierapp.ModeIssuer)
	resp, err := b.PostForm(decision, url.Values{"decision": {"decline"}})
	if err != nil {
		t.Fatalf("decline: %v", err)
	}
	if page := read(t, resp); !strings.Contains(page, "nothing was shared") {
		t.Error("decline page doesn't say nothing was shared")
	}
	if _, answered := env.Verifier.Outcome(id); answered {
		t.Error("the verifier got an answer after the holder declined")
	}

	// The decision is single-use.
	resp, err = b.PostForm(decision, url.Values{"decision": {"share"}})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("a used consent decision could be replayed")
	}
}

func TestWebWallet_RejectsNonOfferLinks(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	b := browser(env)
	resp, err := b.PostForm(env.WebWalletURL+"/receive", url.Values{"offer": {"https://example.com/not-an-offer"}})
	if err != nil {
		t.Fatalf("POST /receive: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	resp, err = b.Get(env.WebWalletURL + "/present?request=" + url.QueryEscape("https://example.com/x"))
	if err != nil {
		t.Fatalf("GET /present: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

// TestWebWallet_DuplicateCallbackDoesNotHang delivers the issuer's
// redirect twice at once: one completes the receive, the other is
// refused, and neither is left waiting.
func TestWebWallet_DuplicateCallbackDoesNotHang(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	b := browser(env)
	b.Timeout = 20 * time.Second

	offer, err := env.Issuer.CreateTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	resp, err := b.PostForm(env.WebWalletURL+"/receive", url.Values{"offer": {offer.URI}})
	authorize := mustRedirect(t, resp, err, "POST /receive")
	resp, err = b.Get(authorize.String())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	tag := approvalTag(t, read(t, resp))
	resp, err = b.PostForm(env.IssuerURL+"/authorize/decision", url.Values{"interaction": {tag}, "decision": {"approve"}, "code": {offer.ConfirmationCode}})
	callback := mustRedirect(t, resp, err, "approve")

	statuses := make(chan int, 2)
	for range 2 {
		go func() {
			resp, err := b.Get(callback.String())
			if err != nil {
				statuses <- 0
				return
			}
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	got := map[int]int{}
	for range 2 {
		got[<-statuses]++
	}
	if got[http.StatusSeeOther] != 1 || got[http.StatusBadRequest] != 1 {
		t.Fatalf("callback statuses = %v, want one 303 and one 400", got)
	}
}

// cookieBrowser is browser with a cookie jar, as the verifier's
// same-device flow binds the result to the browser's session cookie.
func cookieBrowser(t *testing.T, env *demotest.Env) *http.Client {
	t.Helper()
	b := browser(env)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	b.Jar = jar
	return b
}

// shareSameDevice starts a request on the verifier's page in b, opens it
// in the web wallet from that page's link, shares, and returns the
// verifier's result page path and the redirect_uri the wallet sent b to.
func shareSameDevice(t *testing.T, env *demotest.Env, b *http.Client) (resultPath string, redirect *url.URL) {
	t.Helper()
	resp, err := b.PostForm(env.VerifierURL+"/requests", url.Values{"mode": {"issuer"}})
	resultPath = mustRedirect(t, resp, err, "POST /requests").Path
	resp, err = b.Get(env.VerifierURL + resultPath)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET request page: %v %v", resp, err)
	}
	m := regexp.MustCompile(`href="(` + regexp.QuoteMeta(env.WebWalletURL) + `/present\?request=[^"]+)"`).FindStringSubmatch(read(t, resp))
	if m == nil {
		t.Fatal("the request page has no web wallet link")
	}
	consent := openConsent(t, env, b, html.UnescapeString(m[1]))
	d := regexp.MustCompile(`action="(/present/[^"]+)"`).FindStringSubmatch(consent)
	if d == nil {
		t.Fatal("consent page has no decision form")
	}
	resp, err = b.PostForm(env.WebWalletURL+d[1], url.Values{"decision": {"share"}, "credential": {credentialOption(t, consent, "dc+sd-jwt")}})
	redirect = mustRedirect(t, resp, err, "share")
	if !strings.HasPrefix(redirect.String(), env.VerifierURL+"/continue?response_code=") {
		t.Fatalf("the wallet sent the browser to %s, want the verifier's redirect_uri", redirect)
	}
	return resultPath, redirect
}

// TestSameDevice_RedirectBackReleasesTheResult runs the same-device
// flow (HAIP 1.0 §5.1, OpenID4VP §8.2): the verifier holds the verified
// answer until the wallet brings the same browser back, then shows it.
func TestSameDevice_RedirectBackReleasesTheResult(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	b := cookieBrowser(t, env)
	receiveViaBrowser(t, env, b)

	resultPath, redirect := shareSameDevice(t, env, b)
	id := strings.TrimPrefix(resultPath, "/requests/")
	if _, answered := env.Verifier.Outcome(id); answered {
		t.Fatal("the result was released before the redirect back")
	}
	resp, err := b.Get(redirect.String())
	if back := mustRedirect(t, resp, err, "follow redirect_uri"); back.Path != resultPath {
		t.Fatalf("redirect back led to %s, want %s", back.Path, resultPath)
	}
	resp, err = b.Get(env.VerifierURL + resultPath)
	if err != nil {
		t.Fatalf("GET result page: %v", err)
	}
	if page := read(t, resp); !strings.Contains(page, "Presentation verified") || !strings.Contains(page, "DOE") {
		t.Fatal("the result page doesn't show the verified presentation")
	}

	// The result page is for the browser that asked, and nobody else.
	resp, err = browser(env).Get(env.VerifierURL + resultPath)
	if err != nil {
		t.Fatalf("GET result page without the session cookie: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("result page without the session cookie: status %d, want 404", resp.StatusCode)
	}
}

// TestSameDevice_RedirectInAnotherBrowserIsRejected checks the answer is
// rejected, never shown, when the redirect back arrives in a different
// browser session than the one that asked (HAIP 1.0 §5.1).
func TestSameDevice_RedirectInAnotherBrowserIsRejected(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	b := cookieBrowser(t, env)
	receiveViaBrowser(t, env, b)

	resultPath, redirect := shareSameDevice(t, env, b)
	resp, err := cookieBrowser(t, env).Get(redirect.String())
	if err != nil {
		t.Fatalf("follow redirect_uri elsewhere: %v", err)
	}
	if page := read(t, resp); resp.StatusCode != http.StatusForbidden || strings.Contains(page, "DOE") {
		t.Fatalf("redirect back in another browser: status %d; want 403 without the claims", resp.StatusCode)
	}
	if _, answered := env.Verifier.Outcome(strings.TrimPrefix(resultPath, "/requests/")); answered {
		t.Fatal("the verifier accepted an answer whose redirect came back elsewhere")
	}
	resp, err = b.Get(env.VerifierURL + resultPath)
	if err != nil {
		t.Fatalf("GET result page: %v", err)
	}
	if page := read(t, resp); !strings.Contains(page, "Presentation rejected") || strings.Contains(page, "DOE") {
		t.Fatal("the asking browser's page doesn't show the rejection, or shows the claims")
	}
	// The response_code is single-use: the asking browser can't use it now.
	resp, err = b.Get(redirect.String())
	if err != nil {
		t.Fatalf("reuse redirect_uri: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Error("a used response_code was accepted again")
	}
}

// TestWebWallet_RefusesCallbackInAnotherBrowser starts a receive in one
// browser and delivers the issuer's callback in another — what an
// attacker does to have a victim's browser complete a flow it didn't
// start (login CSRF, RFC 9700 §4.7). The other browser lacks the session
// cookie the receive left in the first, so it's refused, and nothing is
// stored.
func TestWebWallet_RefusesCallbackInAnotherBrowser(t *testing.T) {
	env := demotest.New(t, nil)
	store := walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")}
	env.StartWebWallet(t, store)
	started, other := browser(env), browser(env)

	offer, err := env.Issuer.CreateTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	resp, err := started.PostForm(env.WebWalletURL+"/receive", url.Values{"offer": {offer.URI}})
	authorize := mustRedirect(t, resp, err, "POST /receive")
	resp, err = started.Get(authorize.String())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	tag := approvalTag(t, read(t, resp))
	resp, err = started.PostForm(env.IssuerURL+"/authorize/decision", url.Values{"interaction": {tag}, "decision": {"approve"}, "code": {offer.ConfirmationCode}})
	callback := mustRedirect(t, resp, err, "approve")

	resp, err = other.Get(callback.String())
	if err != nil {
		t.Fatalf("GET /callback in another browser: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("a callback in another browser completed the receive")
	}
	if held, err := store.List(); err != nil || len(held) != 0 {
		t.Errorf("store holds %d credentials (%v) after a refused callback, want none", len(held), err)
	}
}

// TestWebWallet_GETFetchesNothing: opening a /present link — which any
// site can make a browser do — doesn't make the wallet contact the
// request_uri; only the holder's same-origin POST does.
func TestWebWallet_GETFetchesNothing(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	var hits atomic.Int32
	// Plain http on loopback: the demo wallet's fetcher allows it, so an
	// unwanted fetch would reach the handler.
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	link := "openid4vp://?" + url.Values{"client_id": {"x509_hash:abc"}, "request_uri": {target.URL + "/request"}}.Encode()

	resp, err := browser(env).Get(env.WebWalletURL + "/present?request=" + url.QueryEscape(link))
	if err != nil {
		t.Fatalf("GET /present: %v", err)
	}
	page := read(t, resp)
	if n := hits.Load(); n != 0 {
		t.Errorf("GET /present contacted the request_uri %d time(s)", n)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Review the request") {
		t.Errorf("GET /present: status %d, want the confirmation page", resp.StatusCode)
	}
}

// TestWebWallet_RefusesCrossOriginPosts: a form another site posts into
// this wallet — to receive, review or share — is refused.
func TestWebWallet_RefusesCrossOriginPosts(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	for _, path := range []string{"/receive", "/present", "/present/some-id"} {
		req, err := http.NewRequest(http.MethodPost, env.WebWalletURL+path, strings.NewReader("offer=x&request=x&decision=share"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://attacker.example")
		resp, err := browser(env).Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-origin POST %s: status %d, want 403", path, resp.StatusCode)
		}
	}
}

// TestWebWallet_DeferredCredential: a credential the issuer defers is
// listed as waiting; "Check now" reports it's still waiting until the
// operator decides, then stores it.
func TestWebWallet_DeferredCredential(t *testing.T) {
	env := demotest.New(t, nil)
	store := walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")}
	env.StartWebWallet(t, store)
	b := browser(env)

	offer, err := env.Issuer.CreateTransactionForReview(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := b.PostForm(env.WebWalletURL+"/receive", url.Values{"offer": {offer.URI}})
	authorize := mustRedirect(t, resp, err, "POST /receive")
	resp, err = b.Get(authorize.String())
	if err != nil {
		t.Fatal(err)
	}
	tag := approvalTag(t, read(t, resp))
	resp, err = b.PostForm(env.IssuerURL+"/authorize/decision", url.Values{"interaction": {tag}, "decision": {"approve"}, "code": {offer.ConfirmationCode}})
	callback := mustRedirect(t, resp, err, "approve")
	resp, err = b.Get(callback.String())
	home := mustRedirect(t, resp, err, "GET /callback")
	if home.Query().Get("received") != "0" || home.Query().Get("deferred") != "2" {
		t.Fatalf("callback redirect = %s, want 0 received and 2 deferred", home)
	}

	resp, err = b.Get(env.WebWalletURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page := read(t, resp)
	checks := regexp.MustCompile(`action="(/deferred/[^"]+)"`).FindAllStringSubmatch(page, -1)
	if !strings.Contains(page, "Waiting for the issuer") || len(checks) != 2 {
		t.Fatalf("home page doesn't list two credentials waiting:\n%s", page)
	}
	resp, err = b.PostForm(env.WebWalletURL+checks[0][1], nil)
	if waiting := mustRedirect(t, resp, err, "check before a decision"); waiting.Query().Get("waiting") == "" {
		t.Fatalf("check before a decision = %s, want still waiting", waiting)
	}

	for _, rv := range env.Issuer.Reviews() {
		if err := env.Issuer.Review(rv.Ref, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range checks {
		resp, err = b.PostForm(env.WebWalletURL+c[1], nil)
		if got := mustRedirect(t, resp, err, "check after approval"); got.Query().Get("received") != "1" {
			t.Fatalf("check after approval = %s, want the credential received", got)
		}
	}
	stored, err := store.List()
	if err != nil || len(stored) != 2 {
		t.Fatalf("store holds %d credentials, %v; want both", len(stored), err)
	}
}

// TestWebWallet_PreAuthorizedOffer: a pre-authorized offer asks for the
// PIN instead of sending the browser to the issuer, and is received in
// one step with it; a wrong PIN receives nothing.
func TestWebWallet_PreAuthorizedOffer(t *testing.T) {
	env := demotest.New(t, nil)
	store := walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")}
	env.StartWebWallet(t, store)
	b := browser(env)

	offer, err := env.Issuer.CreatePreAuthorizedTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if offer.ConfirmationCode == "999999" {
		t.Skip("the PIN happens to be the wrong PIN this test tries")
	}
	resp, err := b.Get(env.WebWalletURL + "/receive?offer=" + url.QueryEscape(offer.URI))
	if err != nil {
		t.Fatal(err)
	}
	if page := read(t, resp); !strings.Contains(page, `name="pin"`) || strings.Contains(page, "Continue to the issuer") {
		t.Fatalf("confirmation page doesn't ask for the PIN:\n%s", page)
	}

	resp, err = b.PostForm(env.WebWalletURL+"/receive", url.Values{"offer": {offer.URI}, "pin": {"999999"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("wrong PIN: status %d, want an error", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp, err = b.PostForm(env.WebWalletURL+"/receive", url.Values{"offer": {offer.URI}, "pin": {offer.ConfirmationCode}})
	home := mustRedirect(t, resp, err, "POST /receive with the PIN")
	if home.Query().Get("received") != "2" {
		t.Fatalf("redirect = %s, want 2 received", home)
	}
	if stored, err := store.List(); err != nil || len(stored) != 2 {
		t.Fatalf("store holds %d credentials, %v; want both", len(stored), err)
	}
}

// A request for several passports offers checkboxes, and shares each
// one ticked.
func TestWebWallet_SharesSeveralPassports(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	store := walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")}
	env.StartWebWallet(t, store)
	b := browser(env)
	receiveViaBrowser(t, env, b)
	receiveViaBrowser(t, env, b)

	id, page, decision := reviewRequest(t, env, b, verifierapp.ModeGroup)
	if !strings.Contains(page, `type="checkbox" name="credential"`) || strings.Contains(page, `type="radio"`) {
		t.Error("the consent page for several passports doesn't offer checkboxes")
	}
	both := credentialOptions(t, page, "dc+sd-jwt")
	if len(both) != 2 {
		t.Fatalf("SD-JWT VC options = %d, want 2", len(both))
	}
	resp, err := b.PostForm(decision, url.Values{"decision": {"share"}, "credential": both})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	_ = read(t, resp)
	outcome, ok := env.Verifier.Outcome(id)
	if !ok || len(outcome.People) != 2 {
		t.Fatalf("verifier outcome = %+v (ok %v), want two people", outcome, ok)
	}
}
