package webwallet_test

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// browser is an HTTP client that, like a person clicking through the
// pages, sees each redirect rather than following it automatically.
func browser(env *demotest.Env) *http.Client {
	c := *env.HTTP
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
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
	handle := resp.Header.Get("X-Interaction-Handle")
	_ = resp.Body.Close()
	resp, err = b.PostForm(env.IssuerURL+"/authorize/decision", url.Values{"handle": {handle}, "decision": {"approve"}})
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

// reviewRequest opens a verifier request in the web wallet and returns
// the consent page and its decision URL.
func reviewRequest(t *testing.T, env *demotest.Env, b *http.Client, mode verifierapp.Mode) (id, page, decisionURL string) {
	t.Helper()
	id, link, err := env.Verifier.CreateRequest(mode)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	resp, err := b.Get(env.WebWalletURL + "/present?request=" + url.QueryEscape(link))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /present: %v %v", resp, err)
	}
	page = read(t, resp)
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
	if home := read(t, resp); strings.Count(home, "DOE") < 2 || !strings.Contains(home, "mso_mdoc") || !strings.Contains(home, "dc+sd-jwt") {
		t.Error("home page doesn't show both received credentials")
	}

	// The consent screen shows what's asked for, in each format the
	// wallet can answer with — and nothing is sent yet.
	id, page, decision := reviewRequest(t, env, b, verifierapp.ModeICAO)
	for _, want := range []string{"icao_sod", "icao_dg1", `value="mso_mdoc"`, `value="dc+sd-jwt"`} {
		if !strings.Contains(page, want) {
			t.Errorf("consent page is missing %q", want)
		}
	}
	if strings.Contains(page, "icao_dg2") {
		t.Error("consent page offers to disclose icao_dg2, which wasn't requested")
	}
	if _, answered := env.Verifier.Outcome(id); answered {
		t.Fatal("the verifier got an answer before the holder consented")
	}

	resp, err = b.PostForm(decision, url.Values{"decision": {"share"}, "format": {"dc+sd-jwt"}})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if done := read(t, resp); !strings.Contains(done, "Shared passport_sdjwt") {
		t.Errorf("share result page: status %d", resp.StatusCode)
	}
	outcome, ok := env.Verifier.Outcome(id)
	if !ok || outcome.Error != "" || outcome.Format != "dc+sd-jwt" {
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
