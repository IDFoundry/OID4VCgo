package issuerapp_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// approvalPage opens the approval page for a new offer in a browser
// with cookies, returning the browser, the page and the offer's code.
func approvalPage(t *testing.T, env *demotest.Env) (*http.Client, string, string) {
	t.Helper()
	offer, err := env.Issuer.CreateTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	b, page := openApproval(t, env, offer.URI)
	return b, page, offer.ConfirmationCode
}

// openApproval opens the approval page for offer as a wallet of its own
// would, in a browser of its own: anyone holding the offer link can.
// It returns the browser and the page.
func openApproval(t *testing.T, env *demotest.Env, offer string) (*http.Client, string) {
	t.Helper()
	ctx := context.Background()
	s, err := refreshingWallet(t, env).StartIssuance(ctx, offer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(ctx) })
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := *env.HTTP
	b.Jar, _ = cookiejar.New(nil)
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := b.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("approval page: status %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	return &b, string(page)
}

// decide submits the approval page's form from browser b with decision
// and code, returning the answer's status, Location and body.
func decide(t *testing.T, env *demotest.Env, b *http.Client, page, decision, code string) (int, string, string) {
	t.Helper()
	tag, err := walletapp.ApprovalTag([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := b.PostForm(env.IssuerURL+"/authorize/decision", url.Values{"interaction": {tag}, "decision": {decision}, "code": {code}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), string(body)
}

// wrongCode is a six-digit code other than code.
func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// TestApprovalPage: the approval page names the wallet and what it
// asks for, takes the code in one labelled input, and offers Approve
// and Deny — still without any passport data.
func TestApprovalPage(t *testing.T) {
	env := demotest.New(t, nil)
	b, page, code := approvalPage(t, env)
	for _, want := range []string{
		"The passport demo wallet is asking", "Passport as an mdoc", "Passport as an SD-JWT VC", "Fresh copies for 24 hours",
		`<label for="code"`, `<span class="code-field"><input id="code" name="code" inputmode="numeric"`, `autocomplete="one-time-code"`,
		`class="btn" name="decision" value="approve"`, `class="btn secondary" name="decision" value="deny" formnovalidate`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the approval page lacks %q", want)
		}
	}
	if strings.Contains(page, "DOE") || strings.Contains(page, "K0000000A") {
		t.Error("the approval page shows passport data")
	}

	// A wrong code shows the page again, saying so.
	if _, _, again := decide(t, env, b, page, "approve", wrongCode(code)); !strings.Contains(again, `role="alert"`) || !strings.Contains(again, "That confirmation code is wrong") {
		t.Error("a wrong code doesn't show the approval page again with the error")
	}
}

// TestApproval_WrongCodesEndTheirPage: an approval page takes three
// wrong codes, then ends without sending the browser back to the
// wallet, and redeems nothing afterwards, even with the right code and
// the page's cookie kept. The holder's wallet, on a page of its own,
// still redeems the offer with the code.
func TestApproval_WrongCodesEndTheirPage(t *testing.T) {
	env := demotest.New(t, nil)
	ctx := context.Background()
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	b, page := openApproval(t, env, offer.URI)
	wrong := wrongCode(offer.ConfirmationCode)
	for i := range 2 {
		if status, _, body := decide(t, env, b, page, "approve", wrong); status != http.StatusOK || !strings.Contains(body, "That confirmation code is wrong") {
			t.Fatalf("wrong code %d: status %d, want the page again", i+1, status)
		}
	}
	issuer, err := url.Parse(env.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	cookies := b.Jar.Cookies(issuer)
	for _, code := range []string{wrong, offer.ConfirmationCode} {
		status, loc, body := decide(t, env, b, page, "approve", code)
		if status != http.StatusBadRequest || loc != "" || !strings.Contains(body, "too many wrong confirmation codes on this page") {
			t.Fatalf("code %q on a page that has had three wrong ones: status %d, Location %q; want it ended, without a redirect", code, status, loc)
		}
		b.Jar.SetCookies(issuer, cookies) // the page's cookie, kept as a script would
	}

	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 2 {
		t.Fatalf("the holder's wallet, with the code: %d credentials, %v; want both", len(received), err)
	}
}

// TestApproval_OfferLinkAloneNeitherVoidsNorDeclines: whoever has only
// the offer link, the QR code the offer page shows, can open approval
// pages with wallets of their own, but neither voids the offer with
// nine wrong codes, one short of the ten that do, nor has the offer
// page show it declined by denying without the code. A deny is answered
// the same whatever its code. The holder, with the code, declines it on
// the offer page, and redeems it afterwards.
func TestApproval_OfferLinkAloneNeitherVoidsNorDeclines(t *testing.T) {
	env := demotest.New(t, nil)
	ctx := context.Background()
	holder, statusURL, offer, code := offerBrowser(t, env, url.Values{})
	wrong := wrongCode(code)
	wantState := func(when, want string) {
		t.Helper()
		if _, st := offerStatus(t, holder, statusURL); st["state"] != want {
			t.Fatalf("the offer page %s: %v, want %s", when, st, want)
		}
	}
	deny := func(withCode string) {
		t.Helper()
		b, page := openApproval(t, env, offer)
		status, loc, _ := decide(t, env, b, page, "deny", withCode)
		if u, err := url.Parse(loc); err != nil || status != http.StatusSeeOther || u.Query().Get("error") != "access_denied" {
			t.Errorf("deny with code %q: status %d, Location %q; want the wallet told access_denied", withCode, status, loc)
		}
	}

	for i := range 9 {
		if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: wrong}); err == nil {
			t.Fatalf("wrong code %d redeemed the offer", i+1)
		}
	}
	wantState("after wrong codes from wallets with the offer link alone", "waiting")
	deny("")
	deny(wrong)
	wantState("after denies without the code", "waiting")
	deny(code)
	wantState("after the holder declined with the code", "denied")

	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: code})
	if err != nil || len(received) != 2 {
		t.Fatalf("the holder's wallet, with the code: %d credentials, %v; want both", len(received), err)
	}
	wantState("after the holder redeemed it", "issued")
}
