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
	ctx := context.Background()
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	s, err := refreshingWallet(t, env).StartIssuance(ctx, offer.URI)
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
	return &b, string(page), offer.ConfirmationCode
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
	tag, err := walletapp.ApprovalTag([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	resp, err := b.PostForm(env.IssuerURL+"/authorize/decision", url.Values{"interaction": {tag}, "decision": {"approve"}, "code": {wrong}})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(again), `role="alert"`) || !strings.Contains(string(again), "That confirmation code is wrong") {
		t.Error("a wrong code doesn't show the approval page again with the error")
	}
}
