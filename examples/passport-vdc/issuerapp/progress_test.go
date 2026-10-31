package issuerapp_test

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// offerBrowser is a browser with cookies that uploads gmrtd's sample
// passport with form's options, returning the offer page's status URL,
// offer link and code.
func offerBrowser(t *testing.T, env *demotest.Env, form url.Values) (b *http.Client, statusURL, offer, code string) {
	t.Helper()
	c := *env.HTTP
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Jar = jar
	resp, err := c.PostForm(env.IssuerURL+"/demo/sample", form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	page := string(body)
	find := func(re string) string {
		t.Helper()
		m := regexp.MustCompile(re).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("the offer page has no %s", re)
		}
		return html.UnescapeString(m[1])
	}
	statusURL = env.IssuerURL + find(`data-status="([^"]+)"`)
	if !strings.Contains(page, `aria-live="polite"`) || !strings.Contains(page, "<noscript>") || !strings.Contains(page, `class="steps"`) {
		t.Error("the offer page's progress lacks its live region, steps or noscript fallback")
	}
	return &c, statusURL, find(`id="offer-link">([^<]+)<`), find(`id="offer-code">([0-9]+)<`)
}

// offerStatus GETs an offer's status as c, checking it's never cached
// and carries only coarse progress.
func offerStatus(t *testing.T, c *http.Client, statusURL string, leaks ...string) (int, map[string]any) {
	t.Helper()
	resp, err := c.Get(statusURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("status headers: Cache-Control %q, Content-Type %q", resp.Header.Get("Cache-Control"), resp.Header.Get("Content-Type"))
	}
	for _, leak := range leaks {
		if strings.Contains(string(body), leak) {
			t.Errorf("the status carries %q: %s", leak, body)
		}
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("status %s: %v", body, err)
	}
	for k := range out {
		if !slices.Contains([]string{"state", "credentials", "steps", "summary", "final"}, k) {
			t.Errorf("the status carries %q", k)
		}
	}
	return resp.StatusCode, out
}

// An offer's status follows it from waiting to issued, for the browser
// that uploaded the passport only, and never carries passport data,
// the code or the offer.
func TestOfferStatus_FollowsTheOffer(t *testing.T) {
	env := demotest.New(t, nil)
	b, statusURL, offer, code := offerBrowser(t, env, url.Values{})
	leaks := []string{"SMITH", "JOHN", code, "credential_offer", "issuer_state"}

	status, st := offerStatus(t, b, statusURL, leaks...)
	if status != http.StatusOK || st["state"] != "waiting" || st["final"] != false {
		t.Fatalf("a new offer: %d %v, want waiting", status, st)
	}

	for _, tc := range []struct {
		name string
		c    *http.Client
		url  string
	}{
		{"another browser", env.HTTP, statusURL},
		{"an unknown offer", b, env.IssuerURL + "/demo/offers/no-such-offer/status"},
	} {
		if status, st := offerStatus(t, tc.c, tc.url); status != http.StatusNotFound || st["state"] != "ended" {
			t.Errorf("%s: %d %v, want 404 ended", tc.name, status, st)
		}
	}
	frame := strings.TrimSuffix(statusURL, "/status") + "/progress"
	if resp, err := env.HTTP.Get(frame); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("another browser's progress frame: %v %v, want 404", resp, err)
	}
	resp, err := b.Get(frame)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(string(body), `http-equiv="refresh"`) {
		t.Errorf("the progress frame: %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}

	if _, err := walletapp.Receive(context.Background(), env.WalletConfig(), offer, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: code}); err != nil {
		t.Fatal(err)
	}
	_, st = offerStatus(t, b, statusURL, leaks...)
	creds, _ := st["credentials"].(map[string]any)
	if st["state"] != "issued" || st["final"] != true || creds["mso_mdoc"] != "issued" || creds["dc+sd-jwt"] != "issued" {
		t.Errorf("after issuance: %v, want both issued", st)
	}
}

// A passport held for review shows its credentials deferred, then
// approved, then issued once the wallet checks back.
func TestOfferStatus_Review(t *testing.T) {
	env := demotest.New(t, nil)
	b, statusURL, offer, code := offerBrowser(t, env, url.Values{"review": {"1"}})
	ctx := context.Background()
	_, pending, err := walletapp.ReceiveDeferrable(ctx, env.WalletConfig(), offer, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: code})
	if err != nil || len(pending) != 2 {
		t.Fatalf("ReceiveDeferrable: %d pending, %v", len(pending), err)
	}
	if _, st := offerStatus(t, b, statusURL); st["state"] != "deferred" {
		t.Fatalf("held for review: %v, want deferred", st)
	}
	for _, rv := range env.Issuer.Reviews() {
		if err := env.Issuer.Review(rv.Ref, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, st := offerStatus(t, b, statusURL); st["credentials"].(map[string]any)["mso_mdoc"] != "approved" {
		t.Errorf("after approval: %v, want approved", st)
	}
	for _, p := range pending {
		if _, err := p.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, st := offerStatus(t, b, statusURL); st["state"] != "issued" {
		t.Errorf("after the wallet's check: %v, want issued", st)
	}
}
