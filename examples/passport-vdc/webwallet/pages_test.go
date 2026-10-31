package webwallet_test

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// TestWebWallet_PasteLink: the home page's one paste box takes an offer
// to the receive confirmation and a request to its consent page; it
// refuses anything else, and a cross-origin post.
func TestWebWallet_PasteLink(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	b := browser(env)
	receiveViaBrowser(t, env, b)

	offer, err := env.Issuer.CreateTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := b.PostForm(env.WebWalletURL+"/link", url.Values{"link": {"  " + offer.URI + "\n"}})
	loc := mustRedirect(t, resp, err, "paste an offer")
	if loc.Path != "/receive" || loc.Query().Get("offer") != offer.URI {
		t.Errorf("an offer went to %s, want the receive confirmation", loc)
	}

	_, link, err := env.Verifier.CreateRequest(verifierapp.ScenarioSignup)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = b.PostForm(env.WebWalletURL+"/link", url.Values{"link": {link}})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("paste a request: %v %v", resp, err)
	}
	if page := read(t, resp); !strings.Contains(page, `action="/present/`) || !strings.Contains(page, "Chirp Social") {
		t.Error("a request didn't open its consent page")
	}

	for _, bad := range []string{"https://example.com/not-a-link", "", "openid-credential-offerx"} {
		resp, err = b.PostForm(env.WebWalletURL+"/link", url.Values{"link": {bad}})
		if err != nil {
			t.Fatal(err)
		}
		if page := read(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(page, "isn't a link this wallet recognises") {
			t.Errorf("pasting %q: status %d, want 400 saying so", bad, resp.StatusCode)
		}
	}

	req, err := http.NewRequest(http.MethodPost, env.WebWalletURL+"/link", strings.NewReader(url.Values{"link": {offer.URI}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.example")
	resp, err = b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin paste: status %d, want 403", resp.StatusCode)
	}

	resp, err = b.Get(env.WebWalletURL + "/link")
	if loc := mustRedirect(t, resp, err, "GET /link"); loc.Path != "/" {
		t.Errorf("GET /link went to %s, want the home page", loc)
	}
}

// TestWebWallet_Pages: the pages show credentials as wallet cards, the
// consent's choices by holder with what each discloses in readable
// labels, and are never cached.
func TestWebWallet_Pages(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	b := browser(env)
	receiveViaBrowser(t, env, b)

	resp, err := b.Get(env.WebWalletURL + "/?received=2")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("home Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}
	home := read(t, resp)
	for _, want := range []string{
		`class="verdict approved"`, "Received 2 credentials", `<form method="post" action="/link"`, `id="clear-link"`, `aria-live="polite"`,
		`class="card entry wallet-card"`, `alt="Portrait of JANE DOE"`, `<p class="wc-name">JANE DOE</p>`, "Family name", "Date of birth",
		"Credential details and raw data", "Passport file (chip data)",
	} {
		if !strings.Contains(home, want) {
			t.Errorf("the home page lacks %q", want)
		}
	}

	_, page, _ := reviewRequest(t, env, b, verifierapp.ScenarioSignup)
	for _, want := range []string{
		"Chirp Social is asking for your passport", "✓ Trusted verifier", `class="choice block"`, `alt="Portrait of JANE DOE"`,
		`<span class="chip">Family name</span>`, `<span class="chip">Given names</span>`, `<span class="chip">Over 18</span>`, `<span class="chip">Photo</span>`,
		`class="btn" name="decision" value="share"`, `class="btn secondary" name="decision" value="decline"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the consent page lacks %q", want)
		}
	}

	resp, err = b.Get(env.WebWalletURL + "/present?request=" + url.QueryEscape("https://example.com/x"))
	if err != nil {
		t.Fatal(err)
	}
	if page := read(t, resp); !strings.Contains(page, `class="verdict refused"`) || resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("the error page lacks its banner, or can be cached")
	}
}
