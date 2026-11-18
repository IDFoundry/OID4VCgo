package webwallet_test

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// TestWebWallet_RefusesForeignHosts: a page whose DNS rebinds its own
// name to loopback reaches the wallet with that name as the Host, and
// is refused before it can read a credential; the wallet's own
// loopback names are served.
func TestWebWallet_RefusesForeignHosts(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	b := browser(env)
	receiveViaBrowser(t, env, b)
	wallet, err := url.Parse(env.WebWalletURL)
	if err != nil {
		t.Fatal(err)
	}
	port := wallet.Port()
	for host, want := range map[string]int{
		"attacker.example:" + port:           http.StatusMisdirectedRequest,
		"attacker.example":                   http.StatusMisdirectedRequest,
		"127.0.0.1.attacker.example:" + port: http.StatusMisdirectedRequest,
		"127.0.0.1:1" + port:                 http.StatusMisdirectedRequest,
		"127.0.0.1:" + port:                  http.StatusOK,
		"localhost:" + port:                  http.StatusOK,
		"LOCALHOST:" + port:                  http.StatusOK,
	} {
		req, err := http.NewRequest(http.MethodGet, env.WebWalletURL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		page := read(t, resp)
		if resp.StatusCode != want {
			t.Errorf("GET / with Host %q: status %d, want %d", host, resp.StatusCode, want)
		}
		if shown := strings.Contains(page, "JANE") || strings.Contains(page, "data:image/jpeg;base64,"); shown != (want == http.StatusOK) {
			t.Errorf("GET / with Host %q: holder's claims in the page: %v", host, shown)
		}
	}
}

// TestWebWallet_RefusesOriginlessPosts: a state-changing request with
// neither Origin nor Referer is refused, as one from another origin
// is; a Referer on the wallet's own pages stands in for Origin.
func TestWebWallet_RefusesOriginlessPosts(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")})
	offer, err := env.Issuer.CreateTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	c := *env.HTTP // not browser(env): it adds an Origin
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	post := func(path, referer string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, env.WebWalletURL+path, strings.NewReader(url.Values{"link": {offer.URI}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for _, path := range []string{"/link", "/receive", "/present", "/present/some-id", "/deferred/some-id"} {
		if got := post(path, ""); got != http.StatusForbidden {
			t.Errorf("POST %s with neither Origin nor Referer: status %d, want 403", path, got)
		}
		if got := post(path, "https://attacker.example/"); got != http.StatusForbidden {
			t.Errorf("POST %s with another site's Referer: status %d, want 403", path, got)
		}
	}
	if got := post("/link", env.WebWalletURL+"/"); got != http.StatusSeeOther {
		t.Errorf("POST /link with the wallet's own Referer: status %d, want 303", got)
	}
}
