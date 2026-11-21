package walletflow

import (
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// A Verifier's redirect back with the Wallet's own redirect URI's
// scheme isn't followed: it would hand the Wallet's callback whatever
// the Verifier put there. The response was delivered all the same.
func TestCheckRedirect_RefusesTheWalletsOwnScheme(t *testing.T) {
	w := &Wallet{cfg: Config{RedirectURI: "com.example.wallet:/callback"}}
	for uri, refused := range map[string]bool{
		"":                                    false,
		"https://verifier.example/done":       false,
		"com.verifier.app:/done":              false,
		"com.example.wallet:/callback?code=x": true,
		"COM.EXAMPLE.WALLET://x":              true,
	} {
		err := w.checkRedirect(uri)
		if (err != nil) != refused {
			t.Errorf("%q: %v, want refused %v", uri, err, refused)
		}
		if err != nil && !errors.Is(err, wallet.ErrResponseDelivered) {
			t.Errorf("%q: %v, want ErrResponseDelivered", uri, err)
		}
	}
	for _, own := range []string{"", "http://127.0.0.1/cb", "https://wallet.example/cb"} {
		if err := (&Wallet{cfg: Config{RedirectURI: own}}).checkRedirect("https://wallet.example/cb"); err != nil {
			t.Errorf("RedirectURI %q: %v, want an https redirect followed", own, err)
		}
	}
}

// New refuses a VerifierRedirectSchemes entry a Verifier's redirect is
// never followed with — the Wallet's own redirect URI's scheme, which
// checkRedirect refuses, and those wallet refuses — and one that isn't
// a URI scheme.
func TestNew_VerifierRedirectSchemes(t *testing.T) {
	deps := Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()}
	cfg := func(schemes ...string) Config {
		return Config{RedirectURI: "com.example.wallet:/callback", Development: true, VerifierRedirectSchemes: schemes}
	}
	for _, schemes := range [][]string{{"COM.Example.Wallet"}, {"https", "http"}, {"market"}, {"com example"}} {
		_, err := New(cfg(schemes...), deps)
		if err == nil || !strings.Contains(err.Error(), "VerifierRedirectSchemes") && !strings.Contains(err.Error(), "verifier_redirect_schemes") {
			t.Errorf("%q: New = %v, want it refused", schemes, err)
		}
	}
	if _, err := New(cfg("https", "com.example.verifier"), deps); err != nil {
		t.Errorf("New = %v", err)
	}
}
