package walletflow

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// redirectDeps are production-grade dependencies for building a Wallet
// whose only question is its RedirectURI.
func redirectDeps() Dependencies {
	return Dependencies{
		Keys: durableKeyStore{NewMemoryKeyStore()}, Credentials: NewMemoryCredentialStore(),
		Provider: attestingProvider{}, Authorizations: durableAuthorizations{NewMemoryAuthorizationStore()},
	}
}

// issuanceClient builds the fapigo/client an issuance of w's would, a
// resumed one's or not.
func issuanceClient(t testing.TB, w *Wallet, resumed bool) error {
	t.Helper()
	s := &Issuance{w: w, offer: oid4vci.CredentialOffer{CredentialIssuer: "https://issuer.example"}, resumed: resumed}
	var err error
	if s.instanceKey, err = newKey(context.Background(), w.deps.Keys, KeyPurposeInstance); err != nil {
		t.Fatal(err)
	}
	if s.dpopKey, err = w.newDPoPKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	issuer, endpoints, err := wallet.AuthorizationServerMetadata{
		Issuer: "https://as.example", AuthorizationEndpoint: "https://as.example/authorize",
		TokenEndpoint: "https://as.example/token", PushedAuthorizationRequestEndpoint: "https://as.example/par",
	}.ClientEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.oauthClient(issuer, endpoints, "https://as.example", client.StaticAttestation("eyJ.attestation.jwt"))
	return err
}

// New refuses, at every assurance level, a redirect URI fapigo/client
// refuses to build an issuance's client with, rather than taking it and
// failing every issuance that authenticates, pre-authorized ones too,
// after the Wallet Provider has been asked for an attestation.
func TestNew_RedirectURIForm(t *testing.T) {
	for _, uri := range []string{
		"myapp:/callback",                // no dot: not a reverse-order domain name
		"myapp://callback",               // and "callback" an authority
		"com.example.wallet:callback",    // no slash
		"com.example.wallet:///callback", // an empty authority
		"com.example.wallet://cb:443/x",  // an authority with a port
		"com.example.wallet://u@cb/x",    // userinfo
		"com.example.wallet://127.0.0.1", // an IP address
		"com.example.wallet://c%41b/x",   // a percent-escape
		"com.example.wallet://cb#frag",   // a fragment
		"com.example.wallet:/cb#frag",    // a fragment
		"http://user@127.0.0.1/cb",       // credentials
		"http://127.0.0.1/cb#x",
		"javascript:/x",
		"https://wallet.example/cb#x",
	} {
		for _, dev := range []bool{false, true} {
			_, err := New(Config{ClientID: "wallet", RedirectURI: uri, IssuerRoots: x509.NewCertPool(), Development: dev}, redirectDeps())
			if err == nil || !strings.Contains(err.Error(), "Config.RedirectURI") {
				t.Errorf("New(RedirectURI %q, Development %v) = %v, want it refused", uri, dev, err)
			}
		}
	}
	// A wallet that doesn't receive credentials is refused too: the
	// configuration is wrong whatever the wallet does with it.
	if _, err := New(Config{ClientID: "wallet", RedirectURI: "myapp:/callback"}, redirectDeps()); err == nil {
		t.Error("New(RedirectURI myapp:/callback, no IssuerRoots) = nil error, want it refused")
	}
	// Both private-use forms fapigo/client takes: RFC 8252 §7.1's single
	// slash, and the authority form deployed wallets register
	// (eu.europa.ec.euidi://authorization, the EUDI reference wallet's).
	for _, uri := range []string{"com.example.wallet:/callback", "com.example.wallet://callback", "eu.europa.ec.euidi://authorization"} {
		for _, dev := range []bool{false, true} {
			w, err := New(Config{
				ClientID: "wallet", RedirectURI: uri, IssuerRoots: x509.NewCertPool(), Development: dev,
				IssuerRevocation: certrevocation.NoCheck{}, StatusRevocation: certrevocation.NoCheck{},
			}, redirectDeps())
			if err != nil {
				t.Errorf("New(RedirectURI %q, Development %v) = %v, want it taken", uri, dev, err)
				continue
			}
			if err := issuanceClient(t, w, true); err != nil {
				t.Errorf("RedirectURI %q, Development %v: a resumed issuance's client = %v", uri, dev, err)
			}
		}
	}
	// Development still takes localhost, as fapigo/client does below
	// production assurance; production takes only the IP literals.
	if _, err := New(Config{ClientID: "wallet", RedirectURI: "http://localhost/cb", Development: true}, redirectDeps()); err != nil {
		t.Errorf("New(Development, http://localhost/cb) = %v, want it taken", err)
	}
	if _, err := New(Config{ClientID: "wallet", RedirectURI: "http://localhost/cb"}, redirectDeps()); err == nil {
		t.Error("New(http://localhost/cb), not receiving, = nil error, want it refused")
	}
}

// FuzzNativeRedirect checks New against fapigo/client: every redirect
// URI New takes, an issuance's client takes too — a resumed one's
// wherever ResumeIssuance can run, always under production assurance —
// so a configuration mistake shows at New, not at the first issuance.
func FuzzNativeRedirect(f *testing.F) {
	for _, s := range []string{
		"com.example.wallet:/cb", "http://127.0.0.1/cb", "http://[::1]:8/cb", "https://a/b", "HTTP://127.0.0.1/x",
		"http://127.0.0.1%2f/x", "myapp:/cb", "com.example.wallet://cb", "com.example.wallet://cb:1/x", "com.example.wallet:cb", "http://localhost/cb",
		"com.example.wallet:/cb#f", "http://u@127.0.0.1/cb", "Com.Example-1.wallet:/a?b=c",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, uri string, dev bool) {
		w, err := New(Config{ClientID: "wallet", RedirectURI: uri, IssuerRoots: x509.NewCertPool(), Development: dev}, redirectDeps())
		if err != nil || uri == "" {
			return
		}
		if err := issuanceClient(t, w, false); err != nil {
			t.Fatalf("New(RedirectURI %q, Development %v) takes it, an issuance's client doesn't: %v", uri, dev, err)
		}
		// A resumed issuance binds the callback to the device's own
		// store, which fapigo/client allows only for a native app's
		// redirect: New requires one outside Development.
		if !dev || nativeRedirectURI(uri) {
			if err := issuanceClient(t, w, true); err != nil {
				t.Fatalf("New(RedirectURI %q, Development %v) takes it, a resumed issuance's client doesn't: %v", uri, dev, err)
			}
		}
	})
}
