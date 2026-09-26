package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// newDiscoveryTestWallet builds a *wallet.Wallet using a real
// *http.Client (unlike validDependencies' own fakeHTTPClient stub) so
// FetchCredentialIssuerMetadata/FetchAuthorizationServerMetadata can
// genuinely reach an httptest.Server.
func newDiscoveryTestWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	cfg := validConfig()
	deps := validDependencies()
	deps.HTTP = http.DefaultClient
	w, err := wallet.New(cfg, deps)
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}
	return w
}

// testMetadata builds a Metadata value exercising every field this
// package's own decode path cares about: a credential configuration
// with proof types, and a request-encryption JWKS with a real EC
// public key — the same shape issuer.Metadata() itself builds one of
// these from, though this test builds it directly, since the wire
// format is identical either way (both use this exact type).
func testMetadata(t *testing.T, issuer string) oid4vci.Metadata {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	issuerURL, err := fapi.ParseIssuerURL(issuer, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	credentialURL, err := fapi.ParseEndpointURL("https://issuer.example.com/credential")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return oid4vci.Metadata{
		CredentialIssuer:   issuerURL,
		CredentialEndpoint: credentialURL,
		CredentialConfigurationsSupported: map[string]oid4vci.CredentialConfigurationMetadata{
			"IdentityCredential": {
				Format: "dc+sd-jwt", Scope: "IdentityCredential", VCT: "urn:eudi:pid:1",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
		CredentialRequestEncryption: &oid4vci.RequestEncryptionMetadata{
			JWKS:               oid4vci.JWKSet{Keys: []oid4vci.JWK{{JWK: pub, Kid: "req-enc-1", Alg: jwe.ECDHES}}},
			EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
			EncryptionRequired: false,
		},
	}
}

// serveJSON starts a server answering path with v as JSON, and 404
// everywhere else.
func serveJSON(t *testing.T, path string, v func(srvURL string) any) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v(srv.URL))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchCredentialIssuerMetadata_RoundTrips proves
// FetchCredentialIssuerMetadata correctly decodes Metadata fetched
// from a real HTTP server at the exact well-known path §12.2.2
// requires (inserted before the issuer's own path component, e.g.
// "/.well-known/openid-credential-issuer/test/a/alias") — not just
// independently-plausible-looking decode code.
func TestFetchCredentialIssuerMetadata_RoundTrips(t *testing.T) {
	var want oid4vci.Metadata
	srv := serveJSON(t, "/.well-known/openid-credential-issuer/test/a/alias", func(srvURL string) any {
		want = testMetadata(t, srvURL+"/test/a/alias")
		return want
	})

	w := newDiscoveryTestWallet(t)
	got, err := w.FetchCredentialIssuerMetadata(t.Context(), srv.URL+"/test/a/alias")
	if err != nil {
		t.Fatalf("FetchCredentialIssuerMetadata: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FetchCredentialIssuerMetadata = %+v, want %+v", got, want)
	}
}

// TestFetchCredentialIssuerMetadata_RejectsNon200 proves a non-200
// response is a real error, not silently decoded as empty Metadata.
func TestFetchCredentialIssuerMetadata_RejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	w := newDiscoveryTestWallet(t)
	if _, err := w.FetchCredentialIssuerMetadata(t.Context(), srv.URL); err == nil {
		t.Error("FetchCredentialIssuerMetadata with a 404 response: want error, got nil")
	}
}

// TestFetchAuthorizationServerMetadata_RoundTrips proves
// FetchAuthorizationServerMetadata correctly decodes Authorization
// Server Metadata fetched from a real HTTP server at RFC 8414 §3.1's
// own well-known path (the issuer's terminating "/" removed, then
// inserted before the issuer's own path component) — the convention
// fapigo/client.Discover doesn't support (see the function's own doc
// comment).
func TestFetchAuthorizationServerMetadata_RoundTrips(t *testing.T) {
	var want wallet.AuthorizationServerMetadata
	srv := serveJSON(t, "/.well-known/oauth-authorization-server/test/a/alias", func(srvURL string) any {
		want = wallet.AuthorizationServerMetadata{
			Issuer: srvURL + "/test/a/alias/", AuthorizationEndpoint: srvURL + "/authorize",
			TokenEndpoint: srvURL + "/token", PushedAuthorizationRequestEndpoint: srvURL + "/par",
		}
		return want
	})

	w := newDiscoveryTestWallet(t)
	got, err := w.FetchAuthorizationServerMetadata(t.Context(), srv.URL+"/test/a/alias/")
	if err != nil {
		t.Fatalf("FetchAuthorizationServerMetadata: %v", err)
	}
	if got != want {
		t.Errorf("FetchAuthorizationServerMetadata = %+v, want %+v", got, want)
	}
}

// TestFetchCredentialIssuerMetadata_LoopbackHTTPIssuer checks a wallet
// configured with Fetch.AllowLoopbackHTTP can discover a local
// development issuer served over plain http, not just fetch its
// metadata: the metadata's own http://127.0.0.1 URLs must decode too.
func TestFetchCredentialIssuerMetadata_LoopbackHTTPIssuer(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential_issuer":"` + srv.URL + `","credential_endpoint":"` + srv.URL + `/credential",` +
			`"nonce_endpoint":"` + srv.URL + `/nonce","credential_configurations_supported":{}}`))
	}))
	t.Cleanup(srv.Close)

	w := newDiscoveryTestWallet(t) // validConfig sets Fetch.AllowLoopbackHTTP
	md, err := w.FetchCredentialIssuerMetadata(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("FetchCredentialIssuerMetadata(%s): %v", srv.URL, err)
	}
	if md.CredentialIssuer.String() != srv.URL || md.NonceEndpoint == nil || md.NonceEndpoint.String() != srv.URL+"/nonce" {
		t.Errorf("metadata = %+v", md)
	}
}

// TestFetchCredentialIssuerMetadata_KeepsTrailingSlash checks an issuer
// identifier's trailing "/" stays in the well-known path — OID4VCI
// §12.2.2 has no RFC 8414 §3.1-style removal — and must then match
// credential_issuer exactly, slash included.
func TestFetchCredentialIssuerMetadata_KeepsTrailingSlash(t *testing.T) {
	srv := serveJSON(t, "/.well-known/openid-credential-issuer/test/a/alias/", func(srvURL string) any {
		return testMetadata(t, srvURL+"/test/a/alias/")
	})
	w := newDiscoveryTestWallet(t)
	if _, err := w.FetchCredentialIssuerMetadata(t.Context(), srv.URL+"/test/a/alias/"); err != nil {
		t.Fatalf("FetchCredentialIssuerMetadata: %v", err)
	}
}

// TestFetchCredentialIssuerMetadata_RejectsAnotherIssuer checks
// metadata whose credential_issuer isn't exactly the issuer it was
// fetched for is refused (§12.2.4) — including a difference of just a
// trailing "/", since the comparison allows no normalization.
func TestFetchCredentialIssuerMetadata_RejectsAnotherIssuer(t *testing.T) {
	for name, issuer := range map[string]func(string) string{
		"another host":   func(string) string { return "https://attacker.example.com" },
		"trailing slash": func(srvURL string) string { return srvURL + "/" },
	} {
		t.Run(name, func(t *testing.T) {
			srv := serveJSON(t, "/.well-known/openid-credential-issuer", func(srvURL string) any {
				return testMetadata(t, issuer(srvURL))
			})
			w := newDiscoveryTestWallet(t)
			if _, err := w.FetchCredentialIssuerMetadata(t.Context(), srv.URL); err == nil || !strings.Contains(err.Error(), "is not the issuer") {
				t.Fatalf("error = %v, want the metadata refused", err)
			}
		})
	}
}

// TestFetchAuthorizationServerMetadata_RejectsAnotherIssuer checks
// Authorization Server Metadata whose issuer isn't exactly the issuer it
// was fetched for is refused (RFC 8414 §3.3) — its issuer is what the
// authorization response's iss is then checked against.
func TestFetchAuthorizationServerMetadata_RejectsAnotherIssuer(t *testing.T) {
	srv := serveJSON(t, "/.well-known/oauth-authorization-server", func(string) any {
		return wallet.AuthorizationServerMetadata{
			Issuer: "https://attacker.example.com", AuthorizationEndpoint: "https://attacker.example.com/authorize",
			TokenEndpoint: "https://attacker.example.com/token", PushedAuthorizationRequestEndpoint: "https://attacker.example.com/par",
		}
	})
	w := newDiscoveryTestWallet(t)
	if _, err := w.FetchAuthorizationServerMetadata(t.Context(), srv.URL); err == nil || !strings.Contains(err.Error(), "is not the issuer") {
		t.Fatalf("error = %v, want the metadata refused", err)
	}
}
