package issuerapp_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/gmrtd/gmrtd/cms"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const (
	walletClientID = "passport-vdc-wallet"
	redirectURI    = "http://127.0.0.1/callback"
	providerIssuer = "https://wallet-provider.demo.example"
)

func date(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

// syntheticEvidence stands in for a verified passport, so this test
// runs in CI without a real (personal-data) passport file.
func syntheticEvidence() passport.Evidence {
	return passport.Evidence{
		Identity: passport.Identity{
			FamilyName: "DOE", GivenNames: "JANE", NamesFromMRZ: true,
			BirthDate: passport.BirthDate{
				Resolution: passport.BirthDateInferred, Date: date("1980-01-01"), Youngest: date("1980-01-01"),
			},
			Sex: "F", Nationality: "SGP", IssuingCountry: "SGP", DocumentNumber: "K0000000A",
			ExpiryDate: time.Now().AddDate(5, 0, 0),
		},
		Raw: passport.RawDataGroups{
			SOD: []byte("synthetic-sod"), DG1: []byte("synthetic-dg1"), DG2: bytes.Repeat([]byte{0xAB}, 20<<10),
		},
		Checks: passport.Checks{PassiveAuthentication: true, ChipAuthenticity: "n/a"},
	}
}

// startIssuer runs an issuerapp.App on a loopback http listener, with
// an empty CSCA pool: tests using it inject already-verified Evidence.
func startIssuer(t *testing.T, provider *walletprovider.Provider) (*issuerapp.App, string) {
	t.Helper()
	return startIssuerWithPool(t, provider, &cms.GenericCertPool{})
}

// startIssuerWithMasterList is startIssuer trusting gmrtd's built-in
// ICAO CSCA master list, for tests that upload a real passport.
func startIssuerWithMasterList(t *testing.T, provider *walletprovider.Provider) (*issuerapp.App, string) {
	t.Helper()
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	return startIssuerWithPool(t, provider, pool)
}

func startIssuerWithPool(t *testing.T, provider *walletprovider.Provider, pool cms.CertPool) (*issuerapp.App, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	issuerURL := "http://" + srv.Listener.Addr().String()
	jwks, err := provider.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	app, err := issuerapp.New(issuerapp.Config{
		IssuerURL: issuerURL,
		CSCAPool:  pool,
		Wallet: issuerapp.WalletClient{
			ClientID: walletClientID, RedirectURIs: []string{redirectURI},
			ProviderIssuer: providerIssuer, ProviderJWKS: jwks,
		},
	})
	if err != nil {
		t.Fatalf("issuerapp.New: %v", err)
	}
	srv.Config.Handler = app
	srv.Start()
	t.Cleanup(srv.Close)
	return app, issuerURL
}

// TestEndToEnd_IssuesBothFormats drives the full HAIP issuance flow
// against the demo issuer with a real fapigo/client and oid4vcgo/wallet:
// credential offer → PAR carrying issuer_state (Wallet Attestation +
// PoP, DPoP) → approval → token → nonce → credential, once per format.
func TestEndToEnd_IssuesBothFormats(t *testing.T) {
	ctx := context.Background()
	provider, err := walletprovider.New(providerIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	app, issuerURL := startIssuer(t, provider)

	offer, err := app.CreateTransaction(ctx, syntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	w := newWallet(t, httpClient)
	credOffer, err := w.ResolveCredentialOffer(ctx, offer.URI)
	if err != nil {
		t.Fatalf("ResolveCredentialOffer: %v", err)
	}

	c := newOAuthClient(t, issuerURL, httpClient, provider)
	authReq, err := wallet.BuildAuthorizationRequest(credOffer, []string{issuerapp.MdocScope, issuerapp.SDJWTScope})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	session, err := c.BeginAuthorization(ctx, authReq)
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	callback := approve(t, session.URL().String())
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: callback.RawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want CompletionSuccess", result)
	}
	resource := c.ProtectedResource(success.Tokens)

	issuerPub := app.IssuerCertificate().PublicKey

	// mso_mdoc
	holder := newHolderKey(t)
	mdocCred := requestCredential(t, ctx, w, resource, issuerURL, issuerapp.MdocConfigurationID, holder)
	wire, err := base64.RawURLEncoding.DecodeString(mdocCred)
	if err != nil {
		t.Fatalf("decode mdoc credential: %v", err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	verified, err := mdoc.Verify(signed, credential.DocType, issuerPub, haip.RecommendedCOSEAlgorithm, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if verified.NameSpaces[credential.IdentityNamespace][credential.FamilyName] != "DOE" {
		t.Errorf("mdoc family_name = %v", verified.NameSpaces[credential.IdentityNamespace][credential.FamilyName])
	}
	if got, _ := verified.NameSpaces[credential.ICAONamespace][credential.ICAODG2].([]byte); len(got) != 20<<10 {
		t.Errorf("mdoc icao_dg2 is %d bytes, want %d", len(got), 20<<10)
	}
	if !holder.Public().(*ecdsa.PublicKey).Equal(verified.DeviceKey) {
		t.Error("mdoc DeviceKey isn't the holder key the wallet proved")
	}

	// dc+sd-jwt
	sdjwt := requestCredential(t, ctx, w, resource, issuerURL, issuerapp.SDJWTConfigurationID, newHolderKey(t))
	payload, _, err := sdjwtvc.Verify(sdjwt, issuerPub, oid4vci.ES256, sdjwtvc.VerifyOptions{RequireKeyBinding: sdjwtvc.KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if payload["vct"] != issuerURL+issuerapp.VCTPath || payload[credential.FamilyName] != "DOE" || payload[credential.ICAOSOD] == nil {
		t.Errorf("sd-jwt payload = %v", payload)
	}
}

// TestAuthorize_RejectsRequestWithoutOffer checks that an authorization
// request not started from a credential offer (no issuer_state) can't
// reach the approval page.
func TestAuthorize_RejectsRequestWithoutOffer(t *testing.T) {
	ctx := context.Background()
	provider, err := walletprovider.New(providerIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	_, issuerURL := startIssuer(t, provider)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	c := newOAuthClient(t, issuerURL, httpClient, provider)

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{issuerapp.MdocScope}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	resp, err := noRedirects().Get(session.URL().String())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("X-Interaction-Handle") != "" {
		t.Errorf("authorize without issuer_state: status %d, handle %q — want 400 and no approval", resp.StatusCode, resp.Header.Get("X-Interaction-Handle"))
	}
}

func newWallet(t *testing.T, httpClient *http.Client) *wallet.Wallet {
	t.Helper()
	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 10 * time.Second, MaxRedirects: 2, AllowLoopbackHTTP: true},
	}, wallet.Dependencies{HTTP: httpClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}
	return w
}

// newOAuthClient builds the wallet's fapigo/client: Wallet Attestation
// client authentication from the demo provider, DPoP, PAR.
func newOAuthClient(t *testing.T, issuerURL string, httpClient *http.Client, provider *walletprovider.Provider) *client.Client {
	t.Helper()
	ctx := context.Background()
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAttestationPoPSigning: fapi.ES256, keys.DPoPProofSigning: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	instance, err := km.PublicKey(ctx, keys.ClientAttestationPoPSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("instance key: %v", err)
	}
	walletAttestation, err := provider.Attest(walletClientID, instance.PublicKey, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	parse := func(path string) fapi.URL {
		u, err := fapi.ParseEndpointURL(issuerURL+path, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatalf("ParseEndpointURL(%s): %v", path, err)
		}
		return u
	}
	iss, err := fapi.ParseIssuerURL(issuerURL, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	c, err := client.New(client.Config{
		Issuer: iss, ClientID: fapi.ClientID(walletClientID), RedirectURI: redirectURI,
		Endpoints: client.Endpoints{
			Authorization: parse("/authorize"), Token: parse("/token"), PushedAuthorizationRequest: parse("/par"),
		},
		Profile: client.ProfileFAPISecurity, Assurance: client.AssuranceDevelopment,
		ClientAuthMethod:               storage.ClientAuthMethodAttestation,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		Algorithms:                     client.Algorithms{DPoP: fapi.ES256, IDToken: fapi.ES256, ClientAttestationPoP: fapi.ES256},
		Limits: client.Limits{
			SessionLifetime: 5 * time.Minute, MaxIDTokenLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second,
			HTTPTimeout: 10 * time.Second, MaxHTTPResponseBytes: 1 << 20, MaxJOSECompactBytes: 16 * 1024,
		},
	}, client.Dependencies{
		Sessions: memstore.NewSessionStore(), Keys: km, IssuerKeys: unusedIssuerKeys{}, HTTP: httpClient,
		Clock: client.SystemClock{}, Random: rand.Reader, Attestation: staticAttestation(walletAttestation),
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

// approve plays the holder on the approval page — headlessly, via its
// X-Interaction-Handle header — and returns the redirect back to the
// wallet.
func approve(t *testing.T, authorizeURL string) *url.URL {
	t.Helper()
	hc := noRedirects()
	resp, err := hc.Get(authorizeURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = resp.Body.Close()
	handle := resp.Header.Get("X-Interaction-Handle")
	if resp.StatusCode != http.StatusOK || handle == "" {
		t.Fatalf("GET authorize: status %d, handle %q", resp.StatusCode, handle)
	}
	u, _ := url.Parse(authorizeURL)
	decision := u.Scheme + "://" + u.Host + "/authorize/decision"
	resp, err = hc.PostForm(decision, url.Values{"handle": {handle}, "decision": {"approve"}})
	if err != nil {
		t.Fatalf("POST decision: %v", err)
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil || !strings.HasPrefix(loc.String(), redirectURI) {
		t.Fatalf("POST decision: status %d, Location %v (%v) — want a redirect to %s", resp.StatusCode, loc, err, redirectURI)
	}
	return loc
}

func requestCredential(t *testing.T, ctx context.Context, w *wallet.Wallet, resource wallet.ProtectedResourceClient, issuerURL, configID string, holder crypto.Signer) string {
	t.Helper()
	nonceURL, err := fapi.ParseEndpointURL(issuerURL+"/nonce", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("nonce URL: %v", err)
	}
	nonce, err := w.RequestNonce(ctx, nonceURL)
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	credentialURL, err := fapi.ParseEndpointURL(issuerURL+"/credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("credential URL: %v", err)
	}
	result, err := w.RequestCredential(ctx, resource, credentialURL, wallet.CredentialRequest{
		CredentialConfigurationID: configID, Keys: []crypto.Signer{holder},
		CredentialIssuer: issuerURL, Nonce: nonce.CNonce,
	})
	if err != nil {
		t.Fatalf("RequestCredential(%s): %v", configID, err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("RequestCredential(%s): %d credentials, want 1", configID, len(result.Credentials))
	}
	return result.Credentials[0].Credential
}

func newHolderKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("holder key: %v", err)
	}
	return k
}

func noRedirects() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type staticAttestation string

func (s staticAttestation) CurrentAttestation(context.Context) (string, error) { return string(s), nil }

// unusedIssuerKeys satisfies fapigo/client's IssuerKeys dependency; this
// OAuth-only flow never verifies an ID token or JARM response.
type unusedIssuerKeys struct{}

func (unusedIssuerKeys) ResolveIssuerKeys(context.Context, keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{}, fmt.Errorf("unexpected issuer key lookup")
}
