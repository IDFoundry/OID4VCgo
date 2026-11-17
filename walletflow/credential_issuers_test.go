package walletflow_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// With Config.CredentialIssuers set, an offer from another issuer is
// refused by StartIssuance, before the holder is asked for a PIN, so
// the PIN never reaches it (OpenID4VCI 1.0, Transaction Code Phishing).
// A listed issuer's offer is redeemed as usual.
func TestStartIssuance_CredentialIssuers(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	walletFor := func(issuers ...string) *walletflow.Wallet {
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
			IssuerRoots: f.env.IssuerRoots, CredentialIssuers: issuers,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	other := walletFor("https://issuer.other.example")
	if _, err := other.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID)); !errors.Is(err, walletflow.ErrUntrustedIssuer) {
		t.Fatalf("an unlisted issuer's offer: %v, want ErrUntrustedIssuer", err)
	}

	listed := walletFor("https://issuer.other.example", f.env.IssuerURL)
	s, err := listed.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatalf("a listed issuer's offer: %v", err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Fatalf("RedeemPreAuthorizedCode: %v", err)
	}
	if _, err := s.RequestCredentials(ctx); err != nil {
		t.Fatalf("RequestCredentials: %v", err)
	}
}

// A wallet receiving credentials decides which issuers' offers it
// takes, in development too: a CredentialIssuers list; signed issuer
// metadata naming its issuer, under roots holding a certificate; or
// AllowAnyCredentialIssuer, alone. A list and signed metadata may be
// combined. A wallet that receives none needs no decision.
func TestNew_CredentialIssuerTrust(t *testing.T) {
	ca, _ := testcert.CA(t, "metadata CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	list := []string{"https://issuer.example"}
	for name, tc := range map[string]struct {
		cfg walletflow.Config
		ok  bool
	}{
		"no decision":         {walletflow.Config{}, false},
		"a list":              {walletflow.Config{CredentialIssuers: list}, true},
		"an empty identifier": {walletflow.Config{CredentialIssuers: []string{""}}, false},
		"signed and named metadata": {walletflow.Config{
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true}, true},
		"signed metadata, not named": {walletflow.Config{IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true}, false},
		"named metadata, not required signed": {walletflow.Config{
			IssuerMetadataRoots: roots, RequireIssuerMetadataName: true}, false},
		"signed and named metadata under empty roots": {walletflow.Config{
			IssuerMetadataRoots: x509.NewCertPool(), RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true}, false},
		"a list and signed, named metadata": {walletflow.Config{CredentialIssuers: list,
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true}, true},
		"any issuer":                      {walletflow.Config{AllowAnyCredentialIssuer: true}, true},
		"any issuer, and signed metadata": {walletflow.Config{AllowAnyCredentialIssuer: true, IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true}, true},
		"any issuer and a list":           {walletflow.Config{AllowAnyCredentialIssuer: true, CredentialIssuers: list}, false},
		"any issuer and named metadata": {walletflow.Config{AllowAnyCredentialIssuer: true,
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true}, false},
	} {
		for _, roots := range []string{"IssuerRoots", "MdocIssuerRoots"} {
			cfg := tc.cfg
			cfg.Development = true
			if roots == "IssuerRoots" {
				cfg.IssuerRoots = x509.NewCertPool()
			} else {
				cfg.MdocIssuerRoots = x509.NewCertPool()
			}
			_, err := walletflow.New(cfg, walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()})
			if (err == nil) != tc.ok {
				t.Errorf("%s, %s: New = %v, want accepted %t", name, roots, err, tc.ok)
			}
		}
	}
	if _, err := walletflow.New(walletflow.Config{Development: true},
		walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()}); err != nil {
		t.Errorf("a wallet receiving no credentials: %v", err)
	}
}

// tokenRequests counts the requests an http.Client sends to a token
// endpoint.
type tokenRequests struct {
	next http.RoundTripper
	mu   sync.Mutex
	n    int
}

func (r *tokenRequests) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/token") {
		r.mu.Lock()
		r.n++
		r.mu.Unlock()
	}
	return r.next.RoundTrip(req)
}

func (r *tokenRequests) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// A wallet trusting issuers by signed metadata naming them refuses, in
// StartIssuance, a pre-authorized offer from an issuer whose metadata
// isn't signed, or is signed by a certificate naming another issuer: the
// holder is never asked for the PIN, and nothing reaches the issuer's
// token endpoint. An issuer whose signed metadata names it is taken.
func TestStartIssuance_SignedNamedIssuerMetadata(t *testing.T) {
	ctx := context.Background()
	ca, caKey := testcert.CA(t, "metadata CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	signedNaming := func(name func(issuerURL string) string) func(string) *issuer.MetadataSigner {
		return func(issuerURL string) *issuer.MetadataSigner {
			named, err := url.Parse(name(issuerURL))
			if err != nil {
				t.Fatal(err)
			}
			cert, key := testcert.Issue(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "issuer metadata"}, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{named},
			}, ca, caKey)
			return &issuer.MetadataSigner{Signer: key, Alg: oid4vci.ES256, Certificate: cert}
		}
	}
	for name, tc := range map[string]struct {
		sign func(string) *issuer.MetadataSigner
		ok   bool
	}{
		"unsigned metadata":                  {nil, false},
		"metadata signed for another issuer": {signedNaming(func(string) string { return "https://issuer.other.example" }), false},
		"metadata signed naming the issuer":  {signedNaming(func(issuerURL string) string { return issuerURL }), true},
	} {
		f := newFixture(t, walletflowtest.Options{SignMetadata: tc.sign})
		requests := &tokenRequests{next: f.env.HTTP.Transport}
		client := *f.env.HTTP
		client.Transport = requests
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true, IssuerRoots: f.env.IssuerRoots,
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: &client})
		if err != nil {
			t.Fatal(err)
		}
		s, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
		if !tc.ok {
			if err == nil {
				_ = s.Close(ctx)
				t.Errorf("%s: StartIssuance took the offer", name)
			}
			if n := requests.count(); n != 0 {
				t.Errorf("%s: %d token requests sent", name, n)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: StartIssuance: %v", name, err)
		}
		if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
			t.Fatalf("%s: RedeemPreAuthorizedCode: %v", name, err)
		}
		_ = s.Close(ctx)
		if requests.count() == 0 {
			t.Errorf("%s: the PIN wasn't redeemed at the token endpoint", name)
		}
	}
}

// sentRequests counts the requests an http.Client sends.
type sentRequests struct {
	next http.RoundTripper
	mu   sync.Mutex
	n    int
}

func (r *sentRequests) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}

func (r *sentRequests) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// listingWallets builds wallets over the same stores, as one app's
// before and after an update changes its Config.CredentialIssuers.
type listingWallets struct {
	f        fixture
	auth     walletflow.AuthorizationStore
	grants   walletflow.GrantStore
	deferred walletflow.DeferredStore
}

func newListingWallets(t *testing.T, opts walletflowtest.Options) listingWallets {
	t.Helper()
	return listingWallets{
		f: newFixture(t, opts), auth: walletflow.NewMemoryAuthorizationStore(),
		grants: walletflow.NewMemoryGrantStore(), deferred: walletflow.NewMemoryDeferredStore(),
	}
}

// listing is a wallet over the stores taking offers from issuers alone,
// and the requests it sends.
func (l listingWallets) listing(t *testing.T, issuers ...string) (*walletflow.Wallet, *sentRequests) {
	t.Helper()
	requests := &sentRequests{next: l.f.env.HTTP.Transport}
	client := *l.f.env.HTTP
	client.Transport = requests
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
		IssuerRoots: l.f.env.IssuerRoots, CredentialIssuers: issuers, RequestRefresh: true,
	}, walletflow.Dependencies{
		Keys: l.f.keys, Credentials: l.f.store, Provider: l.f.env.Provider, HTTP: &client,
		Authorizations: l.auth, Grants: l.grants, Deferred: l.deferred,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w, requests
}

// An authorization begun while its issuer was listed isn't completed
// by a wallet whose Config no longer lists it: ResumeIssuance refuses it
// with ErrUntrustedIssuer, sending nothing, and keeps the authorization,
// which a wallet listing the issuer again still completes.
func TestResumeIssuance_CredentialIssuers(t *testing.T) {
	ctx := context.Background()
	l := newListingWallets(t, walletflowtest.Options{})
	listed, _ := l.listing(t, l.f.env.IssuerURL)
	s, err := listed.StartIssuance(ctx, l.f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := l.f.env.Approve(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}

	unlisted, requests := l.listing(t, "https://issuer.other.example")
	if _, err := unlisted.ResumeIssuance(ctx, redirect); !errors.Is(err, walletflow.ErrUntrustedIssuer) {
		t.Fatalf("ResumeIssuance, the issuer no longer listed: %v, want ErrUntrustedIssuer", err)
	}
	if n := requests.count(); n != 0 {
		t.Errorf("%d requests sent for a refused resume", n)
	}

	relisted, _ := l.listing(t, l.f.env.IssuerURL)
	resumed, err := relisted.ResumeIssuance(ctx, redirect)
	if err != nil {
		t.Fatalf("ResumeIssuance, the issuer listed again: %v", err)
	}
	defer func() { _ = resumed.Close(ctx) }()
	if _, err := resumed.RequestCredentials(ctx); err != nil {
		t.Fatalf("RequestCredentials: %v", err)
	}
}

// A credential from an issuer the Config no longer lists isn't
// refreshed: RefreshCredential refuses with ErrUntrustedIssuer, sending
// nothing, so no refresh token or Wallet Attestation reaches the
// issuer, and keeps the credential and its grant, which a wallet
// listing the issuer again still refreshes.
func TestRefreshCredential_CredentialIssuers(t *testing.T) {
	ctx := context.Background()
	l := newListingWallets(t, walletflowtest.Options{})
	listed, _ := l.listing(t, l.f.env.IssuerURL)
	s, err := listed.StartIssuance(ctx, l.f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, l.f, s)
	res, err := s.RequestCredentials(ctx)
	_ = s.Close(ctx)
	if err != nil || len(res.Credentials) != 1 || res.Credentials[0].GrantID == "" {
		t.Fatalf("RequestCredentials = %+v, %v; want a credential with a refresh grant", res, err)
	}
	id := res.Credentials[0].ID

	unlisted, requests := l.listing(t, "https://issuer.other.example")
	if _, _, err := unlisted.RefreshCredential(ctx, id); !errors.Is(err, walletflow.ErrUntrustedIssuer) {
		t.Fatalf("RefreshCredential, the issuer no longer listed: %v, want ErrUntrustedIssuer", err)
	}
	if n := requests.count(); n != 0 {
		t.Errorf("%d requests sent for a refused refresh", n)
	}
	if grants, err := l.grants.ListGrants(ctx); err != nil || len(grants) != 1 || grants[0].Redemption != "" {
		t.Errorf("refresh grants after a refused refresh = %d, %v; want the grant, unclaimed", len(grants), err)
	}

	relisted, _ := l.listing(t, l.f.env.IssuerURL)
	if _, deferred, err := relisted.RefreshCredential(ctx, id); err != nil || deferred != nil {
		t.Fatalf("RefreshCredential, the issuer listed again: %v", err)
	}
}

// A deferred credential from an issuer the Config no longer lists isn't
// polled after a restart: Poll refuses with ErrUntrustedIssuer, sending
// nothing, and leaves it pending, for a wallet listing the issuer again.
func TestDeferred_CredentialIssuers(t *testing.T) {
	ctx := context.Background()
	l := newListingWallets(t, walletflowtest.Options{Defer: true})
	id := deferUntilClosed(t, l.f, l.deferred, walletflow.GrantPreAuthorizedCode)
	l.f.env.Decide(true)

	unlisted, requests := l.listing(t, "https://issuer.other.example")
	pending, err := unlisted.Deferred(ctx)
	if err != nil || len(pending) != 1 || pending[0].ID() != id {
		t.Fatalf("Deferred = %v, %v", pending, err)
	}
	if stored, err := pending[0].Poll(ctx); stored != nil || !errors.Is(err, walletflow.ErrUntrustedIssuer) {
		t.Fatalf("Poll, the issuer no longer listed: stored %t, %v; want ErrUntrustedIssuer", stored != nil, err)
	}
	if n := requests.count(); n != 0 {
		t.Errorf("%d requests sent for a refused poll", n)
	}
	if pending[0].Done() {
		t.Error("a refused poll ended the deferred credential")
	}

	relisted, _ := l.listing(t, l.f.env.IssuerURL)
	again, err := relisted.Deferred(ctx)
	if err != nil || len(again) != 1 {
		t.Fatalf("Deferred, the issuer listed again = %v, %v", again, err)
	}
	if stored, err := again[0].Poll(ctx); err != nil || stored == nil {
		t.Fatalf("Poll, the issuer listed again: stored %t, %v", stored != nil, err)
	}
}
