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
