// Package demotest starts the passport-vdc demo's issuer and verifier on
// loopback TLS listeners for tests, and supplies synthetic passport
// evidence so tests run without a real (personal-data) passport file.
package demotest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/webwallet"
)

// Demo wallet registration shared by the issuer and wallet in tests.
const (
	WalletClientID = "passport-vdc-wallet"
	RedirectURI    = "http://127.0.0.1/callback"
	ProviderIssuer = "https://wallet-provider.demo.example"
)

// Env is a running demo: issuer, optional verifier, the wallet provider,
// and an HTTP client trusting every server's TLS certificate.
type Env struct {
	Issuer      *issuerapp.App
	IssuerURL   string
	Verifier    *verifierapp.App
	VerifierURL string
	// WebWalletURL is reserved (and registered with the issuer as a
	// redirect URI) up front; StartWebWallet starts it.
	WebWalletURL string
	Provider     *walletprovider.Provider
	HTTP         *http.Client
	roots        *x509.CertPool
	webSrv       *httptest.Server
}

// New starts an issuer (trusting cscaPool for uploads; nil means an
// empty pool) and returns the Env.
func New(t *testing.T, cscaPool cms.CertPool) *Env {
	t.Helper()
	if cscaPool == nil {
		cscaPool = &cms.GenericCertPool{}
	}
	provider, err := walletprovider.New(ProviderIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	jwks, err := provider.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	e := &Env{Provider: provider, roots: x509.NewCertPool()}
	e.webSrv = httptest.NewUnstartedServer(nil)
	e.WebWalletURL = "https://" + e.webSrv.Listener.Addr().String()
	t.Cleanup(func() {
		if e.webSrv.URL == "" { // never started
			_ = e.webSrv.Listener.Close()
		}
	})

	srv := httptest.NewUnstartedServer(nil)
	e.IssuerURL = "https://" + srv.Listener.Addr().String()
	e.Issuer, err = issuerapp.New(issuerapp.Config{
		IssuerURL: e.IssuerURL, CSCAPool: cscaPool,
		Wallet: issuerapp.WalletClient{
			ClientID: WalletClientID, RedirectURIs: []string{RedirectURI, e.WebWalletURL + "/callback"},
			ProviderIssuer: ProviderIssuer, ProviderJWKS: jwks,
		},
	})
	if err != nil {
		t.Fatalf("issuerapp.New: %v", err)
	}
	e.start(t, srv, e.Issuer)
	return e
}

// StartVerifier adds a verifier trusting the issuer's CA and cscaPool.
func (e *Env) StartVerifier(t *testing.T, cscaPool cms.CertPool) {
	t.Helper()
	if cscaPool == nil {
		cscaPool = &cms.GenericCertPool{}
	}
	roots := x509.NewCertPool()
	roots.AddCert(e.Issuer.IssuerCACertificate())
	srv := httptest.NewUnstartedServer(nil)
	e.VerifierURL = "https://" + srv.Listener.Addr().String()
	var err error
	e.Verifier, err = verifierapp.New(verifierapp.Config{
		VerifierURL: e.VerifierURL, IssuerVCT: e.IssuerURL + issuerapp.VCTPath,
		IssuerRoots: roots, CSCAPool: cscaPool,
	})
	if err != nil {
		t.Fatalf("verifierapp.New: %v", err)
	}
	e.start(t, srv, e.Verifier)
}

// StartWebWallet starts the web wallet at WebWalletURL, keeping
// credentials in store.
func (e *Env) StartWebWallet(t *testing.T, store walletapp.Store) {
	t.Helper()
	app, err := webwallet.New(webwallet.Config{WalletURL: e.WebWalletURL, Wallet: e.WalletConfig(), Store: store})
	if err != nil {
		t.Fatalf("webwallet.New: %v", err)
	}
	e.start(t, e.webSrv, app)
	// The web wallet calls the issuer and verifier with e.HTTP, which
	// now trusts every started server.
}

func (e *Env) start(t *testing.T, srv *httptest.Server, h http.Handler) {
	t.Helper()
	srv.Config.Handler = h
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e.roots.AddCert(srv.Certificate())
	e.HTTP = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots, MinVersion: tls.VersionTLS12}},
	}
}

// WalletConfig is the demo wallet's configuration for this Env.
func (e *Env) WalletConfig() walletapp.Config {
	return walletapp.Config{ClientID: WalletClientID, RedirectURI: RedirectURI, Provider: e.Provider, HTTP: e.HTTP}
}

// Date parses a YYYY-MM-DD date, panicking on malformed input.
func Date(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

// SyntheticEvidence stands in for a verified passport. Its SOD is not a
// real signed SOD, so it passes nothing that re-runs Passive
// Authentication.
func SyntheticEvidence() passport.Evidence {
	return passport.Evidence{
		Identity: passport.Identity{
			FamilyName: "DOE", GivenNames: "JANE", NamesFromMRZ: true,
			BirthDate: passport.BirthDate{
				Resolution: passport.BirthDateInferred, Date: Date("1980-01-01"), Youngest: Date("1980-01-01"),
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
