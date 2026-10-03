// Command demo runs the whole passport-vdc demo — issuer, verifier, web
// wallet and the Wallet Provider's service — in one process, on
// loopback:
//
//	go run ./cmd/demo
//
// It keeps what should survive a restart in a state directory
// (-state, default .demo-state): the TLS certificate the servers share,
// so a browser's warning is accepted once; the stand-in Wallet
// Provider's key, which only its service uses; the issuer's CA, signing keys and status list, so
// issued credentials keep verifying and revocations hold; and the
// wallet's credential store. The verifier's request-signing CA is
// regenerated each run and handed to the wallet directly.
//
// With -open it also starts Chrome on the three URLs, in a separate
// profile (state/chrome-profile) that accepts the demo's certificate —
// and only that one — without a warning.
//
// The state directory holds credentials made from a real passport, if
// you upload one: delete it (or pass -reset) when you're done.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotls"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/webwallet"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const (
	issuerAddr, issuerURL     = "127.0.0.1:8543", "https://127.0.0.1:8543"
	verifierAddr, verifierURL = "127.0.0.1:9443", "https://127.0.0.1:9443"
	walletAddr, walletURL     = "127.0.0.1:7443", "https://127.0.0.1:7443"
	providerAddr, providerURL = "127.0.0.1:6443", "https://127.0.0.1:6443"
	cliRedirectURI            = "http://127.0.0.1/callback"
	iosRedirectURI            = "org.idfoundry.oid4vcgo.demowallet:/callback"
	providerIssuer            = "https://wallet-provider.passport-vdc.demo"
	walletClientID            = "passport-vdc-wallet"
)

func main() {
	state := flag.String("state", ".demo-state", "directory the demo keeps its keys, certificates, status list and wallet store in")
	reset := flag.Bool("reset", false, "delete the state directory first, starting over")
	open := flag.Bool("open", false, "open the demo in Chrome, in a separate profile that trusts the demo's certificate (no warnings)")
	chrome := flag.String("chrome", "", "with -open: the Chrome or Chromium executable (default: look in the usual places)")
	flag.Parse()

	if *reset {
		if err := resetState(*state); err != nil {
			log.Fatal(err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, options{state: *state, open: *open, chrome: *chrome}); err != nil {
		log.Fatal(err)
	}
}

// stateMarker is written into every state directory, so -reset deletes
// only a directory this demo made.
const stateMarker = ".passport-vdc-demo-state"

// resetState deletes the state directory dir — but only one this demo
// made, so a mistyped -state can't delete anything else. A directory
// that doesn't exist yet is fine.
func resetState(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("reset %s: %w", dir, err)
	}
	if len(entries) > 0 && !isDemoState(dir) {
		return fmt.Errorf("reset %s: refusing — it isn't a passport-vdc demo state directory (no %s); delete it yourself if you mean to", dir, stateMarker)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("reset %s: %w", dir, err)
	}
	return nil
}

// isDemoState reports whether dir was made by this demo: it has the
// marker, or — made before the marker existed — the demo's TLS
// certificate and issuer state.
func isDemoState(dir string) bool {
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	return exists(stateMarker) || (exists("tls-cert.pem") && exists("issuer"))
}

// options are the command-line choices run acts on.
type options struct {
	state  string
	open   bool   // open Chrome on the demo once it's listening
	chrome string // Chrome's path, when not in the usual places
}

func run(ctx context.Context, opts options) error {
	state := opts.state
	issuerState := filepath.Join(state, "issuer")
	if err := os.MkdirAll(issuerState, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", issuerState, err)
	}
	if err := os.WriteFile(filepath.Join(state, stateMarker), []byte("passport-vdc demo state: delete with `go run ./cmd/demo -reset`\n"), 0o600); err != nil { // #nosec G703 -- operator-supplied state directory
		return fmt.Errorf("mark %s: %w", state, err)
	}
	cert, leaf, err := demotls.PersistentCertificate(state, "passport-vdc demo (TLS)")
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	provider, _, err := walletprovider.LoadOrCreate(providerIssuer, filepath.Join(state, "wallet-provider.pem"))
	if err != nil {
		return err
	}
	csca, err := cms.DefaultMasterList()
	if err != nil {
		return fmt.Errorf("load CSCA master list: %w", err)
	}
	httpClient := demotls.ClientTrusting(leaf)

	issuer, err := issuerapp.New(issuerapp.Config{
		IssuerURL: issuerURL, CSCAPool: csca, StateDir: issuerState, WebWalletURL: walletURL,
		Wallet: issuerapp.WalletClient{
			ClientID: walletClientID, RedirectURIs: []string{cliRedirectURI, iosRedirectURI, walletURL + "/callback"},
			ProviderIssuer: providerIssuer, ProviderCA: provider.CACertificatePEM(),
		},
	})
	if err != nil {
		return err
	}
	verifier, err := verifierapp.New(verifierapp.Config{
		VerifierURL: verifierURL, IssuerVCT: issuerURL + issuerapp.VCTPath,
		IssuerCAs: []*x509.Certificate{issuer.IssuerCACertificate()}, CSCAPool: csca,
		WebWalletURL: walletURL, HTTP: httpClient,
	})
	if err != nil {
		return err
	}
	webWallet, err := webwallet.New(webwallet.Config{
		WalletURL: walletURL,
		Wallet: walletapp.Config{
			ClientID: walletClientID, HTTP: httpClient,
			Provider:    walletprovider.Client{URL: providerURL, HTTP: httpClient},
			IssuerRoots: pool(issuer.IssuerCACertificate()),
		},
		Store:         walletapp.Store{Dir: filepath.Join(state, "wallet-store")},
		VerifierTrust: wallet.X5CVerifierRoots{Roots: pool(verifier.VerifierCACertificate())},
	})
	if err != nil {
		return err
	}
	// For the CLI wallet (cmd/wallet -state): the trust anchors of this
	// run.
	if err := writeCertificates(state, map[string]*x509.Certificate{
		"issuer-ca.pem": issuer.IssuerCACertificate(), "verifier-ca.pem": verifier.VerifierCACertificate(),
	}); err != nil {
		return err
	}

	servers := []*http.Server{
		// The wallets ask it for attestations; they never hold its key.
		demotls.Server(providerAddr, provider.Handler(walletClientID), cert, 30*time.Second),
		demotls.Server(issuerAddr, issuer, cert, 30*time.Second),
		demotls.Server(verifierAddr, verifier, cert, 30*time.Second),
		// Long enough for the callback to finish the token and
		// credential requests.
		demotls.Server(walletAddr, webWallet, cert, 2*time.Minute),
	}
	return serve(ctx, servers, opts, leaf)
}

// serve runs servers until ctx is done or one of them fails. Each
// listens before anything else happens, so a port in use fails at once
// and a browser opened with -open never races the servers.
func serve(ctx context.Context, servers []*http.Server, opts options, cert *x509.Certificate) error {
	listeners := make([]net.Listener, 0, len(servers))
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return fmt.Errorf("listen on %s: %w", srv.Addr, err)
		}
		listeners = append(listeners, ln)
	}
	failed := make(chan error, len(servers))
	for i, srv := range servers {
		go func() {
			if err := srv.ServeTLS(listeners[i], "", ""); !errors.Is(err, http.ErrServerClosed) {
				failed <- fmt.Errorf("%s: %w", srv.Addr, err)
			}
		}()
	}
	printBanner(opts.state, opts.open)
	if opts.open {
		if err := openChrome(opts.chrome, opts.state, cert, issuerURL, verifierURL, walletURL); err != nil {
			log.Printf("couldn't open Chrome (%v); open the URLs above yourself", err)
		}
	}

	var err error
	select {
	case <-ctx.Done():
	case err = <-failed:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return err
}

func printBanner(state string, open bool) {
	browser := fmt.Sprintf(`First time in this browser: open each URL once and accept the
self-signed certificate warning (or run with -open). The certificate is
kept in %s, so you won't be asked again.`, state)
	if open {
		browser = `Opening them in Chrome, in a separate demo profile that trusts the
demo's certificate — use that window for the whole demo.`
	}
	fmt.Printf(`
passport-vdc demo is running (Ctrl-C to stop)

  issuer    %s   upload a gmrtd passport file here
  verifier  %s   ask for the credential
  wallet    %s   holds it
  provider  %s   attests the wallets (no page; they call it)

%s

CLI wallet, sharing the web wallet's credentials:
  go run ./cmd/wallet receive -state %s '<offer link>'

%s holds credentials made from any passport you upload: delete it,
or run with -reset, when you're done.

`, issuerURL, verifierURL, walletURL, providerURL, browser, state, state)
}

func writeCertificates(dir string, certs map[string]*x509.Certificate) error {
	for name, c := range certs {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o600); err != nil { // #nosec G703 -- operator-supplied state directory
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}
