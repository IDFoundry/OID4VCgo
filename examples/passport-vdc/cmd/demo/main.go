// Command demo runs the whole passport-vdc demo — issuer, verifier and
// web wallet — in one process, on loopback:
//
//	go run ./cmd/demo
//
// It keeps what should survive a restart in a state directory
// (-state, default .demo-state): the TLS certificate all three servers
// share, so a browser's warning is accepted once; the stand-in Wallet
// Provider's key; the issuer's CA, signing keys and status list, so
// issued credentials keep verifying and revocations hold; and the
// wallet's credential store. The verifier's request-signing CA is
// regenerated each run and handed to the wallet directly.
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
	cliRedirectURI            = "http://127.0.0.1:8765/callback"
	providerIssuer            = "https://wallet-provider.passport-vdc.demo"
	walletClientID            = "passport-vdc-wallet"
)

func main() {
	state := flag.String("state", ".demo-state", "directory the demo keeps its keys, certificates, status list and wallet store in")
	reset := flag.Bool("reset", false, "delete the state directory first, starting over")
	flag.Parse()

	if *reset {
		if err := os.RemoveAll(*state); err != nil {
			log.Fatalf("reset %s: %v", *state, err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *state); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, state string) error {
	issuerState := filepath.Join(state, "issuer")
	if err := os.MkdirAll(issuerState, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", issuerState, err)
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
			ClientID: walletClientID, RedirectURIs: []string{cliRedirectURI, walletURL + "/callback"},
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
			ClientID: walletClientID, Provider: provider, HTTP: httpClient,
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
		demotls.Server(issuerAddr, issuer, cert, 30*time.Second),
		demotls.Server(verifierAddr, verifier, cert, 30*time.Second),
		// Long enough for the callback to finish the token and
		// credential requests.
		demotls.Server(walletAddr, webWallet, cert, 2*time.Minute),
	}
	return serve(ctx, servers, state)
}

// serve runs servers until ctx is done or one of them fails.
func serve(ctx context.Context, servers []*http.Server, state string) error {
	failed := make(chan error, len(servers))
	for _, srv := range servers {
		go func() {
			if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
				failed <- fmt.Errorf("%s: %w", srv.Addr, err)
			}
		}()
	}
	printBanner(state)

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

func printBanner(state string) {
	fmt.Printf(`
passport-vdc demo is running (Ctrl-C to stop)

  issuer    %s   upload a gmrtd passport file here
  verifier  %s   ask for the credential
  wallet    %s   holds it

First time in this browser: open each URL once and accept the
self-signed certificate warning. The certificate is kept in %s, so
you won't be asked again.

CLI wallet, sharing the web wallet's credentials:
  go run ./cmd/wallet receive -state %s '<offer link>'

%s holds credentials made from any passport you upload: delete it,
or run with -reset, when you're done.

`, issuerURL, verifierURL, walletURL, state, state, state)
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
