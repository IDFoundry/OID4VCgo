// Command webwallet runs the passport-vdc demo wallet in a browser, over
// HTTPS on loopback.
//
//	go run ./cmd/webwallet      # https://127.0.0.1:7443, writes webwallet-tls.pem
//
// It shares its credential store with the CLI wallet (cmd/wallet), and
// its /callback must be registered with the issuer (cmd/issuer does by
// default). Unlike the CLI, it asks before presenting.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotls"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/webwallet"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7443", "listen address")
	walletURL := flag.String("url", "https://127.0.0.1:7443", "this wallet's URL (its /callback is the redirect URI)")
	store := flag.String("store", "wallet-store", "directory the wallet keeps credentials in (shared with cmd/wallet)")
	providerKey := flag.String("wallet-provider-key", "wallet-provider.pem", "the demo Wallet Provider's private key")
	providerIssuer := flag.String("wallet-provider-issuer", "https://wallet-provider.passport-vdc.demo", "the demo Wallet Provider's identifier")
	clientID := flag.String("client-id", "passport-vdc-wallet", "this wallet's client_id")
	trust := flag.String("trust", "issuer-tls.pem,verifier-tls.pem", "comma-separated PEM files of TLS certificates to trust (from cmd/issuer and cmd/verifier)")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: generate a self-signed one)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	certOut := flag.String("tls-cert-out", "webwallet-tls.pem", "where to write a generated TLS certificate")
	flag.Parse()

	keyPEM, err := os.ReadFile(*providerKey) // #nosec G304 -- operator-supplied path
	if err != nil {
		log.Fatalf("read wallet provider key (run cmd/wallet-provider first): %v", err)
	}
	provider, err := walletprovider.Load(*providerIssuer, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	httpClient, err := demotls.TrustingClient(*trust)
	if err != nil {
		log.Fatal(err)
	}
	app, err := webwallet.New(webwallet.Config{
		WalletURL: *walletURL,
		Wallet:    walletapp.Config{ClientID: *clientID, Provider: provider, HTTP: httpClient},
		Store:     walletapp.Store{Dir: *store},
	})
	if err != nil {
		log.Fatal(err)
	}
	cert, err := demotls.Certificate(*certFile, *keyFile, *certOut, "passport-vdc demo web wallet (TLS)")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr: *addr, Handler: app,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, // TLS 1.3 only: FAPI 2.0 allows TLS 1.2 with just a few AES-GCM suites
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		// Long enough for the callback handler to finish the token and
		// credential requests.
		WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second,
	}
	log.Printf("passport-vdc web wallet on https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
