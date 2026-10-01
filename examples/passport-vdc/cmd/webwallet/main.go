// Command webwallet runs the passport-vdc demo wallet in a browser, over
// HTTPS on loopback.
//
//	go run ./cmd/webwallet      # https://127.0.0.1:7443, writes webwallet-tls.pem
//
// It shares its credential store with the CLI wallet (cmd/wallet), and
// its /callback must be registered with the issuer (cmd/issuer does by
// default). It gets its attestations from the demo Wallet Provider's
// service (cmd/wallet-provider, -wallet-provider-url). Unlike the CLI,
// it asks before presenting.
package main

import (
	"flag"
	"log"
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
	providerURL := flag.String("wallet-provider-url", "https://127.0.0.1:6443", "the demo Wallet Provider's service (cmd/wallet-provider)")
	clientID := flag.String("client-id", "passport-vdc-wallet", "this wallet's client_id")
	issuerCA := flag.String("trust-issuer-ca", "issuer-ca.pem", "comma-separated PEM files of issuer CAs whose credentials to accept (from cmd/issuer)")
	verifierCA := flag.String("trust-verifier-ca", "verifier-ca.pem", "comma-separated PEM files of verifier CAs whose requests to answer (from cmd/verifier)")
	trust := flag.String("trust", "issuer-tls.pem,verifier-tls.pem,wallet-provider-tls.pem", "comma-separated PEM files of TLS certificates to trust (from cmd/issuer, cmd/verifier and cmd/wallet-provider)")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: generate a self-signed one)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	certOut := flag.String("tls-cert-out", "webwallet-tls.pem", "where to write a generated TLS certificate")
	flag.Parse()

	httpClient, err := demotls.TrustingClient(*trust)
	if err != nil {
		log.Fatal(err)
	}
	provider := walletprovider.Client{URL: *providerURL, HTTP: httpClient}
	issuerRoots, err := walletapp.LoadCertPool(*issuerCA)
	if err != nil {
		log.Fatalf("issuer CA: %v (start cmd/issuer first)", err)
	}
	verifierTrust, err := walletapp.LoadVerifierTrust(*verifierCA)
	if err != nil {
		log.Fatalf("%v (start cmd/verifier first)", err)
	}
	app, err := webwallet.New(webwallet.Config{
		WalletURL:     *walletURL,
		Wallet:        walletapp.Config{ClientID: *clientID, Provider: provider, IssuerRoots: issuerRoots, HTTP: httpClient},
		Store:         walletapp.Store{Dir: *store},
		VerifierTrust: verifierTrust,
	})
	if err != nil {
		log.Fatal(err)
	}
	cert, err := demotls.Certificate(*certFile, *keyFile, *certOut, "passport-vdc demo web wallet (TLS)")
	if err != nil {
		log.Fatal(err)
	}
	// Long enough for the callback handler to finish the token and
	// credential requests.
	srv := demotls.Server(*addr, app, cert, 2*time.Minute)
	log.Printf("passport-vdc web wallet on https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
