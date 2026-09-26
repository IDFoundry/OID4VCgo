// Command issuer runs the passport-vdc demo Credential Issuer.
//
//	go run ./cmd/wallet-provider            # once: wallet-provider.pem + .jwks.json
//	go run ./cmd/issuer -wallet-provider-jwks wallet-provider.jwks.json
//
// then open http://127.0.0.1:8080 and upload a gmrtd portable passport
// file. Passports are verified against gmrtd's built-in ICAO CSCA
// master list.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	issuerURL := flag.String("issuer", "http://127.0.0.1:8080", "issuer URL (loopback http, or https behind a TLS-terminating proxy)")
	jwksPath := flag.String("wallet-provider-jwks", "wallet-provider.jwks.json", "the demo Wallet Provider's public JWK Set")
	providerIssuer := flag.String("wallet-provider-issuer", "https://wallet-provider.passport-vdc.demo", "the demo Wallet Provider's identifier (Wallet Attestation iss)")
	clientID := flag.String("wallet-client-id", "passport-vdc-wallet", "the demo wallet's client_id")
	redirectURI := flag.String("wallet-redirect-uri", "http://127.0.0.1:8765/callback", "the demo wallet's redirect URI")
	flag.Parse()

	jwks, err := os.ReadFile(*jwksPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		log.Fatalf("read wallet provider JWKS (run cmd/wallet-provider first): %v", err)
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		log.Fatalf("load CSCA master list: %v", err)
	}
	app, err := issuerapp.New(issuerapp.Config{
		IssuerURL: *issuerURL,
		CSCAPool:  pool,
		Wallet: issuerapp.WalletClient{
			ClientID: *clientID, RedirectURIs: []string{*redirectURI},
			ProviderIssuer: *providerIssuer, ProviderJWKS: jwks,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr: *addr, Handler: app,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Printf("passport-vdc issuer on %s (issuer %s)", *addr, *issuerURL)
	log.Fatal(srv.ListenAndServe())
}
