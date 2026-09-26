// Command issuer runs the passport-vdc demo Credential Issuer over
// HTTPS on loopback.
//
//	go run ./cmd/wallet-provider     # once: wallet-provider.pem + .jwks.json
//	go run ./cmd/issuer              # https://127.0.0.1:8543, writes issuer-tls.pem
//
// Without -tls-cert/-tls-key it generates a self-signed certificate for
// 127.0.0.1 and localhost and writes it to -tls-cert-out, for the demo
// wallet (and your browser) to trust. Passports are verified against
// gmrtd's built-in ICAO CSCA master list.
package main

import (
	"crypto/tls"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotls"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8543", "listen address")
	issuerURL := flag.String("issuer", "https://127.0.0.1:8543", "issuer URL")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: generate a self-signed one)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	certOut := flag.String("tls-cert-out", "issuer-tls.pem", "where to write a generated TLS certificate for the wallet to trust")
	caOut := flag.String("issuer-ca-out", "issuer-ca.pem", "where to write the demo CA certificate for verifiers to trust")
	jwksPath := flag.String("wallet-provider-jwks", "wallet-provider.jwks.json", "the demo Wallet Provider's public JWK Set")
	providerIssuer := flag.String("wallet-provider-issuer", "https://wallet-provider.passport-vdc.demo", "the demo Wallet Provider's identifier (Wallet Attestation iss)")
	clientID := flag.String("wallet-client-id", "passport-vdc-wallet", "the demo wallet's client_id")
	redirectURIs := flag.String("wallet-redirect-uris", "http://127.0.0.1:8765/callback,https://127.0.0.1:7443/callback", "the demo wallets' redirect URIs, comma-separated (CLI wallet, web wallet)")
	webWallet := flag.String("web-wallet", "https://127.0.0.1:7443", "the demo web wallet's URL, for the offer page's \"Open in web wallet\" button (empty to hide it)")
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
			ClientID: *clientID, RedirectURIs: splitList(*redirectURIs),
			ProviderIssuer: *providerIssuer, ProviderJWKS: jwks,
		},
		WebWalletURL: *webWallet,
	})
	if err != nil {
		log.Fatal(err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: app.IssuerCACertificate().Raw})
	if err := os.WriteFile(*caOut, caPEM, 0o600); err != nil { // #nosec G703 -- operator-supplied path
		log.Fatalf("write %s: %v", *caOut, err)
	}
	log.Printf("wrote the demo CA certificate to %s for verifiers to trust", *caOut)

	cert, err := demotls.Certificate(*certFile, *keyFile, *certOut, "passport-vdc demo issuer (TLS)")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr: *addr, Handler: app,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Printf("passport-vdc issuer on https://%s (issuer %s)", *addr, *issuerURL)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
