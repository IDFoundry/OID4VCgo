// Command wallet-provider runs the passport-vdc demo's stand-in Wallet
// Provider: an HTTPS service the demo wallets ask for Wallet
// Attestations and Key Attestations, so they never hold the provider's
// key. It writes the CA certificate the demo issuer verifies both kinds
// of attestation with (by their x5c chain), and keeps the provider's key
// and certificate in -key.
//
//	go run ./cmd/wallet-provider -key wallet-provider.pem -ca wallet-provider-ca.pem
//
// The key's certificate names the provider's identifier
// (-wallet-provider-issuer, which the issuer is given too). An existing
// -key file is reused, so restarting keeps the same CA. Without
// -tls-cert/-tls-key it generates a self-signed TLS certificate for
// 127.0.0.1 and localhost and writes it to -tls-cert-out, for the
// wallets to trust.
//
// It attests only -client-id, and any key a wallet sends it, without
// checking who is asking: a real Wallet Provider would first check
// platform evidence that the request comes from a genuine instance of
// its wallet, holding its keys in secure hardware.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotls"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:6443", "listen address")
	keyPath := flag.String("key", "wallet-provider.pem", "private key file (created if missing)")
	caPath := flag.String("ca", "wallet-provider-ca.pem", "CA certificate file to write, for the issuer")
	providerIssuer := flag.String("wallet-provider-issuer", "https://wallet-provider.passport-vdc.demo", "the demo Wallet Provider's identifier, named in its certificate")
	clientID := flag.String("client-id", "passport-vdc-wallet", "the wallet client_id this provider attests")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: generate a self-signed one)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	certOut := flag.String("tls-cert-out", "wallet-provider-tls.pem", "where to write a generated TLS certificate for the wallets to trust")
	flag.Parse()

	provider, created, err := walletprovider.LoadOrCreate(*providerIssuer, *keyPath)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		fmt.Println("created", *keyPath)
	} else {
		fmt.Println("reusing", *keyPath)
	}
	if err := os.WriteFile(*caPath, provider.CACertificatePEM(), 0o600); err != nil { // #nosec G703 -- operator-supplied path
		log.Fatalf("write %s: %v", *caPath, err)
	}
	fmt.Println("wrote", *caPath)

	cert, err := demotls.Certificate(*certFile, *keyFile, *certOut, "passport-vdc demo Wallet Provider (TLS)")
	if err != nil {
		log.Fatal(err)
	}
	srv := demotls.Server(*addr, provider.Handler(*clientID), cert, 30*time.Second)
	log.Printf("passport-vdc Wallet Provider on https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
