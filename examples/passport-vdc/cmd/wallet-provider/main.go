// Command wallet-provider creates the passport-vdc demo's stand-in
// Wallet Provider: a private key and its certificate (for the demo
// wallet to attest itself and its holder keys with), and the CA
// certificate (for the demo issuer to verify both kinds of attestation
// by their x5c chain).
//
//	go run ./cmd/wallet-provider -key wallet-provider.pem -ca wallet-provider-ca.pem
//
// The key's certificate names the provider's identifier
// (-wallet-provider-issuer, which the issuer and wallets are given too).
// An existing -key file is reused, so rerunning just rewrites the CA
// certificate.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
)

func main() {
	keyPath := flag.String("key", "wallet-provider.pem", "private key file (created if missing)")
	caPath := flag.String("ca", "wallet-provider-ca.pem", "CA certificate file to write")
	providerIssuer := flag.String("wallet-provider-issuer", "https://wallet-provider.passport-vdc.demo", "the demo Wallet Provider's identifier, named in its certificate")
	flag.Parse()
	if err := run(*keyPath, *caPath, *providerIssuer); err != nil {
		log.Fatal(err)
	}
}

func run(keyPath, caPath, providerIssuer string) error {
	provider, created, err := walletprovider.LoadOrCreate(providerIssuer, keyPath)
	if err != nil {
		return err
	}
	if created {
		fmt.Println("created", keyPath)
	} else {
		fmt.Println("reusing", keyPath)
	}
	if err := os.WriteFile(caPath, provider.CACertificatePEM(), 0o600); err != nil { // #nosec G703 -- operator-supplied path
		return fmt.Errorf("write %s: %w", caPath, err)
	}
	fmt.Println("wrote", caPath)
	return nil
}
