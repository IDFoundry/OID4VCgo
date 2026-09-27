// Command wallet-provider creates the passport-vdc demo's stand-in
// Wallet Provider: a private key and its certificate (for the demo
// wallet to attest itself and its holder keys with), and the CA
// certificate (for the demo issuer to verify both kinds of attestation
// by their x5c chain).
//
//	go run ./cmd/wallet-provider -key wallet-provider.pem -ca wallet-provider-ca.pem
//
// An existing -key file is reused, so rerunning just rewrites the CA
// certificate.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
)

func main() {
	keyPath := flag.String("key", "wallet-provider.pem", "private key file (created if missing)")
	caPath := flag.String("ca", "wallet-provider-ca.pem", "CA certificate file to write")
	flag.Parse()
	if err := run(*keyPath, *caPath); err != nil {
		log.Fatal(err)
	}
}

func run(keyPath, caPath string) error {
	// The issuer identifier isn't stored with the key; the demo issuer
	// and wallet are each told it separately (-wallet-provider-issuer).
	var provider *walletprovider.Provider
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- operator-supplied path
	switch {
	case err == nil:
		if provider, err = walletprovider.Load("", keyPEM); err != nil {
			return err
		}
		fmt.Println("reusing", keyPath)
	case errors.Is(err, fs.ErrNotExist):
		if provider, err = walletprovider.New(""); err != nil {
			return err
		}
		if keyPEM, err = provider.PEM(); err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil { // #nosec G703 -- operator-supplied path
			return fmt.Errorf("write %s: %w", keyPath, err)
		}
		fmt.Println("created", keyPath)
	default:
		return fmt.Errorf("read %s: %w", keyPath, err)
	}

	if err := os.WriteFile(caPath, provider.CACertificatePEM(), 0o600); err != nil { // #nosec G703 -- operator-supplied path
		return fmt.Errorf("write %s: %w", caPath, err)
	}
	fmt.Println("wrote", caPath)
	return nil
}
