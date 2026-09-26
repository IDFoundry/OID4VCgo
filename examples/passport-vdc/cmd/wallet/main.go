// Command wallet is the passport-vdc demo wallet.
//
//	go run ./cmd/wallet receive 'openid-credential-offer://?credential_offer=...'
//	go run ./cmd/wallet list
//
// receive redeems a Credential Offer from the demo issuer, attesting
// itself with the demo Wallet Provider key (see cmd/wallet-provider),
// and stores every offered credential with its holder key. By default
// it prints the authorization URL for you to open and approve in a
// browser; -headless approves automatically.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
)

func main() {
	fs := flag.NewFlagSet("wallet", flag.ExitOnError)
	store := fs.String("store", "wallet-store", "directory the wallet keeps credentials in")
	providerKey := fs.String("wallet-provider-key", "wallet-provider.pem", "the demo Wallet Provider's private key")
	providerIssuer := fs.String("wallet-provider-issuer", "https://wallet-provider.passport-vdc.demo", "the demo Wallet Provider's identifier")
	clientID := fs.String("client-id", "passport-vdc-wallet", "this wallet's client_id")
	redirectURI := fs.String("redirect-uri", "http://127.0.0.1:8765/callback", "this wallet's loopback redirect URI")
	issuerCA := fs.String("issuer-ca", "issuer-tls.pem", "PEM certificate(s) to trust for the issuer's TLS (from cmd/issuer)")
	headless := fs.Bool("headless", false, "approve automatically instead of in a browser")

	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}

	switch cmd {
	case "receive":
		if fs.NArg() != 1 {
			usage()
		}
		httpClient, err := trustingClient(*issuerCA)
		if err != nil {
			log.Fatal(err)
		}
		keyPEM, err := os.ReadFile(*providerKey) // #nosec G304 -- operator-supplied path
		if err != nil {
			log.Fatalf("read wallet provider key (run cmd/wallet-provider first): %v", err)
		}
		provider, err := walletprovider.Load(*providerIssuer, keyPEM)
		if err != nil {
			log.Fatal(err)
		}
		var approver walletapp.Approver = walletapp.BrowserApprover{
			RedirectURI: *redirectURI,
			Show: func(u string) {
				fmt.Printf("Open this URL in a browser to approve:\n\n  %s\n\nWaiting for approval...\n", u)
			},
		}
		if *headless {
			approver = walletapp.HeadlessApprover{HTTP: httpClient}
		}
		if err := receive(fs.Arg(0), *store, walletapp.Config{
			ClientID: *clientID, RedirectURI: *redirectURI, Provider: provider, HTTP: httpClient,
		}, approver); err != nil {
			log.Fatal(err)
		}
	case "list":
		if err := list(*store); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wallet receive [flags] <credential-offer-uri> | wallet list [flags]")
	os.Exit(2)
}

func receive(offerURI, dir string, cfg walletapp.Config, approver walletapp.Approver) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	received, err := walletapp.Receive(ctx, cfg, offerURI, approver)
	if err != nil {
		return err
	}
	store := walletapp.Store{Dir: dir}
	for _, r := range received {
		path, err := store.Save(r, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("received %-16s (%s) → %s\n", r.ConfigurationID, r.Format, path)
	}
	return nil
}

func list(dir string) error {
	stored, err := walletapp.Store{Dir: dir}.List()
	if err != nil {
		return err
	}
	if len(stored) == 0 {
		fmt.Println("no credentials in", dir)
		return nil
	}
	for _, s := range stored {
		fmt.Printf("%s  %-16s %-10s %6d bytes  %s\n", s.ReceivedAt.Local().Format("2006-01-02 15:04"), s.ConfigurationID, s.Format, len(s.Credential), s.Path)
	}
	return nil
}

// trustingClient returns an HTTP client trusting the certificates in
// caFile (the demo issuer's self-signed TLS certificate) in addition to
// the system roots. A missing file just means system roots.
func trustingClient(caFile string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	pemBytes, err := os.ReadFile(caFile) // #nosec G304 -- operator-supplied path
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", caFile, err)
	case !roots.AppendCertsFromPEM(pemBytes):
		return nil, fmt.Errorf("%s holds no PEM certificates", caFile)
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, nil
}
