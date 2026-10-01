// Command wallet is the passport-vdc demo wallet.
//
//	go run ./cmd/wallet receive 'openid-credential-offer://?credential_offer=...'
//	go run ./cmd/wallet list
//	go run ./cmd/wallet present [-format mso_mdoc|dc+sd-jwt] [-yes] 'openid4vp://?client_id=...&request_uri=...'
//
// receive redeems a Credential Offer from the demo issuer, attesting
// itself and its holder keys through the demo Wallet Provider's service
// (cmd/wallet-provider, -wallet-provider-url), and stores every offered credential with its holder key. By default
// it prints the authorization URL for you to open and approve in a
// browser; -headless -code <code> approves automatically. present answers a
// request from a verifier whose certificate chains to a trusted
// verifier CA (-trust-verifier-ca, verifier-ca.pem from cmd/verifier),
// showing who is asking and what they'd see, and asking you first
// (-yes skips that); it discloses only what the request asks for.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotls"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func main() {
	fs := flag.NewFlagSet("wallet", flag.ExitOnError)
	store := fs.String("store", "wallet-store", "directory the wallet keeps credentials in")
	providerURL := fs.String("wallet-provider-url", "https://127.0.0.1:6443", "receive: the demo Wallet Provider's service (cmd/wallet-provider)")
	clientID := fs.String("client-id", "passport-vdc-wallet", "this wallet's client_id")
	redirectURI := fs.String("redirect-uri", "http://127.0.0.1:8765/callback", "this wallet's loopback redirect URI")
	trust := fs.String("trust", "issuer-tls.pem,verifier-tls.pem,wallet-provider-tls.pem", "comma-separated PEM files of TLS certificates to trust (from cmd/issuer, cmd/verifier and cmd/wallet-provider); missing files are skipped")
	headless := fs.Bool("headless", false, "receive: approve automatically instead of in a browser (needs -code)")
	code := fs.String("code", "", "receive -headless: the confirmation code shown with the offer")
	issuerCA := fs.String("trust-issuer-ca", "issuer-ca.pem", "receive: comma-separated PEM files of issuer CAs whose credentials to accept (from cmd/issuer)")
	verifierCA := fs.String("trust-verifier-ca", "verifier-ca.pem", "present: comma-separated PEM files of verifier CAs whose requests to answer (from cmd/verifier)")
	yes := fs.Bool("yes", false, "present: share without asking")
	format := fs.String("format", "", "present: only offer stored credentials of this format (mso_mdoc or dc+sd-jwt)")
	state := fs.String("state", "", "a cmd/demo state directory: take the store and trust files from it (flags set explicitly still win)")

	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}
	if *state != "" {
		useState(fs, *state, map[string]*string{
			"store": store, "trust": trust,
			"trust-issuer-ca": issuerCA, "trust-verifier-ca": verifierCA,
		})
	}

	switch cmd {
	case "receive":
		if fs.NArg() != 1 {
			usage()
		}
		httpClient, err := demotls.TrustingClient(*trust)
		if err != nil {
			log.Fatal(err)
		}
		provider := walletprovider.Client{URL: *providerURL, HTTP: httpClient}
		issuerRoots, err := walletapp.LoadCertPool(*issuerCA)
		if err != nil {
			log.Fatalf("issuer CA: %v (start cmd/issuer first)", err)
		}
		var approver walletapp.Approver = walletapp.BrowserApprover{
			RedirectURI: *redirectURI,
			Show: func(u string) {
				fmt.Printf("Open this URL in a browser to approve:\n\n  %s\n\nWaiting for approval...\n", u)
			},
		}
		if *headless {
			approver = walletapp.HeadlessApprover{HTTP: httpClient, Code: *code}
		}
		if err := receive(fs.Arg(0), *store, walletapp.Config{
			ClientID: *clientID, RedirectURI: *redirectURI, Provider: provider, IssuerRoots: issuerRoots, HTTP: httpClient,
		}, approver); err != nil {
			log.Fatal(err)
		}
	case "list":
		if err := list(*store); err != nil {
			log.Fatal(err)
		}
	case "present":
		if fs.NArg() != 1 {
			usage()
		}
		httpClient, err := demotls.TrustingClient(*trust)
		if err != nil {
			log.Fatal(err)
		}
		verifierTrust, err := walletapp.LoadVerifierTrust(*verifierCA)
		if err != nil {
			log.Fatalf("%v (start cmd/verifier first)", err)
		}
		if err := present(fs.Arg(0), *store, *format, *yes, httpClient, verifierTrust); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wallet receive [flags] <credential-offer-uri> | wallet list [flags] | wallet present [flags] <openid4vp-uri>")
	os.Exit(2)
}

func receive(offerURI, dir string, cfg walletapp.Config, approver walletapp.Approver) error {
	// Long enough for an operator to review a deferred issuance.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cfg.OnPending = func(p *walletapp.Pending) {
		fmt.Printf("the issuer deferred %s (%s) for review; polling every %s until it decides…\n", p.ConfigurationID, p.Format, p.Interval)
	}
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

// present answers a presentation request, first showing the holder
// who is asking and what they'd see, unless yes.
func present(link, dir, format string, yes bool, httpClient *http.Client, trust wallet.VerifierTrust) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	prepared, err := walletapp.Prepare(ctx, link, walletapp.Store{Dir: dir}, httpClient, trust)
	if err != nil {
		return err
	}
	if !yes && !confirmShare(prepared, format) {
		fmt.Println("declined — nothing was shared")
		return nil
	}
	presented, err := prepared.Send(ctx, format)
	if err != nil {
		return err
	}
	fmt.Printf("presented %s to %s\n", strings.Join(presented.Credentials, ", "), presented.VerifierClientID)
	if presented.RedirectURI != "" {
		fmt.Printf("the verifier asks you to continue in your browser at:\n  %s\n", presented.RedirectURI)
	}
	return nil
}

// confirmShare shows the verifier and what each way of answering in
// format ("" for any) would disclose, and asks the holder to confirm.
func confirmShare(p *walletapp.Prepared, format string) bool {
	fmt.Printf("Verifier %q (%s) asks for your passport credential.\nThe answer goes to %s.\n", p.VerifierName, p.VerifierClientID, p.ResponseURI)
	for _, o := range p.Options {
		if format != "" && o.Format != format {
			continue
		}
		fmt.Printf("As %s it will see only:\n", o.Format)
		for _, c := range o.Claims {
			fmt.Printf("  - %s\n", strings.Join(c, " › "))
		}
	}
	fmt.Print("Share? [y/N] ")
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(answer), "y")
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

// useState points the flags a cmd/demo state directory provides at its
// files, unless they were set explicitly.
func useState(fs *flag.FlagSet, dir string, flags map[string]*string) {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	files := map[string]string{
		"store": "wallet-store", "trust": "tls-cert.pem",
		"trust-issuer-ca": "issuer-ca.pem", "trust-verifier-ca": "verifier-ca.pem",
	}
	for name, v := range flags {
		if !set[name] {
			*v = filepath.Join(dir, files[name])
		}
	}
}
