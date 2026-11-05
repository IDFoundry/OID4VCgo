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
// It attests only -client-id, without checking who is asking. It gives
// the Android demo wallet attestation challenges (POST
// /attestation-challenge) and verifies the Android Key Attestation
// chains it sends with its keys: a bad signature, another key or an
// unknown or used challenge is refused; a chain that isn't hardware
// Google vouches for (an emulator's) is logged, and refused only with
// -require-hardware-key-attestation. A key sent without a chain (iOS,
// the CLI and web wallets) is attested as before, unverified: a real
// Wallet Provider would first check platform evidence for every key.
//
// The attestations are issued by the library's Wallet Provider
// (oid4vcgo/walletprovider), which this service gives demo-only
// evidence for what it checked; each names the provider's status list,
// served at /v1/status under -url. The library's own protocol is served
// under /v1/ too; with -android-app it attests that app's Android Key
// Attestation chains (Google-rooted, locked and verified boot) there.
// The library's instances are kept in -instances, and their status list
// indices and statuses in -status-indices, so a restart keeps them.
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
	verifiedKeys := flag.String("verified-keys", "wallet-provider-keys.json", "file keeping the Android keys whose attestation chains were verified, so a restart still recognises them")
	requireHardware := flag.Bool("require-hardware-key-attestation", false, "refuse an Android key whose attestation chain isn't from hardware Google vouches for (an emulator's, say), rather than only log it; a key sent without a chain (iOS, the CLI and web wallets) is still attested")
	publicURL := flag.String("url", "", "the service's public https URL, which every attestation's status list is under (default: https://-addr)")
	instances := flag.String("instances", "wallet-provider-instances.json", "file keeping the wallet instances the library Wallet Provider registered, so a restart keeps them")
	statusIndices := flag.String("status-indices", "wallet-provider-status-indices.json", "file keeping the instances' status list indices and statuses, so a restart neither forgets a revocation nor reuses an index")
	var androidApps walletprovider.AndroidAppsFlag
	flag.Var(&androidApps, "android-app", walletprovider.AndroidAppsUsage)
	flag.Parse()
	if *publicURL == "" {
		*publicURL = "https://" + *addr
	}

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
	service, err := provider.NewService(walletprovider.ServiceConfig{
		ClientID: *clientID, RequireHardwareKeyAttestation: *requireHardware, VerifiedKeysPath: *verifiedKeys,
		URL: *publicURL, AndroidApps: androidApps,
		InstancesPath: *instances, StatusIndicesPath: *statusIndices,
	})
	if err != nil {
		log.Fatal(err)
	}
	srv := demotls.Server(*addr, service, cert, 30*time.Second)
	log.Printf("passport-vdc Wallet Provider on https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
