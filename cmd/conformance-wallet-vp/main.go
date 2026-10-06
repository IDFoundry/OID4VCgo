// Command conformance-wallet-vp stands up wallet's own OID4VP
// presentation half behind real HTTP for the OIDF conformance suite's
// own "oid4vp-1final-wallet-haip-test-plan" ("OpenID for Verifiable
// Presentations 1.0 Final/HAIP: Test a wallet") — specifically its
// direct_post.jwt + x509_hash + request_uri_signed module list (the
// suite plays Verifier, driving this binary's real Authorization
// Request resolution and credential presentation over the redirect
// flow), under either credential format the plan's own
// VP1FinalWalletCredentialFormat variant offers (sd_jwt_vc, the
// default, or iso_mdl — see Config.CredentialFormat/credential.go's
// own issueFixtureMdocCredential) — and its three dc_api.jwt module
// lists, through POST /dcapi (dcapi.go), with the driver standing in
// for the browser — see conformance/wallet-vp/README.md.
//
// It's a conformance harness: it doesn't verify the Verifier's TLS
// certificate, and checks the Verifier's Request Object certificate
// chain only against the config's verifier_trust_anchors_pem — see
// the README's "What a passing run shows".
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

func main() {
	configPath := flag.String("config", "", "path to the JSON config file")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	holderKey, err := cfg.holderPrivateKey()
	if err != nil {
		log.Fatalf("holder private key: %v", err)
	}
	var cred wallet.HeldCredential
	if cfg.isMdoc() {
		cred, err = issueFixtureMdocCredential(cfg, holderKey)
		if err != nil {
			log.Fatalf("issue fixture mdoc credential: %v", err)
		}
		log.Printf("issued fixture %s credential (doctype=%s)", cred.Format, cfg.MdocDocType)
	} else {
		issuerKey, keyErr := cfg.credentialIssuerKey()
		if keyErr != nil {
			log.Fatalf("credential issuer key: %v", keyErr)
		}
		cred, err = issueFixtureCredential(cfg, issuerKey, holderKey)
		if err != nil {
			log.Fatalf("issue fixture credential: %v", err)
		}
		log.Printf("issued fixture %s credential (vct=%s)", cred.Format, cfg.VCT)
	}

	trust, err := cfg.verifierTrust()
	if err != nil {
		log.Fatalf("verifier trust: %v", err)
	}
	// A conformance harness, not a Wallet to judge a Verifier's
	// security by: say what a completed presentation doesn't show.
	log.Printf("WARNING: this harness does not verify the Verifier's TLS certificate")
	if _, none := trust.(wallet.NoVerifierTrust); none {
		log.Printf("WARNING: verifier_trust_anchors_pem is unset: the Verifier's Request Object certificate chain is not checked, only its signature and x509_hash client_id")
	}
	srv := &server{cred: cred, trust: trust}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", srv.handleAuthorize)
	// The DC API stand-in: see handleDCAPI.
	mux.HandleFunc("POST /dcapi", srv.handleDCAPI)

	tlsCert, err := cfg.tlsCertificate()
	if err != nil {
		log.Fatalf("tls certificate: %v", err)
	}
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{tlsCert}},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
