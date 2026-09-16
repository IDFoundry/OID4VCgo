// Command conformance-wallet-vp stands up wallet's own OID4VP
// presentation half behind real HTTP for the OIDF conformance suite's
// own "oid4vp-1final-wallet-haip-test-plan" ("OpenID for Verifiable
// Presentations 1.0 Final/HAIP: Test a wallet") — specifically its
// direct_post.jwt + x509_hash + request_uri_signed module list (the
// suite plays Verifier, driving this binary's real Authorization
// Request resolution and credential presentation over the redirect
// flow); the dc_api.jwt variants aren't covered — see
// conformance/wallet-vp/README.md.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"time"
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

	issuerKey, err := cfg.credentialIssuerKey()
	if err != nil {
		log.Fatalf("credential issuer key: %v", err)
	}
	holderKey, err := cfg.holderPrivateKey()
	if err != nil {
		log.Fatalf("holder private key: %v", err)
	}
	cred, err := issueFixtureCredential(cfg, issuerKey, holderKey)
	if err != nil {
		log.Fatalf("issue fixture credential: %v", err)
	}
	log.Printf("issued fixture %s credential (vct=%s)", cred.Format, cfg.VCT)

	srv := &server{cred: cred}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", srv.handleAuthorize)

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
