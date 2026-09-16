// Command conformance-issuer pairs a real fapigo/server.Server (FAPI
// 2.0 Security Profile Final, Wallet Attestation client
// authentication, DPoP) with a real oid4vcigo/issuer.Issuer behind
// real HTTP, for the OIDF conformance suite's own
// "oid4vci-1_0-issuer-haip-test-plan" ("OpenID for Verifiable
// Credential Issuance 1.0 Final/HAIP: Test an issuer"). See
// conformance/issuer/README.md for what this covers and what's still
// open.
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
	mux, err := newServerMux(cfg)
	if err != nil {
		log.Fatalf("build server: %v", err)
	}

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
