// Command conformance-issuer pairs a real fapigo/server.Server (FAPI
// 2.0 Security Profile Final, Wallet Attestation client
// authentication, DPoP) with a real oid4vcgo/issuer.Issuer behind
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

	"github.com/idfoundry/fapigo/server"
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
		Addr:    cfg.ListenAddr,
		Handler: mux,
		// MinVersion/CipherSuites match FAPIgo's own OpenID-Certified
		// cmd/conformance-as (server/tls.go's own doc comment): without
		// them, Go negotiates TLS 1.3 by default, whose three built-in
		// AEAD suites always include ChaCha20-Poly1305 — which the
		// OIDF suite's own FAPI-RW-8.5-1/-2 probe flags as "not
		// permitted" (confirmed live: "Server accepted a cipher that
		// is not on the list of permitted ciphers"), even though Go's
		// crypto/tls gives no way to restrict TLS 1.3's own suite
		// selection at all. Forcing TLS 1.2 with this narrower
		// AES-GCM-only list sidesteps that entirely.
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
			CipherSuites: server.FAPIRWTLSCipherSuites,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
