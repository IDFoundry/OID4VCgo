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

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceusage"
)

func main() {
	configPath := flag.String("config", "", "path to the JSON config file")
	conformanceusage.Set("conformance-issuer -config <file>",
		"A test harness for the OIDF conformance suite's issuer plans, not a\n"+
			"deployment model: its Authorization Server and Credential Issuer run\n"+
			"under development assurance, with in-memory stores and test keys.\n"+
			"Never deploy it or copy its wiring; DEPLOYING.md is the checklist\n"+
			"for a production issuer.")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	built, err := newServers(cfg)
	if err != nil {
		log.Fatalf("build server: %v", err)
	}
	if built.offers != nil {
		go func() {
			log.Fatal(offersServer(cfg.Offers.ListenAddr, built.offers).ListenAndServe())
		}()
		log.Printf("minting credential offers on http://%s/offers", cfg.Offers.ListenAddr)
	}

	// The CRL distribution point of the mdoc Document Signer
	// certificate, which the OIDF suite fetches and checks for every
	// mdoc it's issued.
	crl, err := cfg.mdocCRL()
	if err != nil {
		log.Fatalf("mdoc crl: %v", err)
	}
	if crl != nil {
		go func() {
			log.Fatal(conformancecert.ServeMdocCRL(cfg.Mdoc.CRLListenAddr, crl))
		}()
		log.Printf("serving the mdoc IACA CRL on http://%s%s", cfg.Mdoc.CRLListenAddr, conformancecert.MdocCRLPath)
	}

	tlsCert, err := cfg.tlsCertificate()
	if err != nil {
		log.Fatalf("tls certificate: %v", err)
	}
	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: built.public,
		// MinVersion/CipherSuites match FAPIgo's own OpenID-Certified
		// cmd/conformance-as (server/tls.go's own doc comment). TLS 1.3
		// isn't disabled: a client offering it still negotiates it,
		// with crypto/tls's three built-in AEAD suites, which
		// CipherSuites doesn't restrict. CipherSuites narrows TLS 1.2
		// to ECDHE with AES-GCM, which is what the OIDF suite's
		// FAPI-RW-8.5-1/-2 check probes: it connects with TLS 1.2 and
		// flags any other suite the server accepts there (with Go's
		// defaults, CBC and ChaCha20-Poly1305 suites: "Server accepted
		// a cipher that is not on the list of permitted ciphers").
		// MinVersion refuses TLS 1.0 and 1.1.
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

// offersServer serves the offer-minting handler on addr, a loopback
// address (validateOffers): plain HTTP, never the Credential Issuer's
// TLS listener.
func offersServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
}
