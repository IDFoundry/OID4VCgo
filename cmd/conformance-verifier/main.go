// Command conformance-verifier stands up verifier.Verifier behind
// real HTTP for the OIDF conformance suite's own
// "oid4vp-1final-verifier-haip-test-plan" ("OpenID for Verifiable
// Presentations 1.0 Final/HAIP: Test a verifier") — the suite plays
// Wallet, driving this binary's real Authorization Request
// construction, request_uri hosting, and direct_post.jwt response
// verification. See conformance/verifier/README.md for how to run it
// against a live suite and what's been confirmed so far.
package main

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/verifier"
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

	clientCert, clientKey, err := cfg.clientCertificateAndKey()
	if err != nil {
		log.Fatalf("client certificate: %v", err)
	}
	issuerKeys, err := newStaticIssuerKeyResolver(cfg.CredentialIssuerJWK)
	if err != nil {
		log.Fatalf("credential issuer jwk: %v", err)
	}
	responseURI, err := fapi.ParseEndpointURL(cfg.BaseURL + "/response")
	if err != nil {
		log.Fatalf("response_uri: %v", err)
	}

	v, err := verifier.New(verifier.Config{
		ClientCertificate:  clientCert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
	}, verifier.Dependencies{
		Signer: clientKey,
		Random: rand.Reader,
	})
	if err != nil {
		log.Fatalf("verifier.New: %v", err)
	}
	log.Printf("verifier client_id: %s", v.ClientID())

	srv := &server{cfg: cfg, v: v, sessions: newSessionStore(), issuerKeys: issuerKeys}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", srv.handleAuthorize)
	mux.HandleFunc("GET /request/{id}", srv.handleRequestObject)
	mux.HandleFunc("POST /response", srv.handleResponse)
	mux.HandleFunc("GET /result/{id}", srv.handleResult)

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
