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
	"fmt"
	"log"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func main() {
	configPath := flag.String("config", "", "path to the JSON config file")
	flag.Usage = func() {
		_, _ = fmt.Fprint(flag.CommandLine.Output(), "usage: conformance-verifier -config <file>\n\n"+
			"A test harness for the OIDF conformance suite's verifier plan, not a\n"+
			"deployment model: it runs under development assurance, checks no\n"+
			"certificate revocation, and keeps its transactions in memory. Never\n"+
			"deploy it or copy its wiring; DEPLOYING.md is the checklist for a\n"+
			"production Verifier.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	srv, err := newServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("verifier client_id: %s", srv.v.ClientID())
	mux := srv.routes()

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

// newServer builds the Verifier and the server cfg describes.
func newServer(cfg Config) (*server, error) {
	clientCert, clientKey, err := cfg.clientCertificateAndKey()
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	issuerKeys, err := cfg.sdJWTVCIssuerKeys()
	if err != nil {
		return nil, fmt.Errorf("credential issuer: %w", err)
	}
	status, err := cfg.statusPolicy()
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	var mdocIssuerKeys verifier.MdocIssuerKeyResolver
	if cfg.CredentialFormat == "mso_mdoc" {
		mdocTrustAnchorPool, err := cfg.mdocTrustAnchorPool()
		if err != nil {
			return nil, fmt.Errorf("mdoc trust anchor: %w", err)
		}
		// No revocation check: the OIDF suite generates its own IACA
		// and document signer for each run, and publishes no CRL for
		// them that this binary could fetch.
		mdocIssuerKeys = verifier.X5ChainIssuerKeyResolver{Roots: mdocTrustAnchorPool, Revocation: certrevocation.NoCheck{}}
	}
	responseURI, err := fapi.ParseEndpointURL(cfg.BaseURL + "/response")
	if err != nil {
		return nil, fmt.Errorf("response_uri: %w", err)
	}

	v, err := verifier.New(verifier.Config{
		Assurance:          verifier.AssuranceDevelopment,
		ClientCertificate:  clientCert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: vpFormatsSupported(cfg.CredentialFormat),
	}, verifier.Dependencies{
		Signer: clientKey,
		Random: rand.Reader,
	})
	if err != nil {
		return nil, fmt.Errorf("verifier.New: %w", err)
	}
	return &server{cfg: cfg, v: v, sessions: newSessionStore(), issuerKeys: issuerKeys, mdocIssuerKeys: mdocIssuerKeys, status: status}, nil
}

// vpFormatsSupported builds this Verifier's own "client_metadata" >
// "vp_formats_supported" (OID4VP §5.1) for whichever one format
// credentialFormat selects — matching buildQuery's own one-format-
// per-run scope, not advertising a format this session's DCQL query
// never actually asks for.
func vpFormatsSupported(credentialFormat string) map[string]any {
	if credentialFormat == "mso_mdoc" {
		return verifier.MdocFormatSupport()
	}
	return verifier.SDJWTVCFormatSupport([]string{string(jose.ES256)}, []string{string(jose.ES256)})
}
