// Command conformance-verifier stands up verifier.Verifier behind
// real HTTP for the OIDF conformance suite's own
// "oid4vp-1final-verifier-haip-test-plan" ("OpenID for Verifiable
// Presentations 1.0 Final/HAIP: Test a verifier") — the suite plays
// Wallet, driving this binary's real Authorization Request
// construction, request_uri hosting, and direct_post.jwt response
// verification. Config.Engine picks whether its own session store
// drives verifier.Verifier directly (the default) or
// verifier.Transactions serves the whole flow (transactions.go). See
// conformance/verifier/README.md for how to run it against a live
// suite and what's been confirmed so far.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/internal/conformanceusage"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func main() {
	configPath := flag.String("config", "", "path to the JSON config file")
	conformanceusage.Set("conformance-verifier -config <file>",
		"A test harness for the OIDF conformance suite's verifier plan, not a\n"+
			"deployment model: by default it runs under development assurance,\n"+
			"checks certificate revocation only against the CRLs its config\n"+
			"names, and keeps its transactions in\n"+
			"memory. Never deploy it or copy its wiring; DEPLOYING.md is the\n"+
			"checklist for a production Verifier.")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if err := cfg.startIssuerCRL(context.Background()); err != nil {
		log.Fatal(err)
	}
	mux, clientID, err := newHandler(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("verifier client_id: %s (engine %q)", clientID, cfg.Engine)

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

// newServer builds the Verifier and the server cfg describes: the
// sessions engine's.
func newServer(cfg Config) (*server, error) {
	issuerKeys, mdocIssuerKeys, err := cfg.issuerKeyResolvers()
	if err != nil {
		return nil, err
	}
	status, err := cfg.statusPolicy()
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	v, err := newVerifier(cfg, verifier.AssuranceDevelopment)
	if err != nil {
		return nil, err
	}
	return &server{cfg: cfg, v: v, sessions: newSessionStore(), issuerKeys: issuerKeys, mdocIssuerKeys: mdocIssuerKeys, status: status}, nil
}

// issuerKeyResolvers is the "dc+sd-jwt" and "mso_mdoc" issuer trust
// cfg configures.
func (c Config) issuerKeyResolvers() (verifier.SDJWTVCIssuerKeyResolver, verifier.MdocIssuerKeyResolver, error) {
	issuerKeys, err := c.sdJWTVCIssuerKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("credential issuer: %w", err)
	}
	if c.CredentialFormat != "mso_mdoc" {
		return issuerKeys, nil, nil
	}
	mdocTrustAnchorPool, err := c.mdocTrustAnchorPool()
	if err != nil {
		return nil, nil, fmt.Errorf("mdoc trust anchor: %w", err)
	}
	// The Document Signer's revocation, against IssuerCRL's CRLs when
	// it's set: the OIDF suite's own IACA and Document Signers publish
	// no CRL this binary could fetch, so its mdoc runs leave it unset.
	return issuerKeys, verifier.X5ChainIssuerKeyResolver{Roots: mdocTrustAnchorPool, Revocation: c.revocation()}, nil
}

// newVerifier builds the verifier.Verifier cfg describes, at assurance.
func newVerifier(cfg Config, assurance verifier.AssuranceLevel) (*verifier.Verifier, error) {
	clientCert, clientKey, err := cfg.clientCertificateAndKey()
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	responseURI, err := fapi.ParseEndpointURL(cfg.BaseURL + "/response")
	if err != nil {
		return nil, fmt.Errorf("response_uri: %w", err)
	}
	v, err := verifier.New(verifier.Config{
		Assurance:          assurance,
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
	return v, nil
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
