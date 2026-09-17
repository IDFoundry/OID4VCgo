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

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
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
		VPFormatsSupported: vpFormatsSupported(cfg.CredentialFormat),
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
	mux.HandleFunc("POST /request/{id}", srv.handleRequestObject)
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

// vpFormatsSupported builds this Verifier's own "client_metadata" >
// "vp_formats_supported" (OID4VP §5.1) for whichever one format
// credentialFormat selects — matching buildQuery's own one-format-
// per-run scope, not advertising a format this session's DCQL query
// never actually asks for.
func vpFormatsSupported(credentialFormat string) map[string]any {
	if credentialFormat == "mso_mdoc" {
		// Unlike "dc+sd-jwt" (whose sd-jwt_alg_values/kb-jwt_alg_values
		// this binary's own JOSE-signed query genuinely constrains),
		// no established convention for "mso_mdoc"'s own inner
		// vp_formats_supported shape is verified against this suite —
		// left empty rather than guessing unverified field names; the
		// suite's own compatibility check is expected to key on the
		// "mso_mdoc" member's presence, not its contents.
		return map[string]any{"mso_mdoc": map[string]any{}}
	}
	return map[string]any{
		"dc+sd-jwt": map[string]any{
			"sd-jwt_alg_values": []string{"ES256"},
			"kb-jwt_alg_values": []string{"ES256"},
		},
	}
}
