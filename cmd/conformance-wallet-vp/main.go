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
// It's a conformance harness: it verifies the Verifier's TLS
// certificate only against the config's verifier_tls_trust_anchors_pem,
// and its Request Object certificate chain only against
// verifier_trust_anchors_pem — see the README's "What a passing run
// shows". Config.Engine "walletflow" answers /authorize through
// walletflow instead of the wallet package directly (walletflow.go).
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceusage"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func main() {
	configPath := flag.String("config", "", "path to the JSON config file")
	conformanceusage.Set("conformance-wallet-vp -config <file>",
		"A test harness for the OIDF conformance suite's wallet (OID4VP) plan,\n"+
			"not a wallet to model one on: it trusts the Verifiers its config\n"+
			"names, and presents fixture credentials. Build a wallet on\n"+
			"the wallet package, or on the mobile libraries.")
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
		serveMdocCRL(cfg)
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
	client, tlsVerified, err := cfg.verifierHTTPClient()
	if err != nil {
		log.Fatalf("verifier http client: %v", err)
	}
	// A conformance harness, not a Wallet to judge a Verifier's
	// security by: say what a completed presentation doesn't show.
	if !tlsVerified {
		log.Printf("WARNING: verifier_tls_trust_anchors_pem is unset: the Verifier's TLS certificate is not verified")
	}
	if _, none := trust.(wallet.NoVerifierTrust); none {
		log.Printf("WARNING: verifier_trust_anchors_pem is unset: the Verifier's Request Object certificate chain is not checked, only its signature and x509_hash client_id")
	}
	srv := &server{cred: cred, trust: trust, acceptSANDNS: cfg.AcceptX509SANDNS, http: client}

	mux := http.NewServeMux()
	if cfg.Engine == engineWalletflow {
		if srv.flow, err = newFlow(cfg, cred, trust, client); err != nil {
			log.Fatalf("walletflow engine: %v", err)
		}
		log.Printf("engine: walletflow")
		mux.HandleFunc("GET /authorize", srv.handleAuthorizeWalletflow)
	} else {
		mux.HandleFunc("GET /authorize", srv.handleAuthorize)
	}
	// The DC API stand-in: see handleDCAPI. It presents the fixture
	// credential to anyone who asks, for any origin they name.
	mux.HandleFunc("POST /dcapi", srv.handleDCAPI)
	log.Printf("WARNING: POST /dcapi presents the configured credential to any caller, for any origin: run this harness only against a conformance suite, with throwaway keys and credentials")

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

// serveMdocCRL starts the plain-HTTP listener for the IACA's CRL when
// the config has one — the CRL distribution point of the fixture
// mdoc's Document Signer certificate, which the OIDF suite fetches
// and checks for every mdoc presented to it.
func serveMdocCRL(cfg Config) {
	crl, err := cfg.mdocCRL()
	if err != nil {
		log.Fatalf("mdoc crl: %v", err)
	}
	if crl == nil {
		log.Printf("WARNING: mdoc_crl_pem is unset: nothing serves the Document Signer certificate's CRL distribution point")
		return
	}
	go func() {
		log.Fatal(conformancecert.ServeMdocCRL(cfg.MdocCRLListenAddr, crl))
	}()
	log.Printf("serving the mdoc IACA CRL on http://%s%s", cfg.MdocCRLListenAddr, conformancecert.MdocCRLPath)
}
