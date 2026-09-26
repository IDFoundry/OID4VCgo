// Command verifier runs the passport-vdc demo Verifier over HTTPS on
// loopback.
//
//	go run ./cmd/verifier      # https://127.0.0.1:9443, writes verifier-tls.pem, verifier-ca.pem
//
// It trusts the demo issuer's CA (issuer-ca.pem, written by cmd/issuer)
// for credential signatures, and gmrtd's built-in ICAO CSCA master list
// for the "trust only the issuing country" check. It writes its own
// request-signing CA to verifier-ca.pem, for the demo wallets to trust.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotls"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "listen address")
	verifierURL := flag.String("verifier", "https://127.0.0.1:9443", "verifier URL")
	issuerURL := flag.String("issuer", "https://127.0.0.1:8543", "the demo issuer's URL (for its credentials' vct)")
	issuerCA := flag.String("issuer-ca", "issuer-ca.pem", "the demo issuer's CA certificate (from cmd/issuer)")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: generate a self-signed one)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	certOut := flag.String("tls-cert-out", "verifier-tls.pem", "where to write a generated TLS certificate for the wallet to trust")
	caOut := flag.String("verifier-ca-out", "verifier-ca.pem", "where to write the demo verifier CA certificate for wallets to trust")
	webWallet := flag.String("web-wallet", "https://127.0.0.1:7443", "the demo web wallet's URL, for the request page's \"Open in web wallet\" button (empty to hide it)")
	flag.Parse()

	caPEM, err := os.ReadFile(*issuerCA) // #nosec G304 -- operator-supplied path
	if err != nil {
		log.Fatalf("read issuer CA (start cmd/issuer first): %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatalf("%s holds no PEM certificates", *issuerCA)
	}
	cscaPool, err := cms.DefaultMasterList()
	if err != nil {
		log.Fatalf("load CSCA master list: %v", err)
	}
	app, err := verifierapp.New(verifierapp.Config{
		VerifierURL: *verifierURL, IssuerVCT: *issuerURL + "/vct/passport/1",
		IssuerRoots: roots, CSCAPool: cscaPool, WebWalletURL: *webWallet,
	})
	if err != nil {
		log.Fatal(err)
	}
	verifierCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: app.VerifierCACertificate().Raw})
	if err := os.WriteFile(*caOut, verifierCAPEM, 0o600); err != nil { // #nosec G703 -- operator-supplied path
		log.Fatalf("write %s: %v", *caOut, err)
	}
	log.Printf("wrote the demo verifier CA certificate to %s for wallets to trust", *caOut)
	cert, err := demotls.Certificate(*certFile, *keyFile, *certOut, "passport-vdc demo verifier (TLS)")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr: *addr, Handler: app,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, // TLS 1.3 only: FAPI 2.0 allows TLS 1.2 with just a few AES-GCM suites
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Printf("passport-vdc verifier on https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
