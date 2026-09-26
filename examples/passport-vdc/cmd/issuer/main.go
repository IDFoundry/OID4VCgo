// Command issuer runs the passport-vdc demo Credential Issuer over
// HTTPS on loopback.
//
//	go run ./cmd/wallet-provider     # once: wallet-provider.pem + .jwks.json
//	go run ./cmd/issuer              # https://127.0.0.1:8443, writes issuer-tls.pem
//
// Without -tls-cert/-tls-key it generates a self-signed certificate for
// 127.0.0.1 and localhost and writes it to -tls-cert-out, for the demo
// wallet (and your browser) to trust. Passports are verified against
// gmrtd's built-in ICAO CSCA master list.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	issuerURL := flag.String("issuer", "https://127.0.0.1:8443", "issuer URL")
	certFile := flag.String("tls-cert", "", "TLS certificate PEM (default: generate a self-signed one)")
	keyFile := flag.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	certOut := flag.String("tls-cert-out", "issuer-tls.pem", "where to write a generated TLS certificate for the wallet to trust")
	jwksPath := flag.String("wallet-provider-jwks", "wallet-provider.jwks.json", "the demo Wallet Provider's public JWK Set")
	providerIssuer := flag.String("wallet-provider-issuer", "https://wallet-provider.passport-vdc.demo", "the demo Wallet Provider's identifier (Wallet Attestation iss)")
	clientID := flag.String("wallet-client-id", "passport-vdc-wallet", "the demo wallet's client_id")
	redirectURI := flag.String("wallet-redirect-uri", "http://127.0.0.1:8765/callback", "the demo wallet's redirect URI")
	flag.Parse()

	jwks, err := os.ReadFile(*jwksPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		log.Fatalf("read wallet provider JWKS (run cmd/wallet-provider first): %v", err)
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		log.Fatalf("load CSCA master list: %v", err)
	}
	app, err := issuerapp.New(issuerapp.Config{
		IssuerURL: *issuerURL,
		CSCAPool:  pool,
		Wallet: issuerapp.WalletClient{
			ClientID: *clientID, RedirectURIs: []string{*redirectURI},
			ProviderIssuer: *providerIssuer, ProviderJWKS: jwks,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	cert, err := tlsCertificate(*certFile, *keyFile, *certOut)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr: *addr, Handler: app,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Printf("passport-vdc issuer on https://%s (issuer %s)", *addr, *issuerURL)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// tlsCertificate loads certFile/keyFile, or generates a self-signed
// loopback certificate and writes it to certOut.
func tlsCertificate(certFile, keyFile, certOut string) (tls.Certificate, error) {
	if certFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "passport-vdc demo issuer (TLS)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certOut, pemBytes, 0o600); err != nil { // #nosec G703 -- operator-supplied path
		return tls.Certificate{}, fmt.Errorf("write %s: %w", certOut, err)
	}
	log.Printf("generated a self-signed TLS certificate; wrote it to %s for the wallet to trust", certOut)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
