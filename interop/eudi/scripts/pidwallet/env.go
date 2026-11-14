package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// environment is what every engine shares: the run's trust anchors, an
// HTTP client trusting the run's TLS CA that records each exchange, and
// the Wallet Provider.
type environment struct {
	o   options
	rec *recorder
	// revocation checks every certificate the wallet verifies for
	// revocation (startCRL).
	revocation certrevocation.Checker
	// http makes every protocol request; statusHTTP fetches status
	// lists, through a plain *http.Transport, as statuslist.Fetcher
	// requires.
	http, statusHTTP *http.Client
	metadataRoots    *x509.CertPool
	issuerRoots      *x509.CertPool
	statusIssuer     string
	provider         *provider
	// encryptedRequest is set once a Credential Request went encrypted.
	encryptedRequest bool

	// production is -assurance production (production.go): stores are
	// the wallet's durable stores, and prodHTTP the core engine's client.
	production bool
	stores     *prodwallet.Stores
	prodHTTP   *http.Client
}

func newEnvironment(o options) (*environment, error) {
	tlsRoots, err := pool(filepath.Join(o.work, "tls-ca.pem"))
	if err != nil {
		return nil, err
	}
	env := &environment{o: o}
	newTransport := func() *http.Transport {
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: tlsRoots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
	}
	env.rec = &recorder{next: newTransport()}
	env.http = &http.Client{Transport: env.rec, Timeout: 30 * time.Second}
	env.statusHTTP = &http.Client{Transport: newTransport(), Timeout: 30 * time.Second}
	if env.metadataRoots, err = pool(filepath.Join(o.work, o.metadataRoots)); err != nil {
		return nil, err
	}
	if env.issuerRoots, err = pool(filepath.Join(o.work, o.issuerRoots)); err != nil {
		return nil, err
	}
	if env.statusIssuer, err = text(filepath.Join(o.work, "status-issuer.txt")); err != nil {
		return nil, err
	}
	p := &provider{walletStatusIdx: o.walletStatusIdx, keyStorageStatus: o.keyStorageStatusIdx, now: time.Now}
	if p.statusURI, err = text(filepath.Join(o.work, "wallet-provider-status-list.txt")); err != nil {
		return nil, err
	}
	if p.waKey, p.waCert, err = signer(o.work, "wallet-attestation"); err != nil {
		return nil, err
	}
	if p.kaKey, p.kaCert, err = signer(o.work, "key-attestation"); err != nil {
		return nil, err
	}
	env.provider = p
	if o.assurance == assuranceProduction {
		if err := env.startProduction(); err != nil {
			return nil, err
		}
	}
	return env, nil
}

// newWallet is the wallet package's Wallet, taking signed metadata
// only, verified under the metadata CA, its signer naming the issuer.
func (env *environment) newWallet() (*wallet.Wallet, error) {
	cfg := wallet.Config{
		// Development only for the stack's loopback address; nothing
		// below relaxes a check.
		Assurance:       wallet.AssuranceDevelopment,
		ProofSigningAlg: jose.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes:   2 << 20,
			RequestTimeout:     30 * time.Second,
			AllowLoopbackHosts: true,
		},
		IssuerMetadataRoots:         env.metadataRoots,
		IssuerMetadataRevocation:    env.revocation,
		RequireSignedIssuerMetadata: true,
		RequireIssuerMetadataName:   true,
	}
	if env.production {
		cfg.Assurance, cfg.Fetch.AllowLoopbackHosts = wallet.AssuranceProduction, false
		cfg.Fetch.AllowedPrivateHosts = env.o.allowedPrivateHosts
	}
	return wallet.New(cfg, wallet.Dependencies{HTTP: env.walletHTTP(), Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
}

// summarize reads what the exchanges show into res.
func (env *environment) summarize(res *result) {
	for _, e := range env.rec.recorded() {
		switch {
		case e.Method == http.MethodPost && strings.HasSuffix(e.Path, "/challenge") && e.Status == http.StatusOK:
			res.Challenges++
		case strings.HasPrefix(e.Path, "/.well-known/openid-credential-issuer/") && e.Status == http.StatusOK:
			res.SignedMetadata = strings.HasPrefix(e.ContentType, "application/jwt")
		case strings.HasSuffix(e.Path, "/credentialEndpoint") && (e.Status == http.StatusOK || e.Status == http.StatusAccepted):
			res.EncryptedResponse = strings.HasPrefix(e.ContentType, "application/jwt")
		}
		if e.DPoPNonce {
			res.DPoPNonces++
		}
		if e.Error == "use_dpop_nonce" {
			res.DPoPNonceRetries++
		}
	}
	res.EncryptedRequest = env.encryptedRequest
}

// pool reads the certificates in file.
func pool(file string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(file) // #nosec G304 -- the run's own -work
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no certificate", file)
	}
	return p, nil
}

// text reads a one-line file.
func text(file string) (string, error) {
	raw, err := os.ReadFile(file) // #nosec G304 -- the run's own -work
	return strings.TrimSpace(string(raw)), err
}

// signer reads pidsetup's NAME.key.pem and the leaf of NAME.chain.pem.
func signer(dir, name string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, name+".key.pem")) // #nosec G304 -- the run's own -work
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("%s.key.pem holds no key", name)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.key.pem: %w", name, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New(name + ".key.pem isn't an EC key")
	}
	chainPEM, err := os.ReadFile(filepath.Join(dir, name+".chain.pem")) // #nosec G304 -- the run's own -work
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(chainPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("%s.chain.pem holds no certificate", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.chain.pem: %w", name, err)
	}
	return key, cert, nil
}
