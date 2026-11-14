package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

// DefaultIdentifier is the provider's identifier when -identifier
// isn't set: every attestation's iss, and its signing certificate's
// URI subject alternative name.
const DefaultIdentifier = "https://wallet-provider.oid4vcgo-interop.example"

// statusListsPath is where the provider's status lists are served,
// under -base-url.
const statusListsPath = "/statuslists"

// stores are the provider's stores, all in one database.
type stores struct {
	instances    walletprovider.InstanceStore
	instanceKeys walletprovider.InstanceKeyStore
	challenges   walletprovider.ChallengeStore
	indices      statuslist.IndexStore
	tokens       statuslist.TokenStore
}

// runProvider is the provider's command line.
func runProvider(args []string) error {
	fs := flag.NewFlagSet("walletprovider", flag.ContinueOnError)
	dir := fs.String("dir", "", "the directory it writes ca.pem, tls-cert.pem and its database to (required)")
	addr := fs.String("addr", "127.0.0.1:0", "the HTTPS listener's address")
	baseURL := fs.String("base-url", "", "its HTTPS base URL, where wallets and issuers reach it (required)")
	identifier := fs.String("identifier", DefaultIdentifier, "its identifier: every attestation's iss")
	clientIDs := fs.String("client-id", "", "the OAuth client IDs it attests, comma-separated (required)")
	hosts := fs.String("hosts", "localhost", "the DNS names its TLS certificate names, comma-separated")
	admin := fs.String("admin", "", "the admin listener's loopback address (required)")
	caName := fs.String("ca-name", "OID4VCgo interop Wallet Provider CA", "its CA's common name")
	statusTTL := fs.Duration("status-list-ttl", walletprovider.DefaultStatusListTTL, "its status lists' ttl: how long an issuer may cache one, and so how soon a revocation reaches it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *baseURL == "" || *clientIDs == "" || *admin == "" {
		return errors.New("-dir, -base-url, -client-id and -admin are required")
	}
	if err := loopback("admin", *admin); err != nil {
		return err
	}
	p, tlsCert, err := newProvider(*dir, *baseURL, *identifier, *caName, strings.Split(*clientIDs, ","), strings.Split(*hosts, ","), *statusTTL)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(statusListsPath+"/", http.StripPrefix(statusListsPath, p.StatusLists()))
	mux.Handle("/", p.Handler())
	srv := &http.Server{
		Addr: *addr, Handler: logRequests(mux), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
	}
	adminSrv := &http.Server{Addr: *admin, Handler: adminHandler(p), ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 2)
	go func() { errs <- srv.ListenAndServeTLS("", "") }()
	go func() { errs <- adminSrv.ListenAndServe() }()
	log.Printf("wallet provider %s serving on https %s (%s), admin on http %s", *identifier, *addr, *baseURL, *admin)
	return <-errs
}

// newProvider makes the run's CA, the attestation signer's certificate
// under it (naming identifier) and a TLS certificate for hosts, writes
// the CA and the TLS certificate to dir, and builds the provider over
// the stores openStores opens there.
func newProvider(dir, baseURL, identifier, caName string, clientIDs, hosts []string, statusTTL time.Duration) (*walletprovider.Provider, tls.Certificate, error) {
	id, err := url.Parse(identifier)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("-identifier: %w", err)
	}
	ca, caKey, caPEM, _, err := conformancecert.GenerateCA(caName)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leafPEM, err := conformancecert.IssueLeafCertPEM("OID4VCgo interop Wallet Provider", signer, ca, caKey, id)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leaf, err := conformancecert.ParseCertificatePEM(leafPEM)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM(hosts[0], hosts)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	tlsCert, err := tls.X509KeyPair([]byte(tlsCertPEM), []byte(tlsKeyPEM))
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	for name, content := range map[string]string{"ca.pem": caPEM, "tls-cert.pem": tlsCertPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return nil, tls.Certificate{}, err
		}
	}
	s, err := openStores(filepath.Join(dir, "wallet-provider.db"))
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	p, err := walletprovider.New(providerConfig(identifier, strings.TrimSuffix(baseURL, "/")+statusListsPath, clientIDs, statusTTL), walletprovider.Dependencies{
		Signer: signer, Chain: []*x509.Certificate{leaf},
		Instances: s.instances, InstanceKeys: s.instanceKeys, Challenges: s.challenges,
		StatusIndices: s.indices, StatusListTokens: s.tokens,
		Evidence: []walletprovider.EvidenceVerifier{evidenceVerifier()},
		Random:   rand.Reader,
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	return p, tlsCert, err
}

// providerConfig is the provider's configuration: the defaults a
// deployment starts from (status list periods, sizes, lifetimes and
// retention) but for the status lists' ttl, its records sealed.
func providerConfig(identifier, statusListBaseURI string, clientIDs []string, statusTTL time.Duration) walletprovider.Config {
	return walletprovider.Config{
		Identifier: identifier, ClientIDs: clientIDs,
		WalletName: "OID4VCgo interop wallet", WalletLink: identifier,
		StatusListBaseURI:  statusListBaseURI,
		StatusListTTL:      statusTTL,
		Policy:             policy(),
		RequireSealedStore: true,
	}
}

// evidenceVerifier is the stand-in for a device's platform evidence:
// it vouches for the keys FakeEvidence names, made in a TEE.
func evidenceVerifier() walletprovidertest.FakeVerifier {
	return walletprovidertest.FakeVerifier{SecurityLevel: walletprovider.SecurityLevelTEE}
}

// policy accepts FakeVerifier's platform at TEE level and claims a
// TEE key's storage as iso_18045_moderate, as a policy claims an
// Android TEE key's.
func policy() walletprovider.Policy {
	return walletprovider.Policy{
		Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{
			walletprovidertest.FakePlatform: {SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelTEE}},
		},
		KeyStorage: []walletprovider.KeyStorageRule{{
			Platform: walletprovidertest.FakePlatform, SecurityLevel: walletprovider.SecurityLevelTEE,
			KeyStorage: []attestation.AttackPotentialResistance{attestation.ISO18045Moderate},
		}},
	}
}

// adminHandler serves the admin listener: POST /revoke revokes every
// registered instance.
func adminHandler(p *walletprovider.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ready") })
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		defer cancel()
		n, err := p.RevokeWhere(ctx, func(walletprovider.Instance) bool { return true }, "interop control")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("admin: revoked %d instances", n)
		_, _ = fmt.Fprintf(w, "%d\n", n)
	})
	return mux
}

// logRequests logs each request's method, endpoint and status, so a
// run can show what the wallet asked for and who fetched the status
// lists. Only a method and an endpoint the provider serves are named:
// the sender chose the rest of the request.
func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		method := "another method"
		switch r.Method {
		case http.MethodGet:
			method = http.MethodGet
		case http.MethodPost:
			method = http.MethodPost
		}
		log.Printf("served %s %q %d", method, endpoint(r.URL.Path), rec.status)
	})
}

// endpoint names the endpoint path is: one of the protocol's, the
// status lists (statusListsPath + "/{start}/{n}"), or another path.
func endpoint(path string) string {
	for _, p := range []string{
		walletprovider.ChallengePath, walletprovider.InstancesPath, walletprovider.WalletAttestationPath,
		walletprovider.KeyAttestationPath, walletprovider.StatusPath,
	} {
		if path == p {
			return p
		}
	}
	if strings.HasPrefix(path, statusListsPath+"/") {
		return statusListsPath + "/{start}/{n}"
	}
	return "another path"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
