// Command vpholder is OID4VCgo's wallet for the issued-credential cases
// of interop/eudi/run-verifier.sh: walletflow over sqlstore's sealed
// stores (internal/prodwallet), holding credentials OID4VCgo's issuer
// issued it, and presenting them to the EUDI Verifier Endpoint. Each
// step is a process of its own over the one store directory, as a
// wallet app's launches are:
//
//	vpholder receive -store DIR -offer URL -wallet-provider URL -wallet-provider-tls FILE ...
//
// redeems the issuer's pre-authorized code offer (cmd/conformance-issuer
// in its production setup), attested by OID4VCgo's Wallet Provider
// (interop/walletprovider, over interop/internal/interopwp), and stores
// what it issued, checked as walletflow checks it: its issuer's chain
// to -issuer-ca or -iaca and the issuer's certificates against their
// CAs' CRLs; and, once stored, its status (Wallet.CheckStatus), its
// list's signer's certificate checked against its CA's CRL too, unless
// -check-status=false.
//
//	vpholder present -store DIR -request URL ...
//
// answers a Verifier's request (an openid4vp: link) from the store,
// with walletflow's default selection, trusting Verifiers whose Access
// Certificate chains to -verifier-ca and isn't revoked by its CA's CRL.
//
// The CRLs are the run's own: this process publishes them over https on
// loopback (-crl-publisher, a conformancecrl.Publisher) and fetches them
// back from the distribution points the certificates name (-crl-trust,
// a conformancecrl.Trust), as interop/eudi/scripts/setup wrote them.
//
// -assurance development (the default) runs walletflow's Development
// over this process's own HTTP client, its TLS roots -tls-ca;
// -assurance production runs it as a wallet
// app runs it (walletflow's own client, which dials public addresses
// only, and the private ones of the hosts -allowed-private-host names,
// the system's TLS roots), for run-verifier.sh's production run,
// which runs it in a container on interop/prodnet.sh's network. The
// stores are sqlstore's in both.
//
// The result, written to -out as JSON, says how far the step got and
// what it saw: run-verifier.sh decides whether that's what the case
// expects.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
	"github.com/idfoundry/oid4vcgo/interop/internal/interopwp"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// The -assurance levels.
const (
	assuranceDevelopment = "development"
	assuranceProduction  = "production"
)

// stepTimeout bounds a step.
const stepTimeout = 2 * time.Minute

// options are the flags.
type options struct {
	command, store, assurance, out string
	tlsCA                          string
	issuerCA, iaca, verifierCA     string
	crlPublisher, crlTrust         string
	clientID                       string
	// allowedPrivateHosts are the hosts production's client may reach
	// at a private address (walletflow.Config.AllowedPrivateHosts).
	allowedPrivateHosts []string
	// receive's.
	offer, walletProvider, walletProviderTLS string
	checkStatus                              bool
	// present's.
	request string
}

// result is what a step saw: Stage is the last step reached ("done"
// when every step succeeded), Error why the next failed.
type result struct {
	Command   string     `json:"command"`
	Assurance string     `json:"assurance"`
	Stage     string     `json:"stage"`
	Error     string     `json:"error,omitempty"`
	Received  []received `json:"received,omitempty"`
	// Held is what the store held when present began.
	Held        []held   `json:"held,omitempty"`
	QueryIDs    []string `json:"query_ids,omitempty"`
	RedirectURI string   `json:"redirect_uri,omitempty"`
}

// received is a credential receive stored.
type received struct {
	ID              string `json:"id"`
	Format          string `json:"format"`
	ConfigurationID string `json:"configuration_id"`
	Copies          int    `json:"copies"`
	// Status is its status as the wallet checked it once stored
	// (Wallet.CheckStatus), and StatusReason why.
	Status       string `json:"status"`
	StatusReason string `json:"status_reason,omitempty"`
	// StatusLists are its copies' status list entries.
	StatusLists []statusEntry `json:"status_lists"`
}

type statusEntry struct {
	URI string `json:"uri"`
	Idx uint64 `json:"idx"`
}

// held is a credential in the store.
type held struct {
	ID               string    `json:"id"`
	Format           string    `json:"format"`
	CredentialIssuer string    `json:"credential_issuer"`
	ReceivedAt       time.Time `json:"received_at"`
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "receive" && os.Args[1] != "present") {
		log.Fatal("usage: vpholder receive|present [flags]")
	}
	o := options{command: os.Args[1]}
	fs := flag.NewFlagSet("vpholder "+o.command, flag.ExitOnError)
	fs.StringVar(&o.store, "store", "", "the directory of the wallet's sqlstore stores (required)")
	fs.StringVar(&o.assurance, "assurance", assuranceDevelopment, "development, or production: walletflow as a wallet app runs it")
	fs.StringVar(&o.out, "out", "", "where to write the result (required)")
	fs.StringVar(&o.tlsCA, "tls-ca", "", "development: the certificates the parties' TLS certificates chain to")
	fs.StringVar(&o.issuerCA, "issuer-ca", "", "the CA SD-JWT VC issuers chain to (required)")
	fs.StringVar(&o.iaca, "iaca", "", "the IACA mdocs chain to (required)")
	fs.StringVar(&o.verifierCA, "verifier-ca", "", "the CA Verifiers' Access Certificates chain to (required)")
	fs.StringVar(&o.crlPublisher, "crl-publisher", "", "the CRLs to publish, a conformancecrl.Publisher's JSON (required)")
	fs.StringVar(&o.crlTrust, "crl-trust", "", "the CRL distribution points to check against, a conformancecrl.Trust's JSON (required)")
	fs.StringVar(&o.clientID, "client-id", "", "the client_id the Wallet Provider attests the wallet as (required)")
	fs.Func("allowed-private-host", "production: a host the wallet may reach at a private address (repeatable)", func(host string) error {
		o.allowedPrivateHosts = append(o.allowedPrivateHosts, host)
		return nil
	})
	fs.StringVar(&o.offer, "offer", "", "receive: the issuer's credential offer")
	fs.StringVar(&o.walletProvider, "wallet-provider", "", "receive: the Wallet Provider's base URL")
	fs.StringVar(&o.walletProviderTLS, "wallet-provider-tls", "", "receive: the Wallet Provider's TLS certificate, PEM")
	fs.BoolVar(&o.checkStatus, "check-status", true, "receive: check each credential's status once stored (Wallet.CheckStatus)")
	fs.StringVar(&o.request, "request", "", "present: the Verifier's request")
	_ = fs.Parse(os.Args[2:])
	if err := o.check(); err != nil {
		log.Fatal(err)
	}
	res := run(o)
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(o.out, raw, 0o600); err != nil {
		log.Fatal(err)
	}
}

// check refuses flags that don't make a step.
func (o options) check() error {
	if o.store == "" || o.out == "" || o.issuerCA == "" || o.iaca == "" || o.verifierCA == "" ||
		o.crlPublisher == "" || o.crlTrust == "" || o.clientID == "" {
		return errors.New("-store, -out, -issuer-ca, -iaca, -verifier-ca, -crl-publisher, -crl-trust and -client-id are required")
	}
	switch o.assurance {
	case assuranceDevelopment:
		if o.tlsCA == "" {
			return errors.New("-assurance development needs -tls-ca")
		}
		if len(o.allowedPrivateHosts) > 0 {
			return errors.New("-allowed-private-host is production's: Development's client is this process's own")
		}
	case assuranceProduction:
		if o.tlsCA != "" {
			return errors.New("-assurance production takes no -tls-ca: its client is walletflow's own, its roots the system's")
		}
	default:
		return fmt.Errorf("-assurance is development or production, not %q", o.assurance)
	}
	if o.command == "receive" && (o.offer == "" || o.walletProvider == "" || o.walletProviderTLS == "") {
		return errors.New("receive needs -offer, -wallet-provider and -wallet-provider-tls")
	}
	if o.command == "present" && o.request == "" {
		return errors.New("present needs -request")
	}
	return nil
}

func run(o options) (res result) {
	res = result{Command: o.command, Assurance: o.assurance, Stage: "setup"}
	fail := func(err error) result {
		res.Error = err.Error()
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	revocation, err := conformancecrl.StartFiles(ctx, o.crlPublisher, o.crlTrust, log.Printf)
	if err != nil {
		return fail(fmt.Errorf("crl: %w", err))
	}
	stores, err := prodwallet.Open(o.store)
	if err != nil {
		return fail(fmt.Errorf("-store: %w", err))
	}
	defer func() { _ = stores.Close() }()
	var provider walletflow.WalletProvider
	if o.command == "receive" {
		res.Stage = "wallet provider"
		if provider, err = registerAtProvider(ctx, o.walletProvider, o.walletProviderTLS); err != nil {
			return fail(err)
		}
	}
	w, err := newWallet(o, stores, provider, revocation)
	if err != nil {
		return fail(err)
	}
	if o.command == "receive" {
		if err := receive(ctx, w, o.offer, o.checkStatus, &res); err != nil {
			return fail(err)
		}
	} else if err := present(ctx, w, stores.Credentials, o.request, &res); err != nil {
		return fail(err)
	}
	res.Stage = "done"
	return res
}

// newWallet is walletflow over stores: at production assurance with
// walletflow's own client, or in Development over this process's.
func newWallet(o options, stores *prodwallet.Stores, provider walletflow.WalletProvider, revocation certrevocation.Checker) (*walletflow.Wallet, error) {
	issuerRoots, err := pool(o.issuerCA)
	if err != nil {
		return nil, err
	}
	iaca, err := pool(o.iaca)
	if err != nil {
		return nil, err
	}
	verifierRoots, err := pool(o.verifierCA)
	if err != nil {
		return nil, err
	}
	cfg := walletflow.Config{
		ClientID:    o.clientID,
		IssuerRoots: issuerRoots, MdocIssuerRoots: iaca,
		IssuerRevocation: revocation, StatusRevocation: revocation,
		VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots, Revocation: revocation},
		Development:   o.assurance == assuranceDevelopment,
	}
	if !cfg.Development {
		cfg.AllowedPrivateHosts = o.allowedPrivateHosts
	}
	deps := walletflow.Dependencies{Provider: provider}
	if cfg.Development {
		if deps.HTTP, err = developmentClient(o.tlsCA); err != nil {
			return nil, err
		}
	}
	return walletflow.New(cfg, stores.Dependencies(deps))
}

// developmentClient is the Development wallet's HTTP client: TLS
// verified against tlsCA, following no redirect.
func developmentClient(tlsCA string) (*http.Client, error) {
	roots, err := pool(tlsCA)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		// A wallet follows no redirect of an issuer's or a Verifier's.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, nil
}

// receive redeems offer's pre-authorized code and records what was
// stored.
func receive(ctx context.Context, w *walletflow.Wallet, offer string, checkStatus bool, res *result) error {
	res.Stage = "offer"
	s, err := w.StartIssuance(ctx, offer)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close(ctx) }()
	res.Stage = "token"
	if err := s.RedeemPreAuthorizedCode(ctx, ""); err != nil {
		return err
	}
	res.Stage = "credential"
	got, err := s.RequestCredentials(ctx)
	if err != nil {
		return err
	}
	if len(got.Failed) > 0 {
		return fmt.Errorf("credential %s refused: %w", got.Failed[0].ConfigurationID, got.Failed[0].Err)
	}
	if len(got.Credentials) == 0 {
		return errors.New("no credential issued")
	}
	for _, c := range got.Credentials {
		r := received{ID: c.ID, Format: c.Format, ConfigurationID: c.ConfigurationID, Copies: len(c.AllCopies())}
		for _, cp := range c.AllCopies() {
			ref := cp.StatusList
			if ref == nil {
				ref = c.StatusList
			}
			if ref == nil {
				return fmt.Errorf("credential %s carries no status list entry", c.ConfigurationID)
			}
			r.StatusLists = append(r.StatusLists, statusEntry{URI: ref.URI, Idx: ref.Idx})
		}
		// As a wallet app shows a credential it received: its signer's
		// chain checked again, and its status read from the issuer's
		// list, whose signer's certificate is checked against its CA's
		// CRL.
		if !checkStatus {
			r.Status = "unchecked"
			res.Received = append(res.Received, r)
			continue
		}
		res.Stage = "status"
		checked, err := w.CheckStatus(ctx, c.ID)
		if err != nil {
			return err
		}
		r.Status, r.StatusReason = checked.Status.Value, checked.Status.Reason
		res.Received = append(res.Received, r)
	}
	return nil
}

// present answers request from what store holds.
func present(ctx context.Context, w *walletflow.Wallet, store walletflow.CredentialStore, request string, res *result) error {
	res.Stage = "store"
	creds, err := store.List(ctx)
	if err != nil {
		return err
	}
	for _, c := range creds {
		res.Held = append(res.Held, held{ID: c.ID, Format: c.Format, CredentialIssuer: c.CredentialIssuer, ReceivedAt: c.ReceivedAt})
	}
	slices.SortFunc(res.Held, func(a, b held) int { return a.ReceivedAt.Compare(b.ReceivedAt) })
	res.Stage = "request"
	p, err := w.StartPresentation(ctx, request)
	if err != nil {
		return err
	}
	res.Stage = "selection"
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		return err
	}
	res.Stage = "response"
	presented, err := p.Respond(ctx, sel)
	if err != nil {
		return err
	}
	res.QueryIDs, res.RedirectURI = presented.QueryIDs, presented.RedirectURI
	return nil
}

// registerAtProvider registers the wallet as an instance of OID4VCgo's
// Wallet Provider at baseURL, whose TLS certificate is the PEM file
// tlsCert (interop/internal/interopwp).
func registerAtProvider(ctx context.Context, baseURL, tlsCert string) (*interopwp.Provider, error) {
	roots, err := pool(tlsCert)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}
	return interopwp.Register(ctx, baseURL, hc)
}

// pool is a PEM file's certificates.
func pool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own file
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return p, nil
}
