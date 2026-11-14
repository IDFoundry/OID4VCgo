package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// The common names setup gives Issuer2's certificates (its SD-JWT VC
// signer, "walt.id Issuer2", and its document signer, "walt.id Issuer2
// document signer") and Verifier2's Access Certificate.
const (
	issuer2Name   = "walt.id Issuer2"
	verifier2Name = "walt.id Verifier2"
)

// assurance applies opts.assurance to cfg and deps: production's setup
// under "production", with its stores to close; nothing otherwise
// (stores nil, whose Close does nothing). What the wallet's recording
// transport saw then stays empty: walletflow's own client takes no
// wrapping.
func assurance(opts options, cfg *walletflow.Config, deps *walletflow.Dependencies, revocation certrevocation.Checker) (*prodwallet.Stores, error) {
	if opts.assurance != "production" {
		return nil, nil
	}
	return production(cfg, deps, opts, revocation)
}

// production sets cfg and deps up as a deployment runs walletflow
// (-assurance production): Development off, so walletflow builds its
// own HTTP client (Dependencies.HTTP nil), which dials public addresses
// only, and the private ones of -allowed-private-host's hosts, follows
// no redirect and verifies TLS against the system roots;
// the durable stores in store (internal/prodwallet), which receiving
// credentials requires; StatusRevocation, the status list signers'
// revocation check, which production requires besides
// IssuerRevocation; and leaf policies telling Issuer2's certificates
// from Verifier2's, which production requires of two roles whose roots
// share an anchor, as the run's one CA is for both.
//
// The policies stand in for the role marker an ecosystem's PKI puts in
// its certificates (an extended key usage, a certificate policy):
// setup's CA marks none, so they go by the subject's common name, which
// only that CA, trusted for nothing else, issues.
func production(cfg *walletflow.Config, deps *walletflow.Dependencies, opts options, revocation certrevocation.Checker) (*prodwallet.Stores, error) {
	if revocation == nil {
		return nil, errors.New("-assurance production checks revocation: -crl-set none is development's")
	}
	stores, err := prodwallet.Open(opts.store)
	if err != nil {
		return nil, fmt.Errorf("-store: %w", err)
	}
	cfg.Development, cfg.AllowedPrivateHosts = false, opts.allowedPrivateHosts
	cfg.StatusRevocation = revocation
	cfg.IssuerLeafPolicy = commonNamePolicy(issuer2Name, true)
	roots, ok := cfg.VerifierTrust.(wallet.X5CVerifierRoots)
	if !ok {
		_ = stores.Close()
		return nil, errors.New("-assurance production: the Verifier trust isn't X5CVerifierRoots")
	}
	roots.LeafPolicy = commonNamePolicy(verifier2Name, false)
	cfg.VerifierTrust = roots
	*deps = stores.Dependencies(walletflow.Dependencies{Provider: deps.Provider})
	return stores, nil
}

// commonNamePolicy accepts a leaf whose common name is name, or, with
// prefix, starts with it.
func commonNamePolicy(name string, prefix bool) func(*x509.Certificate, [][]*x509.Certificate) error {
	return func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		cn := leaf.Subject.CommonName
		if cn == name || (prefix && strings.HasPrefix(cn, name)) {
			return nil
		}
		return fmt.Errorf("certificate %q isn't %q's", cn, name)
	}
}
