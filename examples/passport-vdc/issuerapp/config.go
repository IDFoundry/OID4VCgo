// Package issuerapp is the passport-vdc demo's Credential Issuer: a
// fapigo/server Authorization Server (FAPI 2.0, Wallet Attestation
// client authentication, DPoP) paired with an oid4vcgo/issuer Issuer,
// serving a passport upload page and issuing each verified passport as
// both mso_mdoc and dc+sd-jwt.
//
// # Linking a credential to its passport
//
// Uploading a passport creates a transaction T holding the verified
// passport.Evidence, and a Credential Offer carrying T as its
// issuer_state. The Wallet echoes issuer_state in its Pushed
// Authorization Request; this app records request_uri → T when PAR
// succeeds (fapigo/server doesn't surface extension values later — see
// the library's issuer/authorization_server.go), shows the approval
// page for T's passport, and authorizes with subject T. The access
// token's sub is therefore T, which the Credential Endpoint reads back
// to find the Evidence to encode.
//
// In this demo issuer_state is a bearer secret: whoever scans the offer
// can redeem it until the transaction expires. A production issuer
// would authenticate the holder at the approval step.
package issuerapp

import (
	"fmt"
	"time"

	"github.com/gmrtd/gmrtd/cms"
)

// Config configures an App.
type Config struct {
	// IssuerURL is this issuer's identifier and the base of every
	// endpoint, e.g. "http://127.0.0.1:8080" for local development
	// (loopback http is accepted; anything else must be https).
	IssuerURL string

	// CSCAPool verifies uploaded passports — cms.DefaultMasterList for
	// real passports.
	CSCAPool cms.CertPool

	// Wallet is the one Wallet client this demo registers.
	Wallet WalletClient

	// TransactionLifetime bounds how long a verified passport stays
	// redeemable; zero means 10 minutes.
	TransactionLifetime time.Duration
}

// WalletClient registers the demo Wallet: a client authenticated by
// Wallet Attestation from one custom Wallet Provider key (a demo
// stand-in for a real platform-backed Wallet Provider).
type WalletClient struct {
	// ClientID is the Wallet's client_id — the "sub" of its Wallet
	// Attestation.
	ClientID string

	// RedirectURIs are the Wallet's registered redirect URIs (loopback
	// http is accepted outside production).
	RedirectURIs []string

	// ProviderIssuer is the Wallet Provider's identifier — the "iss" of
	// the Wallet Attestations this issuer accepts.
	ProviderIssuer string

	// ProviderJWKS is the Wallet Provider's public JWK Set, used to
	// verify Wallet Attestations.
	ProviderJWKS []byte
}

func (c Config) transactionLifetime() time.Duration {
	if c.TransactionLifetime == 0 {
		return 10 * time.Minute
	}
	return c.TransactionLifetime
}

func (c Config) validate() error {
	switch {
	case c.IssuerURL == "":
		return fmt.Errorf("issuerapp: IssuerURL is required")
	case c.CSCAPool == nil:
		return fmt.Errorf("issuerapp: CSCAPool is required")
	case c.Wallet.ClientID == "":
		return fmt.Errorf("issuerapp: Wallet.ClientID is required")
	case len(c.Wallet.RedirectURIs) == 0:
		return fmt.Errorf("issuerapp: Wallet.RedirectURIs is required")
	case c.Wallet.ProviderIssuer == "":
		return fmt.Errorf("issuerapp: Wallet.ProviderIssuer is required")
	case len(c.Wallet.ProviderJWKS) == 0:
		return fmt.Errorf("issuerapp: Wallet.ProviderJWKS is required")
	}
	return nil
}
