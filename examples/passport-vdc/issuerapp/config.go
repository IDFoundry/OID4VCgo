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
// Authorization Request; fapigo/server hands it back at the
// interaction step, where this app shows the approval page for T's
// passport and authorizes with subject T. The access
// token's sub is therefore T, which the Credential Endpoint reads back
// to find the Evidence to encode.
//
// An offer is redeemed once, by one wallet: the approval page asks for
// the six-digit confirmation code shown with the offer, and the first
// approval with the right code claims the transaction, so no other
// authorization can reach it. That authorization's DPoP-bound access
// token can fetch each offered credential once; the transaction, and
// its passport data, is dropped once all are issued. Five wrong codes
// void it. The holder still isn't authenticated — whoever sees the
// offer page can redeem it first; a production issuer would
// authenticate the holder at the approval step.
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

	// MaxTransactions caps how many verified passports are held at once,
	// since uploading is unauthenticated; zero means 100.
	MaxTransactions int

	// WebWalletURL, if set, adds an "Open in web wallet" button to the
	// offer page, linking to the demo web wallet's /receive.
	WebWalletURL string

	// AllowSampleDocument adds a button to the upload page that issues
	// passport.SampleDocument without checking it, simulating an issuer
	// that skipped Passive Authentication: its credentials look like any
	// passport's, and only a verifier that re-verifies the passport file
	// finds out. The issuer's own pages mark them. For the demo only:
	// never on a deployment anyone else relies on.
	AllowSampleDocument bool

	// StateDir, if set, is an existing directory this issuer keeps its
	// CA and signing keys and its status list in, so credentials it
	// issued keep verifying, and revocations hold, across restarts.
	// Empty keeps everything in memory: a restart starts over.
	StateDir string
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

	// ProviderCA is the Wallet Provider CA certificate (PEM), the trust
	// anchor for both of the provider's attestations, each verified by
	// its x5c certificate chain:
	//   - Wallet Attestations, which authenticate the wallet at PAR and
	//     the token endpoint (HAIP 1.0 §4.4.1; fapigo/server's
	//     X5CAttesterChain), from a certificate naming ProviderIssuer as
	//     a URI SAN, with this CA bound to ProviderIssuer alone
	//     (AttesterIssuerBoundToAnchor);
	//   - Key Attestations, which every credential request must prove
	//     its holder key with (the attestation proof type, OID4VCI 1.0
	//     Appendix F.3).
	ProviderCA []byte
}

func (c Config) transactionLifetime() time.Duration {
	if c.TransactionLifetime == 0 {
		return 10 * time.Minute
	}
	return c.TransactionLifetime
}

func (c Config) maxTransactions() int {
	if c.MaxTransactions == 0 {
		return 100
	}
	return c.MaxTransactions
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
	case len(c.Wallet.ProviderCA) == 0:
		return fmt.Errorf("issuerapp: Wallet.ProviderCA is required")
	}
	return nil
}
