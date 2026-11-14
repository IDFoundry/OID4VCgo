package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// The engines Config.Engine names.
const (
	engineWallet     = "wallet"
	engineWalletflow = "walletflow"
)

// fixtureKeyID names the fixture credential's holder key in
// fixtureKeys, and fixtureCredentialID the credential in the store.
const (
	fixtureKeyID        = "holder"
	fixtureCredentialID = "fixture"
)

// fixtureKey is the fixture credential's holder key, as walletflow
// holds keys.
type fixtureKey struct{ crypto.Signer }

func (fixtureKey) ID() string { return fixtureKeyID }

// fixtureKeys is a walletflow.KeyStore holding the configured holder
// key alone: the fixture credential, issued at startup, is bound to it.
// Presenting creates no key.
type fixtureKeys struct{ key fixtureKey }

func (k fixtureKeys) NewKey(context.Context, walletflow.KeyPurpose) (walletflow.Key, error) {
	return nil, errors.New("conformance-wallet-vp: the walletflow engine holds the configured holder key only")
}

func (k fixtureKeys) Key(_ context.Context, id string) (walletflow.Key, error) {
	if id != fixtureKeyID {
		return nil, fmt.Errorf("key %q: %w", id, walletflow.ErrNotFound)
	}
	return k.key, nil
}

func (fixtureKeys) DeleteKey(context.Context, string) error { return nil }

// newFlow is the walletflow engine's Wallet: holding cred, the fixture
// credential, bound to its configured holder key, trusting Verifiers
// as trust does, calling them through client. Development, for the
// interop runs' Verifiers on this machine: it lets them be on loopback
// addresses, and client is this binary's own (its TLS verified against
// verifier_tls_trust_anchors_pem), not walletflow's hardened one. Under
// Config.Assurance "production", neither.
func newFlow(cfg Config, cred wallet.HeldCredential, trust wallet.VerifierTrust, client *http.Client) (*walletflow.Wallet, error) {
	store := walletflow.NewMemoryCredentialStore()
	stored := walletflow.StoredCredential{ // #nosec G101 -- the fixture credential issued at startup, not a secret
		ID: fixtureCredentialID, CredentialIssuer: "https://conformance-wallet-vp.invalid", ConfigurationID: fixtureCredentialID,
		Format: cred.Format, VCT: cfg.VCT, DocType: cred.MdocDocType, Credential: cred.Credential,
		HolderKeyID: fixtureKeyID, ReceivedAt: time.Now(),
	}
	if cfg.isMdoc() {
		stored.VCT = ""
	}
	if err := store.Put(context.Background(), stored); err != nil {
		return nil, err
	}
	deps := walletflow.Dependencies{Keys: fixtureKeys{key: fixtureKey{cred.HolderKey}}, Credentials: store, HTTP: client}
	if cfg.production() {
		// Config.Assurance "production": walletflow's own client, as a
		// wallet app has it. Presenting a held credential needs none of
		// production's durable stores.
		deps.HTTP = nil
	}
	return walletflow.New(walletflow.Config{
		Development: !cfg.production(), VerifierTrust: trust, AcceptX509SANDNS: cfg.AcceptX509SANDNS,
		AllowedPrivateHosts: cfg.AllowedPrivateHosts,
	}, deps)
}

// handleAuthorizeWalletflow is handleAuthorize for the walletflow
// engine: the request link goes to walletflow.Wallet.StartPresentation,
// which fetches (by GET, or by POST with walletflow's own
// wallet_metadata) and verifies the Request Object; the default
// selection is presented with Presentation.Respond, and the Verifier's
// redirect_uri followed as a browser would. A request walletflow
// refuses after verifying it, it answers with an error response
// itself, as a wallet app's would.
func (s *server) handleAuthorizeWalletflow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pres, err := s.flow.StartPresentation(ctx, r.URL.String())
	if err != nil {
		log.Printf("walletflow: start presentation: %v", err)
		var refused *walletflow.RequestRefusedError
		if errors.As(err, &refused) {
			s.respondFollowingRedirect(w, "Rejected", fmt.Sprintf("<p>Sent error response: %s: %s</p>", refused.Code, refused.Description), refused.RedirectURI)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sel, err := pres.DefaultSelection(ctx)
	if err != nil {
		log.Printf("walletflow: default selection: %v", err)
		declined, declineErr := pres.Decline(ctx)
		if declineErr != nil {
			http.Error(w, fmt.Sprintf("%v; decline: %v", err, declineErr), http.StatusBadGateway)
			return
		}
		s.respondFollowingRedirect(w, "Rejected", fmt.Sprintf("<p>Declined: %v</p>", err), declined.RedirectURI)
		return
	}
	presented, err := pres.Respond(ctx, sel)
	if err != nil {
		log.Printf("walletflow: respond: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	lead := fmt.Sprintf("<p>walletflow answered %s.</p>", strings.Join(presented.QueryIDs, ", "))
	if presented.RedirectURI == "" {
		lead += "<p>No redirect_uri was returned.</p>"
	}
	s.respondFollowingRedirect(w, "Presented", lead, presented.RedirectURI)
}
