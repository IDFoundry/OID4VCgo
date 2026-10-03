package mobile

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// config is NewWallet's JSON configuration.
type config struct {
	// ClientID and RedirectURI: the wallet's registration with
	// Authorization Servers.
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	// IssuerRoots and VerifierRoots are PEM certificates: the trust
	// anchors for issuers' credentials and Verifiers' requests.
	IssuerRoots   string `json:"issuer_roots"`
	VerifierRoots string `json:"verifier_roots"`
	// Development allows services on loopback addresses.
	Development bool `json:"development"`
}

// testHTTP, when set (by the mobiletest build), is the HTTP client every
// Wallet made afterwards uses: one trusting the in-process test issuer's
// certificate.
var testHTTP atomic.Pointer[http.Client]

// Wallet is a holder's wallet: walletflow over the app's KeyStore,
// CredentialStore and WalletProvider.
type Wallet struct {
	w    *walletflow.Wallet
	keys KeyStore
}

// NewWallet returns a Wallet configured by configJSON:
//
//	{"client_id": "…", "redirect_uri": "…",
//	 "issuer_roots": "<PEM>", "verifier_roots": "<PEM>",
//	 "development": false}
//
// issuer_roots is needed to receive credentials, and verifier_roots to
// present them.
func NewWallet(configJSON string, keys KeyStore, credentials CredentialStore, provider WalletProvider) (*Wallet, error) {
	var cfg config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("configuration: %w", err))
	}
	if keys == nil || credentials == nil {
		return nil, newError(CodeInvalidInput, errors.New("a KeyStore and a CredentialStore are required"))
	}
	wcfg := walletflow.Config{ClientID: cfg.ClientID, RedirectURI: cfg.RedirectURI, Development: cfg.Development}
	var err error
	if cfg.IssuerRoots != "" {
		if wcfg.IssuerRoots, err = certPool(cfg.IssuerRoots); err != nil {
			return nil, newError(CodeInvalidInput, fmt.Errorf("issuer_roots: %w", err))
		}
	}
	if cfg.VerifierRoots != "" {
		roots, err := certPool(cfg.VerifierRoots)
		if err != nil {
			return nil, newError(CodeInvalidInput, fmt.Errorf("verifier_roots: %w", err))
		}
		wcfg.VerifierTrust = wallet.X5CVerifierRoots{Roots: roots}
	}
	deps := walletflow.Dependencies{
		Keys: keyStore{keys}, Credentials: credentialStore{credentials}, Random: randReader{},
		HTTP: testHTTP.Load(), // nil: walletflow's own client
	}
	if provider != nil {
		deps.Provider = walletProvider{provider}
	}
	w, err := walletflow.New(wcfg, deps)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &Wallet{w: w, keys: keys}, nil
}

func certPool(pemText string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return nil, errors.New("no PEM certificates")
	}
	return pool, nil
}

// Credentials returns {"abi", "credentials": [{"id",
// "credential_issuer", "configuration_id", "format", "vct", "doctype",
// "received_at", "holder_key_present"}]}: every credential the wallet
// holds.
func (w *Wallet) Credentials() (string, error) {
	creds, err := w.w.Credentials(context.Background())
	if err != nil {
		return "", classify(err)
	}
	summaries := make([]credentialSummary, 0, len(creds))
	for _, c := range creds {
		s, err := w.summary(c)
		if err != nil {
			return "", err
		}
		summaries = append(summaries, s)
	}
	return marshal(struct {
		result
		Credentials []credentialSummary `json:"credentials"`
	}{result{ABIVersion}, summaries})
}

// Credential returns one credential for display: its summary with
// "claims" — an SD-JWT VC's claims, or an mdoc's namespace → element →
// value, byte strings in base64 — or not_found.
func (w *Wallet) Credential(id string) (string, error) {
	creds, err := w.w.Credentials(context.Background())
	if err != nil {
		return "", classify(err)
	}
	for _, c := range creds {
		if c.ID != id {
			continue
		}
		s, err := w.summary(c)
		if err != nil {
			return "", err
		}
		return marshal(struct {
			result
			credentialSummary
			Claims any `json:"claims"`
		}{result{ABIVersion}, s, jsonClaims(c.Claims)})
	}
	return "", newError(CodeNotFound, fmt.Errorf("no credential %q", id))
}

// summary is c's summary, with whether its holder key is still present.
func (w *Wallet) summary(c walletflow.StoredCredential) (credentialSummary, error) {
	s := summaryOf(c)
	pub, err := w.keys.PublicKey(c.HolderKeyID)
	if err != nil {
		return credentialSummary{}, newError(CodePlatform, fmt.Errorf("credential %q's holder key: %w", c.ID, err))
	}
	present := len(pub) > 0
	s.HolderKeyPresent = &present
	return s, nil
}

// DeleteCredential deletes the credential id names, and its holder key.
func (w *Wallet) DeleteCredential(id string) error {
	return classify(w.w.DeleteCredential(context.Background(), id))
}

// marshal returns v as JSON text.
func marshal(v any) (string, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	return string(out), nil
}
