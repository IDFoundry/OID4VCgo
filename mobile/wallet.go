package mobile

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

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
// Wallet uses: one trusting the in-process test issuer's certificate.
var testHTTP *http.Client

// Wallet is a holder's wallet: walletflow over the app's KeyStore,
// CredentialStore and WalletProvider.
type Wallet struct {
	w *walletflow.Wallet
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
		Keys: keyStore{keys}, Credentials: credentialStore{credentials},
		HTTP: &http.Client{Timeout: 30 * time.Second}, Random: randReader{},
	}
	if provider != nil {
		deps.Provider = walletProvider{provider}
	}
	if testHTTP != nil {
		deps.HTTP = testHTTP
	}
	w, err := walletflow.New(wcfg, deps)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &Wallet{w: w}, nil
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
// "received_at"}]}: every credential the wallet holds.
func (w *Wallet) Credentials() (string, error) {
	creds, err := w.w.Credentials(context.Background())
	if err != nil {
		return "", classify(err)
	}
	return marshal(struct {
		result
		Credentials []credentialSummary `json:"credentials"`
	}{result{ABIVersion}, summariesOf(creds)})
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
