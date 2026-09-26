// Package walletapp is the passport-vdc demo wallet: given a Credential
// Offer, it discovers the issuer, authenticates with a Wallet
// Attestation from the demo Wallet Provider, runs the HAIP
// Authorization Code flow (PAR, PKCE, DPoP) and requests every offered
// credential, each bound to a fresh holder key that the Wallet Provider
// attests in a Key Attestation (the attestation proof type).
//
// It is a demo, not a secure wallet: holder keys are ordinary in-memory
// keys (a real wallet keeps them in secure hardware), and it attests
// itself and its holder keys with the Wallet Provider's own private
// key, which a real wallet would never hold.
package walletapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Config configures a demo wallet.
type Config struct {
	// ClientID and RedirectURI must match the issuer's registration of
	// the demo wallet.
	ClientID    string
	RedirectURI string

	// Provider attests this wallet instance. See the package doc.
	Provider *walletprovider.Provider

	// HTTP makes every request; nil means a client with a 10 s timeout.
	HTTP *http.Client
}

// Approver completes the authorization step: given the authorization
// URL, it returns the raw query of the redirect back to RedirectURI.
type Approver interface {
	Approve(ctx context.Context, authorizationURL string) (callbackQuery string, err error)
}

// Received is one credential the wallet obtained.
type Received struct {
	ConfigurationID string
	Format          string
	// DocType is the mdoc doctype, for mso_mdoc credentials.
	DocType string
	// Credential is the issued credential as the issuer returned it:
	// a compact SD-JWT VC, or base64url-encoded mdoc IssuerSigned CBOR.
	Credential string
	// HolderKey is the key the credential is bound to — needed to
	// present it later.
	HolderKey *ecdsa.PrivateKey
}

const httpTimeout = 10 * time.Second

// Receive redeems the Credential Offer at offerURI and returns every
// credential it offered.
func Receive(ctx context.Context, cfg Config, offerURI string, approver Approver) ([]Received, error) {
	if cfg.Provider == nil || cfg.ClientID == "" || cfg.RedirectURI == "" || approver == nil {
		return nil, fmt.Errorf("walletapp: ClientID, RedirectURI, Provider and an Approver are required")
	}
	httpClient := cfg.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: httpTimeout}
	}

	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: httpTimeout, MaxRedirects: 2, AllowLoopbackHTTP: true},
	}, wallet.Dependencies{HTTP: httpClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		return nil, fmt.Errorf("walletapp: %w", err)
	}

	offer, err := w.ResolveCredentialOffer(ctx, offerURI)
	if err != nil {
		return nil, fmt.Errorf("walletapp: credential offer: %w", err)
	}
	metadata, err := w.FetchCredentialIssuerMetadata(ctx, offer.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("walletapp: issuer metadata: %w", err)
	}
	scopes, err := offeredScopes(offer, metadata)
	if err != nil {
		return nil, err
	}

	// oid4vci.Metadata carries no authorization_servers, so the
	// Credential Issuer is taken to be its own Authorization Server —
	// true of the demo issuer.
	c, err := newOAuthClient(ctx, w, cfg, httpClient, offer.CredentialIssuer)
	if err != nil {
		return nil, err
	}
	authReq, err := wallet.BuildAuthorizationRequest(offer, scopes)
	if err != nil {
		return nil, fmt.Errorf("walletapp: %w", err)
	}
	session, err := c.BeginAuthorization(ctx, authReq)
	if err != nil {
		return nil, fmt.Errorf("walletapp: pushed authorization request: %w", err)
	}
	callback, err := approver.Approve(ctx, session.URL().String())
	if err != nil {
		return nil, fmt.Errorf("walletapp: authorization: %w", err)
	}
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: callback})
	if err != nil {
		return nil, fmt.Errorf("walletapp: token: %w", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		return nil, fmt.Errorf("walletapp: authorization was not granted (%T)", result)
	}

	return requestAll(ctx, w, cfg.Provider, c.ProtectedResource(success.Tokens), offer, metadata)
}

// offeredScopes returns the scope of every offered configuration.
func offeredScopes(offer oid4vci.CredentialOffer, metadata oid4vci.Metadata) ([]string, error) {
	scopes := make([]string, 0, len(offer.CredentialConfigurationIDs))
	for _, id := range offer.CredentialConfigurationIDs {
		conf, ok := metadata.CredentialConfigurationsSupported[id]
		if !ok || conf.Scope == "" {
			return nil, fmt.Errorf("walletapp: offered configuration %q isn't in the issuer's metadata with a scope", id)
		}
		scopes = append(scopes, conf.Scope)
	}
	return scopes, nil
}

func requestAll(ctx context.Context, w *wallet.Wallet, provider *walletprovider.Provider, resource wallet.ProtectedResourceClient, offer oid4vci.CredentialOffer, metadata oid4vci.Metadata) ([]Received, error) {
	if metadata.NonceEndpoint == nil {
		return nil, fmt.Errorf("walletapp: issuer advertises no nonce endpoint")
	}
	received := make([]Received, 0, len(offer.CredentialConfigurationIDs))
	for _, id := range offer.CredentialConfigurationIDs {
		nonce, err := w.RequestNonce(ctx, *metadata.NonceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("walletapp: nonce: %w", err)
		}
		holder, keyAttestation, err := attestedHolderKey(w, provider, nonce.CNonce)
		if err != nil {
			return nil, err
		}
		result, err := w.RequestCredential(ctx, resource, metadata.CredentialEndpoint, wallet.CredentialRequest{
			CredentialConfigurationID: id, Attestation: keyAttestation,
		})
		if err != nil {
			return nil, fmt.Errorf("walletapp: credential %q: %w", id, err)
		}
		if len(result.Credentials) != 1 {
			return nil, fmt.Errorf("walletapp: credential %q: got %d credentials, want 1", id, len(result.Credentials))
		}
		conf := metadata.CredentialConfigurationsSupported[id]
		received = append(received, Received{
			ConfigurationID: id, Format: conf.Format, DocType: conf.DocType,
			Credential: result.Credentials[0].Credential, HolderKey: holder,
		})
	}
	return received, nil
}

// keyAttestationLifetime bounds how long a Key Attestation is valid; it
// is used once, right away.
const keyAttestationLifetime = 5 * time.Minute

// attestedHolderKey generates a holder key and has the Wallet Provider
// attest it in a Key Attestation carrying the issuer's nonce.
func attestedHolderKey(w *wallet.Wallet, provider *walletprovider.Provider, nonce string) (*ecdsa.PrivateKey, string, error) {
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("walletapp: holder key: %w", err)
	}
	claims, err := provider.KeyAttestationClaims([]*ecdsa.PublicKey{&holder.PublicKey}, time.Now(), keyAttestationLifetime)
	if err != nil {
		return nil, "", fmt.Errorf("walletapp: key attestation: %w", err)
	}
	keyAttestation, err := w.GenerateAttestationProof(provider.Key, oid4vci.ES256, provider.KeyAttestationHeader(), claims, nonce)
	if err != nil {
		return nil, "", fmt.Errorf("walletapp: key attestation: %w", err)
	}
	return holder, keyAttestation, nil
}

// newOAuthClient builds the wallet's fapigo/client from the
// Authorization Server's metadata, authenticating with a fresh Wallet
// Attestation over a fresh instance key.
func newOAuthClient(ctx context.Context, w *wallet.Wallet, cfg Config, httpClient *http.Client, asURL string) (*client.Client, error) {
	asMeta, err := w.FetchAuthorizationServerMetadata(ctx, asURL)
	if err != nil {
		return nil, fmt.Errorf("walletapp: authorization server metadata: %w", err)
	}
	var issuer fapi.URL
	var endpoints client.Endpoints
	for raw, dst := range map[string]*fapi.URL{
		asMeta.Issuer: &issuer, asMeta.AuthorizationEndpoint: &endpoints.Authorization,
		asMeta.TokenEndpoint: &endpoints.Token, asMeta.PushedAuthorizationRequestEndpoint: &endpoints.PushedAuthorizationRequest,
	} {
		if *dst, err = parseURL(raw, dst == &issuer); err != nil {
			return nil, fmt.Errorf("walletapp: authorization server metadata: %w", err)
		}
	}

	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAttestationPoPSigning: fapi.ES256, keys.DPoPProofSigning: fapi.ES256,
	})
	if err != nil {
		return nil, fmt.Errorf("walletapp: key manager: %w", err)
	}
	instance, err := km.PublicKey(ctx, keys.ClientAttestationPoPSigning, fapi.ES256)
	if err != nil {
		return nil, fmt.Errorf("walletapp: instance key: %w", err)
	}
	walletAttestation, err := cfg.Provider.Attest(cfg.ClientID, instance.PublicKey, time.Now(), time.Hour)
	if err != nil {
		return nil, fmt.Errorf("walletapp: wallet attestation: %w", err)
	}

	c, err := client.New(client.Config{
		Issuer: issuer, ClientID: fapi.ClientID(cfg.ClientID), RedirectURI: cfg.RedirectURI,
		Endpoints: endpoints,
		Profile:   client.ProfileFAPISecurity, Assurance: client.AssuranceDevelopment,
		ClientAuthMethod:               storage.ClientAuthMethodAttestation,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		Algorithms:                     client.Algorithms{DPoP: fapi.ES256, IDToken: fapi.ES256, ClientAttestationPoP: fapi.ES256},
		Limits: client.Limits{
			SessionLifetime: 10 * time.Minute, MaxIDTokenLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second,
			HTTPTimeout: httpTimeout, MaxHTTPResponseBytes: 1 << 20, MaxJOSECompactBytes: 16 * 1024,
		},
	}, client.Dependencies{
		Sessions: memstore.NewSessionStore(), Keys: km, IssuerKeys: noIssuerKeys{}, HTTP: httpClient,
		Clock: client.SystemClock{}, Random: rand.Reader, Attestation: staticAttestation(walletAttestation),
	})
	if err != nil {
		return nil, fmt.Errorf("walletapp: oauth client: %w", err)
	}
	return c, nil
}

// parseURL parses an issuer (asIssuer) or endpoint URL, allowing
// loopback http for local demos.
func parseURL(raw string, asIssuer bool) (fapi.URL, error) {
	var opts []fapi.URLOption
	if strings.HasPrefix(raw, "http://") {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	if asIssuer {
		return fapi.ParseIssuerURL(raw, opts...)
	}
	return fapi.ParseEndpointURL(raw, opts...)
}

type staticAttestation string

func (s staticAttestation) CurrentAttestation(context.Context) (string, error) { return string(s), nil }

// noIssuerKeys satisfies fapigo/client's IssuerKeys dependency: this
// OAuth-only flow never verifies an ID token or JARM response.
type noIssuerKeys struct{}

func (noIssuerKeys) ResolveIssuerKeys(context.Context, keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{}, fmt.Errorf("walletapp: unexpected issuer key lookup")
}
