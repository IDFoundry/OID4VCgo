package walletapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// PINApprover is an Approver that can also supply a pre-authorized
// offer's PIN (tx_code, OID4VCI 1.0 §4.1.1): the wallet redeems such an
// offer at the token endpoint with the PIN, with no browser approval.
type PINApprover interface {
	PIN(ctx context.Context, txCode oid4vci.TxCode) (string, error)
}

// PIN implements PINApprover with Code.
func (h HeadlessApprover) PIN(context.Context, oid4vci.TxCode) (string, error) {
	if h.Code == "" {
		return "", errors.New("walletapp: the offer needs a PIN")
	}
	return h.Code, nil
}

// receivePreAuthorized redeems a pre-authorized code offer (OID4VCI 1.0
// §3.5): the code and the PIN at the token endpoint, authenticating with
// a Wallet Attestation and its PoP (HAIP 1.0 §4.4.1), then every
// offered credential, with the token bound to a fresh DPoP key.
func receivePreAuthorized(ctx context.Context, w *wallet.Wallet, cfg Config, httpClient *http.Client, offer oid4vci.CredentialOffer, metadata oid4vci.Metadata, approver Approver) ([]Received, []*Pending, error) {
	grant := offer.Grants.PreAuthorizedCode
	var pin string
	if grant.TxCode != nil {
		pa, ok := approver.(PINApprover)
		if !ok {
			return nil, nil, errors.New("walletapp: the offer needs a PIN, and nothing can supply one")
		}
		var err error
		if pin, err = pa.PIN(ctx, *grant.TxCode); err != nil {
			return nil, nil, err
		}
	}

	asURL := grant.AuthorizationServer
	if asURL == "" {
		asURL = offer.CredentialIssuer
		if len(metadata.AuthorizationServers) == 1 {
			asURL = metadata.AuthorizationServers[0].String()
		}
	}
	asMeta, err := w.FetchAuthorizationServerMetadata(ctx, asURL)
	if err != nil {
		return nil, nil, fmt.Errorf("walletapp: authorization server metadata: %w", err)
	}
	tokenEndpoint, err := fapi.ParseEndpointURL(asMeta.TokenEndpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("walletapp: token endpoint: %w", err)
	}

	// The same fapigo/client the authorization code flow uses, for its
	// Wallet Attestation (a fresh instance key, attested by the Wallet
	// Provider) and the PoP it builds for each Token Request.
	c, err := newOAuthClient(ctx, w, cfg, httpClient, asURL)
	if err != nil {
		return nil, nil, err
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("walletapp: dpop key: %w", err)
	}
	token, err := w.RequestPreAuthorizedCodeToken(ctx, tokenEndpoint, wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: grant.PreAuthorizedCode, TxCode: pin, DPoPKey: dpopKey, ClientAttestation: c,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walletapp: token: %w", err)
	}
	return requestAll(ctx, w, cfg, w.DPoPResourceClient(token.AccessToken, dpopKey), offer, metadata)
}
