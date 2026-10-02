package issuerapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The pre-authorized code flow (OID4VCI 1.0 §3.5): a passport issued
// "at the counter" gets an offer carrying a pre-authorized code, and a
// PIN (tx_code) shown separately. The wallet redeems the code and PIN
// at the token endpoint directly — no browser approval — authenticating
// with its Wallet Attestation, as HAIP 1.0 §4.4.1 requires, through
// fapigo/server's AuthenticateAttestedClient. The token it gets names
// the transaction as its subject, so the Credential Endpoint issues
// from it as it does for the authorization code flow.

// preAuthorizedCodeGrantType is the pre-authorized code grant's
// grant_type (OID4VCI 1.0 §3.5).
const preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// preAuthorizedCodeTxCode describes the PIN to the wallet (§4.1.1).
var preAuthorizedCodeTxCode = &oid4vci.TxCode{
	InputMode: "numeric", Length: 6,
	Description: "The PIN shown on the issuer's offer page",
}

// preAuthorizedOffer records a claimed transaction's pre-authorized code,
// redeemable with its PIN, and returns the Credential Offer for it.
func (a *App) preAuthorizedOffer(ctx context.Context, txID, pin string, configIDs []string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("issuerapp: pre-authorized code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(b[:])
	if err := a.preAuthCodes.Issue(ctx, code, issuer.PreAuthorizedCodeRecord{
		TxCode: pin, Scopes: []string{MdocScope, SDJWTScope},
		ExpiresAt: a.now().Add(a.cfg.transactionLifetime()), Subject: txID,
	}); err != nil {
		return "", fmt.Errorf("issuerapp: pre-authorized code: %w", err)
	}
	result, err := a.issuer.CreateCredentialOffer(ctx, issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: configIDs,
		Grants: &oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{
			PreAuthorizedCode: code, TxCode: preAuthorizedCodeTxCode,
		}},
	})
	if err != nil {
		return "", fmt.Errorf("issuerapp: credential offer: %w", err)
	}
	return result.URI, nil
}

// handleToken serves the token endpoint: the authorization code grant
// through fapigo/server, the pre-authorized code grant through the
// issuer, with fapigo/server reading the request once and checking the
// client and DPoP proof for both.
func (a *App) handleToken(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	switch req.GrantType() {
	case "authorization_code":
		result, err := a.server.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
		if err != nil {
			server.WriteError(w, err)
			return
		}
		result.WriteJSON(w)
	case preAuthorizedCodeGrantType:
		a.handlePreAuthorizedToken(w, r, req)
	default:
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "grant_type must be authorization_code or "+preAuthorizedCodeGrantType).WriteJSON(w)
	}
}

// handlePreAuthorizedToken redeems a pre-authorized code and its PIN. The
// Authorization Server authenticates the wallet by its Wallet Attestation
// and verifies the DPoP proof, as for its own grants (one replay record
// and nonce policy for the endpoint); the issuer then redeems the code.
func (a *App) handlePreAuthorizedToken(w http.ResponseWriter, r *http.Request, req server.TokenEndpointRequest) {
	ctx := r.Context()
	params, err := req.Parameters()
	if err != nil {
		server.WriteError(w, err)
		return
	}
	attested, err := a.server.AuthenticateAttestedClient(ctx, req.AttestedClientAuthentication())
	if err != nil {
		server.WriteError(w, err)
		return
	}
	clientID := attested.Client.ID().String()
	if id, ok := params["client_id"]; ok && id != clientID {
		server.NewError(server.ErrorInvalidClient, http.StatusUnauthorized, "client_id doesn't name the attested client").WriteJSON(w)
		return
	}
	binding, err := a.server.VerifyTokenRequestBinding(ctx, attested.Client, req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	if binding.SenderConstrain != storage.SenderConstrainDPoP {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, "this grant issues DPoP-bound tokens only").WriteJSON(w)
		return
	}
	result, err := a.issuer.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"],
		Verified: &issuer.VerifiedTokenRequest{
			ClientID: clientID, DPoPThumbprint: binding.Thumbprint, NextDPoPNonce: binding.NextDPoPNonce,
		},
	})
	if err != nil {
		issuerError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result.WriteJSON(w)
}

// issuerError writes an issuer token error, or a 500 for anything else.
func issuerError(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	issuer.WriteError(w, err)
}

// accessTokenAdapter mints the pre-authorized code grant's access tokens
// with the Authorization Server's own signing keys, so the Credential
// Endpoint's resource verifier accepts them unchanged.
type accessTokenAdapter struct{ inner server.AccessTokenIssuer }

func (t accessTokenAdapter) IssueAccessToken(ctx context.Context, p issuer.AccessTokenParams) (string, string, error) {
	return t.inner.IssueAccessToken(ctx, server.AccessTokenParams{
		Scope: p.Scope, Thumbprint: p.Thumbprint, Claims: p.Claims, Subject: p.Subject,
		ClientID: fapi.ClientID(p.ClientID), Issuer: p.Issuer, Audience: p.Audience,
		Now: p.Now, Lifetime: p.Lifetime, Random: p.Random,
	})
}
