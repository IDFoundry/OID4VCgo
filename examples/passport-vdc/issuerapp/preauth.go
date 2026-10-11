package issuerapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

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
	case "refresh_token":
		// A passport kept for refresh: a new access token for the same
		// transaction, while it's kept.
		result, err := a.server.RefreshAccessToken(r.Context(), req.RefreshToken())
		if err != nil {
			server.WriteError(w, err)
			return
		}
		result.WriteJSON(w)
	case preAuthorizedCodeGrantType:
		a.handlePreAuthorizedToken(w, r, req)
	default:
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "grant_type must be authorization_code, refresh_token or "+preAuthorizedCodeGrantType).WriteJSON(w)
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
	redeemed, err := a.issuer.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"],
		Verified: &issuer.VerifiedTokenRequest{ClientID: clientID, DPoPThumbprint: binding.Thumbprint},
	})
	if err != nil {
		issuerError(w, err)
		return
	}
	// The access token, and a refresh token when there is one, belong to
	// one grant, named by the transaction ID: revoking it (RevokeGrant,
	// or the wallet revoking its refresh token) ends both.
	grant, err := preAuthorizedGrant(attested, binding, redeemed)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result, err := a.server.IssueAccessToken(ctx, grant)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	// A passport kept for refresh gets a refresh token too, as
	// handleDecision grants one. Without one the wallet still gets its
	// credentials, and the passport is dropped once they're issued.
	if a.transactions.keeps(redeemed.Subject) {
		refresh, err := a.server.IssueRefreshToken(ctx, server.IssueRefreshTokenRequest(grant))
		if err != nil {
			a.transactions.dontKeep(redeemed.Subject)
		} else {
			result.RefreshToken, result.HasRefreshToken = refresh, true
		}
	}
	result.WriteJSON(w)
}

// preAuthorizedGrant is a redeemed pre-authorized code's grant: what the
// code granted, to the client and DPoP key the token request verified,
// named by the transaction ID.
func preAuthorizedGrant(attested server.AttestedClient, binding server.TokenBinding, redeemed issuer.RedeemedPreAuthorizedCode) (server.IssueAccessTokenRequest, error) {
	subject, err := server.NewSubjectID(redeemed.Subject)
	if err != nil {
		return server.IssueAccessTokenRequest{}, err
	}
	details := make([]json.RawMessage, 0, len(redeemed.AuthorizationDetails))
	for _, d := range redeemed.AuthorizationDetails {
		raw, err := json.Marshal(d)
		if err != nil {
			return server.IssueAccessTokenRequest{}, err
		}
		details = append(details, raw)
	}
	return server.IssueAccessTokenRequest{
		GrantType: preAuthorizedCodeGrantType, Client: attested, Binding: binding, Subject: subject,
		Scope: redeemed.Scope, AuthorizationDetails: details, GrantID: redeemed.Subject,
	}, nil
}

// issuerError writes an issuer token error, or a 500 for anything else.
func issuerError(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	issuer.WriteError(w, err)
}
