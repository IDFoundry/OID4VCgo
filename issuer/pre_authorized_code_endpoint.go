package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// ExchangePreAuthorizedCodeRequest is the Pre-Authorized Code Flow's
// own Token Request (§6.1).
type ExchangePreAuthorizedCodeRequest struct {
	// PreAuthorizedCode is REQUIRED.
	PreAuthorizedCode string

	// TxCode is the End-User's own Transaction Code value — REQUIRED
	// exactly when the code was issued with one (its
	// PreAuthorizedCodeRecord has a TxCodeHash; §6.1's own MUST), and
	// refused otherwise.
	TxCode string

	// Verified is the request's DPoP proof, and under
	// VerifiedPreAuthorizedCode its client, already verified by the
	// Authorization Server serving the Token Endpoint. REQUIRED: HAIP 1.0
	// §4 makes DPoP mandatory for every grant, so this package doesn't
	// support an unconstrained (bearer) token for this one either. Under
	// AnonymousPreAuthorizedCode its ClientID must be "".
	Verified *VerifiedTokenRequest

	// AuthorizationDetails is the Token Request's authorization_details
	// (§6.1.1, RFC 9396), OPTIONAL: ParseAuthorizationDetails reads the
	// form parameter. Each must be an openid_credential entry for a
	// configuration the code grants, by credential identifiers or scope,
	// whose locations, if any, include this Credential Issuer. The token
	// then carries a credential_identifier for each, and the Token
	// Response echoes them (§6.2: "REQUIRED when the
	// authorization_details parameter is used in ... the Token Request").
	// Their form, and whether the code grants them, are checked before
	// the code is consumed — the latter by PreAuthorizedCodeStore.Consume's
	// accept, in the same atomic step that keeps the code single-use —
	// so a request for more than the code grants is refused with
	// invalid_authorization_details and leaves the code redeemable.
	AuthorizationDetails []oid4vci.AuthorizationDetail
}

// ParseAuthorizationDetails reads a Token Request's
// authorization_details form parameter (RFC 9396 §2): "" is none, and
// anything but a JSON array of objects is invalid_authorization_details.
func ParseAuthorizationDetails(value string) ([]oid4vci.AuthorizationDetail, error) {
	if value == "" {
		return nil, nil
	}
	var details []oid4vci.AuthorizationDetail
	if err := strictjson.Unmarshal([]byte(value), &details); err != nil || len(details) == 0 {
		return nil, newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details isn't a non-empty JSON array of objects", err)
	}
	return details, nil
}

// ExchangePreAuthorizedCodeResult is returned by a successful
// ExchangePreAuthorizedCode.
type ExchangePreAuthorizedCodeResult struct {
	AccessToken string

	// TokenType is always "DPoP" (RFC 9449 §5) — every access token
	// this method issues is DPoP-bound, per HAIP 1.0 §4.
	TokenType string

	ExpiresIn time.Duration

	// NextDPoPNonce is the DPoP nonce the Authorization Server currently
	// hands out,
	// for the caller to set as this response's own DPoP-Nonce header —
	// WriteJSON already does this — so the Wallet's next Token Request
	// already carries a valid one instead of needing its own
	// challenge/retry round trip (RFC 9449 §8.2: the client uses a nonce
	// "until the server supplies a new nonce"). It is
	// VerifiedTokenRequest.NextDPoPNonce: the Authorization Server's,
	// "" when it uses no DPoP nonces.
	NextDPoPNonce string

	// AuthorizationDetails is every "openid_credential"-typed entry
	// (RFC 9396 §5.1.1) this exchange minted from the redeemed
	// PreAuthorizedCodeRecord's own CredentialConfigurationIDs — WriteJSON
	// already includes it in the Token Response's own
	// "authorization_details" member (§6.2) when non-empty. The Wallet
	// then presents one of its own CredentialIdentifiers values in a
	// later Credential Request instead of credential_configuration_id
	// (§8.2). Empty when PreAuthorizedCodeRecord.CredentialConfigurationIDs
	// was empty — this exchange's own behavior is then unchanged from
	// before this field existed.
	AuthorizationDetails []oid4vci.AuthorizationDetail

	// Subject and Scope are the redeemed PreAuthorizedCodeRecord's own
	// Subject and Scopes: what the access token was issued for, and what
	// a refresh token for this grant should grant (with
	// AuthorizationDetails), for an Authorization Server that issues one
	// (fapigo/server.Server.IssueRefreshToken).
	Subject string
	Scope   []string

	// RefreshToken, set by the caller before WriteJSON, is the Token
	// Response's refresh_token: one the Authorization Server issued for
	// this grant, so the Wallet can refresh its credentials (OpenID4VCI
	// 1.0 §13.5). Empty: none. It's optional: if issuing one fails,
	// write the response without it — the pre-authorized code is
	// redeemed already, so failing the response would leave the Wallet
	// with nothing.
	RefreshToken fapi.Secret
}

// WriteJSON writes r as a complete Token Response (§6.2): the
// DPoP-Nonce header when NextDPoPNonce is non-empty (RFC 9449 §8), HTTP
// 200, application/json, {"access_token","token_type","expires_in"},
// plus "authorization_details" (RFC 9396 §6.2) when
// AuthorizationDetails is non-empty. Must be called before anything
// else writes to w.
func (r ExchangePreAuthorizedCodeResult) WriteJSON(w http.ResponseWriter) {
	if r.NextDPoPNonce != "" {
		w.Header().Set("DPoP-Nonce", r.NextDPoPNonce)
	}
	// It carries tokens: never cached. RFC 6749 §5.1 requires both
	// headers, Pragma for HTTP/1.0 caches.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct { //nolint:gosec // the actual §6.2 Token Response body, meant to carry this
		AccessToken          string                        `json:"access_token"`
		TokenType            string                        `json:"token_type"`
		ExpiresIn            int64                         `json:"expires_in"`
		RefreshToken         string                        `json:"refresh_token,omitempty"`
		AuthorizationDetails []oid4vci.AuthorizationDetail `json:"authorization_details,omitempty"`
	}{
		AccessToken: r.AccessToken, TokenType: r.TokenType, ExpiresIn: int64(r.ExpiresIn.Seconds()),
		RefreshToken: r.RefreshToken.Reveal(), AuthorizationDetails: r.AuthorizationDetails,
	})
}

// PreAuthorizedCodeClientAuthentication is how ExchangePreAuthorizedCode
// authenticates the client redeeming a pre-authorized_code (see
// Config.PreAuthorizedCodeClientAuthentication).
type PreAuthorizedCodeClientAuthentication interface {
	isPreAuthorizedCodeClientAuthentication()
}

// AnonymousPreAuthorizedCode redeems a pre-authorized_code for any
// client that presents it (and its tx_code, if any) with a valid DPoP
// proof — no client authentication, so no Wallet Attestation: whoever
// holds the code gets the access token, not only a Wallet this issuer
// trusts. OID4VCI §6.1 allows this; HAIP 1.0 §4.4.1 requires client
// authentication at the Token Endpoint, so an issuer using it isn't
// following HAIP for this grant.
//
// The Authorization Server serving the Token Endpoint verifies the DPoP
// proof, under its own replay record and nonce policy, so the endpoint
// has one of each whichever grant a request uses, and passes the key in
// ExchangePreAuthorizedCodeRequest.Verified, with no ClientID.
// ExchangePreAuthorizedCode then issues the access token through
// Dependencies.AccessTokens, bound to that key. With fapigo/server
// (Server.VerifyTokenRequestDPoP), the Token Endpoint handler refuses a
// request that also authenticates a client, which this grant doesn't
// expect, before verifying the proof:
//
//	tr, err := server.TokenEndpointRequestFromHTTP(r)
//	if err != nil {
//		return err // answer with the token error
//	}
//	params, err := tr.Parameters()
//	if err != nil {
//		return err
//	}
//	auth := tr.AttestedClientAuthentication()
//	if len(auth.ClientAttestations) > 0 || len(auth.ClientAttestationPoPs) > 0 ||
//		params["client_assertion"] != "" || params["client_assertion_type"] != "" ||
//		params["client_secret"] != "" || (r.TLS != nil && len(r.TLS.PeerCertificates) > 0) {
//		return server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest,
//			"this grant takes no client authentication")
//	}
//	// An *server.Error, use_dpop_nonce with the next nonce included:
//	// server.WriteError answers it with its DPoP-Nonce header.
//	b, err := srv.VerifyTokenRequestDPoP(ctx, tr)
//	if err != nil {
//		return err
//	}
//	details, err := issuer.ParseAuthorizationDetails(params["authorization_details"])
//	if err != nil {
//		return err
//	}
//	res, err := iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
//		PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"], AuthorizationDetails: details,
//		Verified: &issuer.VerifiedTokenRequest{DPoPThumbprint: b.Thumbprint, NextDPoPNonce: b.NextDPoPNonce},
//	})
//
// and lists the grant in fapigo/server's Config.AdditionalGrantTypes.
// Behind a proxy that terminates TLS, test for the client certificate
// the proxy forwards instead of r.TLS.
type AnonymousPreAuthorizedCode struct{}

func (AnonymousPreAuthorizedCode) isPreAuthorizedCodeClientAuthentication() {
	// A marker: it only makes the type a PreAuthorizedCodeClientAuthentication.
}

// VerifiedPreAuthorizedCode redeems a pre-authorized_code for a Token
// Request whose client and DPoP proof the Authorization Server serving
// the same Token Endpoint has already verified, and passed in
// ExchangePreAuthorizedCodeRequest.Verified: as HAIP 1.0 §4.4.1
// requires, the client authenticated with its Wallet Attestation, and
// the proof was checked under the Authorization Server's own DPoP replay
// record and nonce policy, so the endpoint has one of each whichever
// grant a request uses. ExchangePreAuthorizedCode then verifies neither
// itself. With fapigo/server, the Token Endpoint handler reads the
// request once and does both checks first:
//
//	tr, err := server.TokenEndpointRequestFromHTTP(r)
//	if err != nil {
//		return err // answer with the token error
//	}
//	params, err := tr.Parameters()
//	if err != nil {
//		return err
//	}
//	// Also refuses a client_id parameter naming another client.
//	c, err := srv.AuthenticateAttestedClient(ctx, tr.AttestedClientAuthentication())
//	if err != nil {
//		return err
//	}
//	b, err := srv.VerifyTokenRequestBinding(ctx, c.Client, tr)
//	if err != nil {
//		return err
//	}
//	if b.SenderConstrain != storage.SenderConstrainDPoP {
//		return errors.New("the access token must be DPoP-bound")
//	}
//	details, err := issuer.ParseAuthorizationDetails(params["authorization_details"])
//	if err != nil {
//		return err
//	}
//	res, err := iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
//		PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"], AuthorizationDetails: details,
//		Verified: &issuer.VerifiedTokenRequest{
//			ClientID: c.Client.ID().String(), DPoPThumbprint: b.Thumbprint, NextDPoPNonce: b.NextDPoPNonce,
//		},
//	})
//	if err != nil {
//		return err // an *issuer.Error writes itself (WriteJSON)
//	}
//
// and lists the grant in fapigo/server's Config.AdditionalGrantTypes.
// To have fapigo/server issue the access token itself instead, call
// RedeemPreAuthorizedCode in place of ExchangePreAuthorizedCode and
// configure the server to accept the authorization_details it mints, as
// its doc comment says: otherwise a Wallet that sends
// authorization_details spends its code on an error.
type VerifiedPreAuthorizedCode struct{}

func (VerifiedPreAuthorizedCode) isPreAuthorizedCodeClientAuthentication() {
	// A marker: it only makes the type a PreAuthorizedCodeClientAuthentication.
}

// VerifiedTokenRequest is what the Authorization Server verified about a
// Token Request, for VerifiedPreAuthorizedCode.
type VerifiedTokenRequest struct {
	// ClientID is the authenticated client. REQUIRED.
	ClientID string

	// DPoPThumbprint is the RFC 7638 thumbprint of the key the request's
	// verified DPoP proof was signed with, to bind the access token to.
	// REQUIRED.
	DPoPThumbprint string

	// NextDPoPNonce, when not "", is sent with the Token Response's
	// DPoP-Nonce header (ExchangePreAuthorizedCodeResult.NextDPoPNonce).
	NextDPoPNonce string
}

// ExchangePreAuthorizedCode implements the Pre-Authorized Code Flow's
// own Token Request/Response (§6.1/§6.2) — the one OAuth 2.0 grant
// type entirely outside fapigo/server's own scope (it's OID4VCI-specific,
// not a FAPI 2.0 or base OAuth 2.0 grant), the same way it's outside
// fapigo/client's; see wallet.RequestPreAuthorizedCodeToken's own doc
// comment for that boundary's client-side half, which this method is
// the server-side counterpart to.
//
// It takes the Token Request's DPoP key from req.Verified, which the
// Authorization Server verified, and redeems req.PreAuthorizedCode via
// Dependencies.PreAuthorizedCodes (§6.1's own single-use nature),
// checking the Transaction Code it was issued with (if any) matches
// req.TxCode exactly, by its hash (PreAuthorizedCodeRecord.TxCodeHash),
// and that the record hasn't expired and grants any requested
// authorization_details, before the code is consumed, and mints an access token via
// Dependencies.AccessTokens bound to the proof's own key by its RFC
// 7638 thumbprint.
//
// Under VerifiedPreAuthorizedCode the Authorization Server has already
// authenticated the client by its Wallet Attestation (HAIP 1.0 §4.4.1)
// and verified the DPoP proof, and the token is bound to that client and
// key. Under AnonymousPreAuthorizedCode the client isn't authenticated,
// and the token is bound to the key alone. Either way this method
// verifies neither, and the Authorization Server's checks happen before
// the code is consumed, so neither a DPoP nonce challenge nor an
// unauthenticated client spends it. Config.PreAuthorizedCodeClientAuthentication
// chooses; AssuranceProduction requires the choice to be explicit.
//
// A wrong TxCode doesn't invalidate the code (PreAuthorizedCodeStore.Consume's
// own contract), so the Wallet holder can retry after a mistyped PIN —
// but this method still bounds how many consecutive wrong guesses one
// code tolerates: once PreAuthorizedCodeStore.Consume's own
// wrongAttempts reaches Config.Limits.MaxTxCodeAttempts, it calls
// PreAuthorizedCodeStore.Invalidate and fails the request, closing the
// otherwise-unbounded guessing window a leaked pre-authorized_code
// would give an attacker against a low-entropy tx_code (found in a
// repo-wide security review).
//
// A successful exchange returns the Authorization Server's next DPoP
// nonce, VerifiedTokenRequest.NextDPoPNonce, as
// ExchangePreAuthorizedCodeResult.NextDPoPNonce, so the Wallet never
// round-trips through a challenge it can already avoid.
//
// When the redeemed record's own CredentialConfigurationIDs is
// non-empty, this also mints one credential_identifier per entry
// (mintAuthorizationDetails) and embeds the result both in the issued
// access token itself (AccessTokenParams.Claims["authorization_details"],
// for RequestCredential to recover later via a caller's own
// AuthorizedRequest.AuthorizationDetails adaptation) and in
// ExchangePreAuthorizedCodeResult.AuthorizationDetails directly, for
// WriteJSON to echo back in the Token Response (§6.2) — this package
// never round-trips a self-contained token's own claims back out of
// itself, so the result carries the same value independently rather
// than relying on the caller to decode its own freshly issued token.
func (iss *Issuer) ExchangePreAuthorizedCode(ctx context.Context, req ExchangePreAuthorizedCodeRequest) (ExchangePreAuthorizedCodeResult, error) {
	// clientID stays "" unless VerifiedPreAuthorizedCode authenticated
	// the client (AuditEvent.ClientID's own "" convention).
	var clientID string
	result, err := iss.exchangePreAuthorizedCode(ctx, req, &clientID)
	iss.audit(ctx, AuditEventExchangePreAuthorizedCode, clientID, err)
	return result, err
}

func (iss *Issuer) exchangePreAuthorizedCode(ctx context.Context, req ExchangePreAuthorizedCodeRequest, clientID *string) (ExchangePreAuthorizedCodeResult, error) {
	if iss.deps.PreAuthorizedCodes != nil && iss.deps.AccessTokens == nil {
		return ExchangePreAuthorizedCodeResult{}, fmt.Errorf("issuer: exchange pre-authorized code: dependencies.access_tokens isn't set: the Authorization Server issues the token (RedeemPreAuthorizedCode)")
	}
	now := iss.deps.Clock.Now()
	redeemed, err := iss.redeemPreAuthorizedCode(ctx, req, now, clientID)
	if err != nil {
		return ExchangePreAuthorizedCodeResult{}, err
	}
	binding, record, authDetails := redeemed.binding, redeemed.record, redeemed.AuthorizationDetails

	params := AccessTokenParams{
		Scope: record.Scopes, Thumbprint: binding.DPoPThumbprint, Subject: record.Subject, ClientID: binding.ClientID,
		Issuer: iss.cfg.Issuer.String(), Audience: iss.cfg.Issuer.String(),
		Now: now, Lifetime: iss.cfg.Limits.AccessTokenLifetime, Random: iss.deps.Random,
	}
	if len(authDetails) > 0 {
		raw, err := json.Marshal(authDetails)
		if err != nil {
			return ExchangePreAuthorizedCodeResult{}, fmt.Errorf("issuer: exchange pre-authorized code: marshal authorization_details: %w", err)
		}
		params.Claims = map[string]json.RawMessage{"authorization_details": raw}
	}

	accessToken, _, err := iss.deps.AccessTokens.IssueAccessToken(ctx, params)
	if err != nil {
		return ExchangePreAuthorizedCodeResult{}, fmt.Errorf("issuer: exchange pre-authorized code: issue access token: %w", err)
	}

	result := ExchangePreAuthorizedCodeResult{
		AccessToken: accessToken, TokenType: "DPoP", ExpiresIn: iss.cfg.Limits.AccessTokenLifetime,
		AuthorizationDetails: authDetails, Subject: record.Subject, Scope: record.Scopes,
	}
	result.NextDPoPNonce = binding.NextDPoPNonce
	return result, nil
}

// RedeemedPreAuthorizedCode is a pre-authorized_code that
// RedeemPreAuthorizedCode redeemed: what to issue an access token for.
type RedeemedPreAuthorizedCode struct {
	// ClientID is the client the Authorization Server authenticated
	// (VerifiedTokenRequest.ClientID).
	ClientID string

	// Subject and Scope are the redeemed PreAuthorizedCodeRecord's own
	// Subject and Scopes.
	Subject string
	Scope   []string

	// AuthorizationDetails is one "openid_credential" entry per
	// CredentialConfigurationIDs entry of the record, each with a freshly
	// minted credential_identifier, as ExchangePreAuthorizedCodeResult's.
	// The access token must carry them, and the Token Response return
	// them (§6.2). Empty when the record names none.
	AuthorizationDetails []oid4vci.AuthorizationDetail

	binding VerifiedTokenRequest
	record  PreAuthorizedCodeRecord
}

// RedeemPreAuthorizedCode redeems a pre-authorized_code for an
// Authorization Server that issues the access token itself, rather than
// ExchangePreAuthorizedCode issuing it through Dependencies.AccessTokens:
// fapigo/server's Server.IssueAccessToken, which binds the token to its
// grant (GrantID), so that revoking the grant ends it.
//
// It needs VerifiedPreAuthorizedCode, and does what ExchangePreAuthorizedCode
// does but issue the token: it checks req.PreAuthorizedCode's tx_code
// (bounding wrong tx_code attempts), its expiry, and that it grants
// req.AuthorizationDetails, consumes it once all of them pass — a
// refused request leaves it redeemable — and mints the
// authorization_details. The caller then issues the access
// token for the result's Subject, Scope and AuthorizationDetails, bound
// to the request's DPoP key, and writes the Token Response with the
// authorization_details in it. A failure to issue after this succeeded
// leaves the code spent.
//
// So the Authorization Server must accept the openid_credential
// authorization_details this mints whenever req.AuthorizationDetails
// is set (§6.1.1 lets a Wallet send them). fapigo/server's
// IssueAccessToken and IssueRefreshToken refuse authorization_details
// unless Config.RAR registers the openid_credential type (an
// extension.RARDefinition of oid4vci.AuthorizationDetail does) and the
// client's registration lists it in AuthorizationDetailsTypes. An
// embedder that doesn't configure that must refuse a Token Request
// with authorization_details, with ErrorInvalidAuthorizationDetails,
// before calling this, since this call is what consumes the code.
//
// Every call records an AuditEventRedeemPreAuthorizedCode.
func (iss *Issuer) RedeemPreAuthorizedCode(ctx context.Context, req ExchangePreAuthorizedCodeRequest) (RedeemedPreAuthorizedCode, error) {
	var clientID string
	redeemed, err := iss.redeemVerifiedPreAuthorizedCode(ctx, req, &clientID)
	iss.audit(ctx, AuditEventRedeemPreAuthorizedCode, clientID, err)
	return redeemed, err
}

func (iss *Issuer) redeemVerifiedPreAuthorizedCode(ctx context.Context, req ExchangePreAuthorizedCodeRequest, clientID *string) (RedeemedPreAuthorizedCode, error) {
	if _, ok := iss.cfg.PreAuthorizedCodeClientAuthentication.(VerifiedPreAuthorizedCode); !ok {
		return RedeemedPreAuthorizedCode{}, fmt.Errorf("issuer: redeem pre-authorized code: needs pre_authorized_code_client_authentication VerifiedPreAuthorizedCode")
	}
	return iss.redeemPreAuthorizedCode(ctx, req, iss.deps.Clock.Now(), clientID)
}

// redeemPreAuthorizedCode is ExchangePreAuthorizedCode's and
// RedeemPreAuthorizedCode's shared redemption: the client and DPoP key,
// the record it consumed, and the authorization_details it minted.
func (iss *Issuer) redeemPreAuthorizedCode(ctx context.Context, req ExchangePreAuthorizedCodeRequest, now time.Time, clientID *string) (RedeemedPreAuthorizedCode, error) {
	if iss.deps.PreAuthorizedCodes == nil {
		return RedeemedPreAuthorizedCode{}, fmt.Errorf("issuer: exchange pre-authorized code: the pre-authorized_code grant is not configured")
	}
	if req.PreAuthorizedCode == "" {
		return RedeemedPreAuthorizedCode{}, newError(ErrorInvalidTokenRequest, 400, "pre-authorized_code is required", nil)
	}

	// The client, under VerifiedPreAuthorizedCode, and the DPoP proof,
	// verified by the Authorization Server before the code is consumed.
	binding, err := iss.preAuthorizedBinding(req)
	if err != nil {
		return RedeemedPreAuthorizedCode{}, err
	}
	*clientID = binding.ClientID

	requested, err := iss.requestedConfigurations(req.AuthorizationDetails)
	if err != nil {
		return RedeemedPreAuthorizedCode{}, err
	}

	// Everything that depends on the record is checked by the store's
	// Consume, before it consumes the code: a request the code doesn't
	// allow is refused and leaves the code for one it does.
	var authDetails []oid4vci.AuthorizationDetail
	record, err := iss.consumePreAuthorizedCode(ctx, req, func(record PreAuthorizedCodeRecord) error {
		details, refused := iss.acceptPreAuthorizedCode(record, requested, now)
		authDetails = details
		return refused
	})
	if err != nil {
		return RedeemedPreAuthorizedCode{}, err
	}
	return RedeemedPreAuthorizedCode{
		ClientID: binding.ClientID, Subject: record.Subject, Scope: record.Scopes, AuthorizationDetails: authDetails,
		binding: binding, record: record,
	}, nil
}

// preAuthorizedBinding is a Token Request's client and DPoP key, for
// the access token, from req.Verified: with a client under
// VerifiedPreAuthorizedCode, and with none under
// AnonymousPreAuthorizedCode, which refuses one the Authorization
// Server authenticated: the embedder took a request this grant doesn't
// expect.
func (iss *Issuer) preAuthorizedBinding(req ExchangePreAuthorizedCodeRequest) (VerifiedTokenRequest, error) {
	v := req.Verified
	if v == nil || v.DPoPThumbprint == "" {
		return VerifiedTokenRequest{}, fmt.Errorf("issuer: exchange pre-authorized code: needs Verified, with the DPoPThumbprint the Authorization Server verified")
	}
	_, verified := iss.cfg.PreAuthorizedCodeClientAuthentication.(VerifiedPreAuthorizedCode)
	switch {
	case verified && v.ClientID == "":
		return VerifiedTokenRequest{}, fmt.Errorf("issuer: exchange pre-authorized code: VerifiedPreAuthorizedCode needs Verified.ClientID")
	case !verified && v.ClientID != "":
		return VerifiedTokenRequest{}, fmt.Errorf("issuer: exchange pre-authorized code: Verified.ClientID is set, but pre_authorized_code_client_authentication is AnonymousPreAuthorizedCode, which authenticates no client")
	}
	return *v, nil
}

// consumePreAuthorizedCode redeems req's pre-authorized_code against
// PreAuthorizedCodes, with accept checking its record before it's
// consumed, turning a wrong tx_code, too many wrong tx_code attempts,
// or an unknown/used code (ErrPreAuthorizedCodeUnknown) into the right
// Token Error, and any other store error into a plain one (a 500) —
// split out of
// exchangePreAuthorizedCode purely to keep its cognitive complexity
// manageable. The code is looked up under this Issuer's own key, and a
// record another Credential Issuer owns, or one with no Owner under
// AssuranceProduction, is refused before accept, as an unknown code.
// accept's own error is returned as it is. A store that
// reports success without accept having accepted the record is refused
// too, though the code is then spent: none of accept's checks ran.
func (iss *Issuer) consumePreAuthorizedCode(ctx context.Context, req ExchangePreAuthorizedCodeRequest, accept func(PreAuthorizedCodeRecord) error) (PreAuthorizedCodeRecord, error) {
	var refused error
	accepted := false
	key := preAuthorizedCodeKey(iss.storeOwner(), req.PreAuthorizedCode)
	record, wrongAttempts, err := iss.deps.PreAuthorizedCodes.Consume(ctx, key, txCodeHash(req.PreAuthorizedCode, req.TxCode), iss.cfg.Limits.MaxTxCodeAttempts, func(r PreAuthorizedCodeRecord) error {
		if !iss.owns(r.Owner) {
			// The key is bound to this Issuer, so only a store that
			// changed or dropped Owner gets here.
			refused = newError(ErrorInvalidGrant, 400, "pre-authorized_code is unknown or already used", errors.New("the code's record isn't this Credential Issuer's"))
			return refused
		}
		refused = accept(r)
		accepted = refused == nil
		return refused
	})
	if err == nil && !accepted {
		return PreAuthorizedCodeRecord{}, fmt.Errorf("issuer: exchange pre-authorized code: dependencies.pre_authorized_codes consumed the code without calling accept")
	}
	if err != nil {
		if refused != nil && errors.Is(err, refused) {
			return PreAuthorizedCodeRecord{}, refused
		}
		if errors.Is(err, ErrTxCodeRequired) {
			return PreAuthorizedCodeRecord{}, newError(ErrorInvalidTokenRequest, 400, "tx_code is required", err)
		}
		if errors.Is(err, ErrTxCodeUnexpected) {
			return PreAuthorizedCodeRecord{}, newError(ErrorInvalidTokenRequest, 400, "tx_code was not expected", err)
		}
		if errors.Is(err, ErrTooManyTxCodeAttempts) {
			return PreAuthorizedCodeRecord{}, newError(ErrorInvalidGrant, 400, "too many incorrect tx_code attempts; pre-authorized_code is no longer valid", err)
		}
		if errors.Is(err, ErrWrongTxCode) {
			if wrongAttempts >= iss.cfg.Limits.MaxTxCodeAttempts {
				// Too many wrong guesses against this one code — close
				// the guessing window rather than leaving it retryable
				// forever (see ExchangePreAuthorizedCode's own doc comment).
				if invalidateErr := iss.deps.PreAuthorizedCodes.Invalidate(ctx, key); invalidateErr != nil {
					return PreAuthorizedCodeRecord{}, fmt.Errorf("issuer: exchange pre-authorized code: invalidate after too many tx_code attempts: %w", invalidateErr)
				}
				return PreAuthorizedCodeRecord{}, newError(ErrorInvalidGrant, 400, "too many incorrect tx_code attempts; pre-authorized_code is no longer valid", err)
			}
			// Deliberately NOT consumed (Consume's own contract) — the
			// Wallet holder gets to retry with the correct PIN instead of
			// the code being permanently destroyed on one mistyped digit.
			if req.TxCode == "" {
				// A store that predates ErrTxCodeRequired: still a missing
				// tx_code, not a wrong one (§6.3).
				return PreAuthorizedCodeRecord{}, newError(ErrorInvalidTokenRequest, 400, "tx_code is required", err)
			}
			return PreAuthorizedCodeRecord{}, newError(ErrorInvalidGrant, 400, "tx_code does not match", err)
		}
		if errors.Is(err, ErrPreAuthorizedCodeUnknown) {
			return PreAuthorizedCodeRecord{}, newError(ErrorInvalidGrant, 400, "pre-authorized_code is unknown or already used", err)
		}
		return PreAuthorizedCodeRecord{}, fmt.Errorf("issuer: exchange pre-authorized code: dependencies.pre_authorized_codes: %w", err)
	}
	return record, nil
}

// requestedConfigurations checks a Token Request's authorization_details
// by their form, before the code is consumed, and returns the
// configurations they name (nil for none): openid_credential entries
// for configurations this issuer supports, each once, with no
// credential_identifiers (the Authorization Server's to mint), and
// locations, if any, including this Credential Issuer.
func (iss *Issuer) requestedConfigurations(details []oid4vci.AuthorizationDetail) ([]string, error) {
	if len(details) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(details))
	for i, d := range details {
		var problem string
		switch _, supported := iss.cfg.CredentialConfigurationsSupported[d.CredentialConfigurationID]; {
		case d.Type != oid4vci.AuthorizationDetailsTypeOpenIDCredential:
			problem = fmt.Sprintf("type %q isn't %q", d.Type, oid4vci.AuthorizationDetailsTypeOpenIDCredential)
		case !supported:
			problem = fmt.Sprintf("credential_configuration_id %q isn't supported", d.CredentialConfigurationID)
		case slices.Contains(ids, d.CredentialConfigurationID):
			problem = fmt.Sprintf("credential_configuration_id %q is requested twice", d.CredentialConfigurationID)
		case len(d.CredentialIdentifiers) > 0:
			problem = "credential_identifiers are the Authorization Server's to issue"
		case len(d.Locations) > 0 && !slices.Contains(d.Locations, iss.cfg.Issuer.String()):
			problem = "locations doesn't include this Credential Issuer"
		}
		if problem != "" {
			return nil, newError(ErrorInvalidAuthorizationDetails, 400, fmt.Sprintf("authorization_details[%d]: %s", i, problem), nil)
		}
		ids = append(ids, d.CredentialConfigurationID)
	}
	return ids, nil
}

// acceptPreAuthorizedCode checks a pre-authorized code's record against
// the request before the store consumes the code — it hasn't expired,
// and grants every configuration requested (requestedConfigurations's
// result, nil for none) — and mints the authorization_details for the
// token: one per requested configuration or, with none requested, per
// the record's CredentialConfigurationIDs.
func (iss *Issuer) acceptPreAuthorizedCode(record PreAuthorizedCodeRecord, requested []string, now time.Time) ([]oid4vci.AuthorizationDetail, error) {
	if now.After(record.ExpiresAt) {
		return nil, newError(ErrorInvalidGrant, 400, "pre-authorized_code has expired", nil)
	}
	mint := record.CredentialConfigurationIDs
	if requested != nil {
		for _, id := range requested {
			if !iss.recordGrants(record, id) {
				return nil, newError(ErrorInvalidAuthorizationDetails, 400, fmt.Sprintf("the pre-authorized_code doesn't grant %q", id), nil)
			}
		}
		mint = requested
	}
	if len(mint) == 0 {
		return nil, nil
	}
	details, err := iss.mintAuthorizationDetails(mint)
	if err != nil {
		return nil, fmt.Errorf("issuer: exchange pre-authorized code: %w", err)
	}
	return details, nil
}

// recordGrants reports whether a pre-authorized code's record grants
// configuration id: by its credential identifiers, or its scope.
func (iss *Issuer) recordGrants(record PreAuthorizedCodeRecord, id string) bool {
	if slices.Contains(record.CredentialConfigurationIDs, id) {
		return true
	}
	scope := iss.cfg.CredentialConfigurationsSupported[id].Scope
	return scope != "" && slices.Contains(record.Scopes, scope)
}

// mintAuthorizationDetails builds one AuthorizationDetail per configID,
// each with a single freshly generated credential_identifier (§6.2).
// Every configID is checked against Config.CredentialConfigurationsSupported
// first — a PreAuthorizedCodeRecord naming one this issuer doesn't
// actually support is this deployment's own bug, not anything the
// Wallet did wrong, so this returns a plain error rather than a
// wallet-facing *Error.
func (iss *Issuer) mintAuthorizationDetails(configIDs []string) ([]oid4vci.AuthorizationDetail, error) {
	details := make([]oid4vci.AuthorizationDetail, len(configIDs))
	for i, configID := range configIDs {
		if _, ok := iss.cfg.CredentialConfigurationsSupported[configID]; !ok {
			return nil, fmt.Errorf("credential_configuration_id %q is not supported", configID)
		}
		identifier, err := randomID(iss.deps.Random, nonceEntropyBytes)
		if err != nil {
			return nil, fmt.Errorf("generate credential_identifier: %w", err)
		}
		details[i] = oid4vci.AuthorizationDetail{
			Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: configID,
			CredentialIdentifiers: []string{identifier},
		}
		if len(iss.cfg.AuthorizationServers) > 0 {
			// §5.1.1: with authorization_servers in the metadata, locations
			// "MUST be set to the Credential Issuer Identifier value".
			details[i].Locations = []string{iss.cfg.Issuer.String()}
		}
	}
	return details, nil
}
