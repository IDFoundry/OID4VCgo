package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The Pre-Authorized Code Flow (OID4VCI 1.0 §3.5) and Credential Offers
// (§4.1), on when Config.Offers is set: see its doc comment.

// preAuthorizedCodeGrantType is the pre-authorized code grant's
// grant_type (OID4VCI 1.0 §3.5).
const preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// credentialOfferPath is the Credential Offer Endpoint (§4.1.3) under
// the Credential Issuer's identifier: a by-reference offer's
// credential_offer_uri is this plus the offer's reference.
const credentialOfferPath = "/credential-offer"

// offerLifetime bounds both an offer's pre-authorized code and how long
// a by-reference offer stays fetchable.
const offerLifetime = 10 * time.Minute

// maxTxCodeAttempts is how many wrong Transaction Codes a
// pre-authorized code survives.
const maxTxCodeAttempts = 3

// Bounds on the openid_credential authorization_details a pre-authorized
// code's token carries: one entry per offered configuration.
const (
	maxCredentialAuthorizationDetails = 2
	maxAuthorizationDetailBytes       = 4 << 10
	maxAuthorizationDetailsBytes      = maxCredentialAuthorizationDetails * maxAuthorizationDetailBytes
	maxAuthorizationDetailsDepth      = 4
)

// credentialAuthorizationDetail is the openid_credential
// authorization_details type (§5.1.1).
var credentialAuthorizationDetail = oid4vci.AuthorizationDetailRARDefinition(maxCredentialAuthorizationDetails, maxAuthorizationDetailBytes)

// credentialAuthorizationDetails registers openid_credential
// authorization_details with the Authorization Server, for the tokens
// that carry them (§6.2): a pre-authorized code's, minted with
// credential_identifiers or redeemed with a Token Request naming
// configurations in authorization_details (§6.1.1), and, under
// Config.AuthorizationDetails, an authorization code's whose PAR
// requested them (§5.1.1). fapigo/server issues no token carrying a
// type Config.RAR doesn't register.
func credentialAuthorizationDetails() (*extension.RARRegistry, error) {
	return extension.NewRARRegistry(maxAuthorizationDetailsBytes, maxAuthorizationDetailsDepth, credentialAuthorizationDetail)
}

// grantCredentialAuthorizationDetails grants each openid_credential
// object an authorization request carried, with a credential_identifier
// the consent mints for it (§6.2): the type's ValidateGrant allows that
// addition, and its ValidateRequest refused a Wallet's own. The
// identifier names the configuration's dataset for the token's subject;
// this binary issues one fixed dataset per configuration.
func grantCredentialAuthorizationDetails(requested extension.RARValues) ([]json.RawMessage, error) {
	details, err := extension.RARGet(requested, credentialAuthorizationDetail)
	if err != nil {
		return nil, err
	}
	granted := make([]json.RawMessage, 0, len(details))
	for _, d := range details {
		detail := d.Fields
		id, err := randomValue()
		if err != nil {
			return nil, err
		}
		detail.Type = oid4vci.AuthorizationDetailsTypeOpenIDCredential
		detail.CredentialIdentifiers = []string{id}
		raw, err := json.Marshal(detail)
		if err != nil {
			return nil, err
		}
		granted = append(granted, raw)
	}
	return granted, nil
}

// preAuthorizedTokenHandler redeems a pre-authorized code and its
// Transaction Code. The Authorization Server authenticates the Wallet by
// its Wallet Attestation (HAIP 1.0 §4.4.1) and verifies the DPoP proof
// under the same replay record and nonce policy as its own grants
// (issuer.VerifiedPreAuthorizedCode); the issuer then redeems the code,
// and the Authorization Server issues the access token, so the
// Credential Endpoint verifies it as it does any other.
func preAuthorizedTokenHandler(srv *server.Server, iss *issuer.Issuer) func(http.ResponseWriter, *http.Request, server.TokenEndpointRequest) {
	return func(w http.ResponseWriter, r *http.Request, req server.TokenEndpointRequest) {
		ctx := r.Context()
		params, err := req.Parameters()
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		attested, err := srv.AuthenticateAttestedClient(ctx, req.AttestedClientAuthentication())
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		binding, err := srv.VerifyTokenRequestBinding(ctx, attested.Client, req)
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		if binding.SenderConstrain != storage.SenderConstrainDPoP {
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, "this grant issues DPoP-bound tokens only")
			return
		}
		details, err := issuer.ParseAuthorizationDetails(params["authorization_details"])
		if err != nil {
			writeIssuerTokenError(w, err)
			return
		}
		redeemed, err := iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"], AuthorizationDetails: details,
			Verified: &issuer.VerifiedTokenRequest{ClientID: attested.Client.ID().String(), DPoPThumbprint: binding.Thumbprint},
		})
		if err != nil {
			writeIssuerTokenError(w, err)
			return
		}
		grant, err := preAuthorizedGrant(attested, binding, redeemed)
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		result, err := srv.IssueAccessToken(ctx, grant)
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		result.WriteJSON(w)
	}
}

// preAuthorizedGrant is a redeemed pre-authorized code's grant: what the
// code granted, to the client and DPoP key the Token Request verified.
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
		Scope: redeemed.Scope, AuthorizationDetails: details,
	}, nil
}

// writeIssuerTokenError writes an issuer Token Endpoint error (an
// *issuer.Error writes its own OAuth error), or a 500 for anything else.
func writeIssuerTokenError(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	issuer.WriteError(w, err)
}

// credentialOfferHandler serves the Credential Offer Endpoint (§4.1.3):
// GET credentialOfferPath/{reference} answers with the offer it
// references, while it hasn't expired.
func credentialOfferHandler(iss *issuer.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		offer, err := iss.GetCredentialOffer(r.Context(), r.PathValue("reference"))
		if err != nil {
			http.Error(w, "unknown or expired credential offer", http.StatusNotFound)
			return
		}
		issuer.WriteCredentialOfferJSON(w, offer)
	}
}

// offerRequest is what POST /offers takes.
type offerRequest struct {
	// Grant is "pre-authorized_code" or "authorization_code".
	Grant string `json:"grant"`
	// CredentialConfigurationIDs are the offered configurations.
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`
	// TxCode, for a pre-authorized code, is the Transaction Code it's
	// redeemed with: none when empty.
	TxCode string `json:"tx_code,omitempty"`
	// CredentialIdentifiers, for a pre-authorized code, has its token
	// carry a credential_identifier per configuration (§6.2).
	CredentialIdentifiers bool `json:"credential_identifiers,omitempty"`
	// ByReference serves the offer at the Credential Offer Endpoint and
	// returns a credential_offer_uri (§4.1.3) instead of the offer by
	// value.
	ByReference bool `json:"by_reference,omitempty"`
}

// offerResponse is what POST /offers answers.
type offerResponse struct {
	// URI is the openid-credential-offer:// deep link (§4.1.2).
	URI string `json:"uri"`
	// IssuerState is an authorization code offer's issuer_state.
	IssuerState string `json:"issuer_state,omitempty"`
}

// hasUnknownMembers reports whether body, a JSON offerRequest, has a
// member offerRequest doesn't define: a misspelled option is refused,
// not ignored.
func hasUnknownMembers(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(&offerRequest{}) != nil
}

// maxOfferRequestBytes bounds a POST /offers body.
const maxOfferRequestBytes = 4 << 10

// offersHandler mints Credential Offers on POST /offers, standing in for
// the issuer's own business process (a counter, an enrolment portal) a
// real issuer would offer credentials from. It's served on its own
// loopback listener (Config.Offers.ListenAddr), never with the
// Credential Issuer's endpoints: whoever reaches it gets an offer.
func offersHandler(iss *issuer.Issuer, cfg Config) http.Handler {
	scopes := map[string]string{cfg.CredentialConfigurationID: cfg.Scope}
	if cfg.Mdoc != nil {
		scopes[cfg.Mdoc.CredentialConfigurationID] = cfg.Mdoc.Scope
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /offers", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOfferRequestBytes))
		var req offerRequest
		if err != nil || strictjson.Unmarshal(body, &req) != nil || hasUnknownMembers(body) {
			http.Error(w, "malformed offer request", http.StatusBadRequest)
			return
		}
		resp, err := mintOffer(r, iss, scopes, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

// mintOffer creates the offer req asks for.
func mintOffer(r *http.Request, iss *issuer.Issuer, scopes map[string]string, req offerRequest) (offerResponse, error) {
	if len(req.CredentialConfigurationIDs) == 0 {
		return offerResponse{}, errors.New("credential_configuration_ids is required")
	}
	var offerScopes []string
	for _, id := range req.CredentialConfigurationIDs {
		scope, ok := scopes[id]
		if !ok {
			return offerResponse{}, fmt.Errorf("unknown credential_configuration_id %q", id)
		}
		offerScopes = append(offerScopes, scope)
	}
	switch req.Grant {
	case "pre-authorized_code":
		subject, err := randomValue()
		if err != nil {
			return offerResponse{}, err
		}
		result, err := iss.CreatePreAuthorizedOffer(r.Context(), issuer.CreatePreAuthorizedOfferRequest{
			CredentialConfigurationIDs: req.CredentialConfigurationIDs, Scopes: offerScopes,
			CredentialIdentifiers: req.CredentialIdentifiers, Subject: subject,
			TxCode: req.TxCode, NoTxCode: req.TxCode == "", Lifetime: offerLifetime, ByReference: req.ByReference,
		})
		if err != nil {
			return offerResponse{}, err
		}
		return offerResponse{URI: result.URI}, nil
	case "authorization_code":
		if req.TxCode != "" || req.CredentialIdentifiers {
			return offerResponse{}, errors.New("tx_code and credential_identifiers are for a pre-authorized code")
		}
		state, err := randomValue()
		if err != nil {
			return offerResponse{}, err
		}
		result, err := iss.CreateCredentialOffer(r.Context(), issuer.CreateCredentialOfferRequest{
			CredentialConfigurationIDs: req.CredentialConfigurationIDs,
			Grants:                     &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: state}},
			ByReference:                req.ByReference,
		})
		if err != nil {
			return offerResponse{}, err
		}
		return offerResponse{URI: result.URI, IssuerState: state}, nil
	default:
		return offerResponse{}, errors.New(`grant must be "pre-authorized_code" or "authorization_code"`)
	}
}

// randomValue is 128 random bits, hex-encoded: a pre-authorized code's
// subject, or an offer's issuer_state.
func randomValue() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
