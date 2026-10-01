package wallet

import (
	"encoding/json"
	"fmt"
	"slices"
)

// dcAPIResponseMode is the only Response Mode a DC API request may ask
// for here: HAIP 1.0 requires the encrypted response (dc_api.jwt).
const dcAPIResponseMode = "dc_api.jwt"

// ParseDCAPIRequestParams is the input to ParseDCAPIRequest.
type ParseDCAPIRequestParams struct {
	// Request is REQUIRED: the signed Request Object, the "request"
	// member of the DC API request's data (OID4VP Appendix A.3.2.1,
	// JWS Compact Serialization).
	Request string

	// Origin is REQUIRED: the origin of the page or app that called the
	// DC API, as the platform reports it — Android Credential Manager's
	// calling origin, for instance. Never take it from the request
	// itself, or from anything the caller supplies: it's what keeps a
	// request one Verifier built from being replayed by another site.
	Origin string

	// VerifierTrust decides whether to trust the certificate chain the
	// Request Object is signed with (OID4VP §5.9.3). REQUIRED — pass
	// NoVerifierTrust{} to opt out explicitly.
	VerifierTrust VerifierTrust
}

// ParseDCAPIRequest verifies a signed OpenID4VP request delivered
// through the Digital Credentials API (OID4VP Appendix A) and returns
// its claims, with Origin set and no ResponseURI or State.
//
// It checks the Request Object as ParseAuthorizationRequest does — its
// x5c chain with params.VerifierTrust, its signature, and that its
// client_id is the x509_hash of the signing certificate — and then
// what the DC API adds: response_type must be vp_token, response_mode
// dc_api.jwt, and
// params.Origin must be one of the request's expected_origins
// (Appendix A.2: "If the Origin does not match any of the entries in
// expected_origins, the Wallet MUST return an error"). A request
// carrying transaction_data is refused with a *RequestRejectedError,
// as ParseAuthorizationRequest refuses it.
//
// Answer it with PresentCredentials, setting PresentationRequest.Origin
// to the returned Origin (it binds the presentations to it, Appendix
// A.4), encrypt the vp_token with BuildDirectPostResponse, and return
// {"response": <that JWE>} to the platform as the DC API response.
// Only signed requests are accepted: an unsigned one (Appendix A.3.1)
// can't be tied to a Verifier.
//
// Prefer (*Wallet).ParseDCAPIRequest, which uses Config.VerifierTrust,
// so AssuranceProduction's refusal of NoVerifierTrust applies.
func ParseDCAPIRequest(params ParseDCAPIRequestParams) (AuthorizationRequest, error) {
	if params.Origin == "" {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: Origin is required")
	}
	cert, clientID, payload, err := verifyRequestObject(params.Request, params.VerifierTrust)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: %w", err)
	}
	var wire wireRequestObjectPayload
	if err := json.Unmarshal(payload, &wire); err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: parse payload: %w", err)
	}
	switch {
	case wire.ClientID != clientID:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: client_id %q does not match x5c leaf's own x509_hash %q", wire.ClientID, clientID)
	case wire.ResponseType != vpTokenResponseType:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: response_type %q, want %q", wire.ResponseType, vpTokenResponseType)
	case wire.ResponseMode != dcAPIResponseMode:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: response_mode %q, want %q", wire.ResponseMode, dcAPIResponseMode)
	case len(wire.ExpectedOrigins) == 0:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: expected_origins is required for a signed request")
	case !slices.Contains(wire.ExpectedOrigins, params.Origin):
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: origin %q is not in expected_origins", params.Origin)
	case wire.Nonce == "":
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: nonce is required")
	}
	encPub, kid, enc, err := responseEncryption(wire.ClientMetadata)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: %w", err)
	}
	if len(wire.TransactionData) > 0 {
		return AuthorizationRequest{}, &RequestRejectedError{
			Code:                  "invalid_transaction_data",
			Description:           "transaction_data is present but this Wallet recognizes no transaction_data type",
			ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
			op: "parse dc api request",
		}
	}
	return AuthorizationRequest{
		ClientID: clientID, Nonce: wire.Nonce, Query: wire.DCQLQuery, VerifierCertificate: cert,
		ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
		Origin: params.Origin,
	}, nil
}

// ParseDCAPIRequest is the package-level ParseDCAPIRequest with this
// Wallet's Config.VerifierTrust, which New refuses to be NoVerifierTrust
// under AssuranceProduction. request is the "request" member of the DC
// API request's data; origin is the calling origin the platform reports.
func (w *Wallet) ParseDCAPIRequest(request, origin string) (AuthorizationRequest, error) {
	if w.cfg.VerifierTrust == nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: Config.VerifierTrust is required (NoVerifierTrust{} opts out explicitly)")
	}
	return ParseDCAPIRequest(ParseDCAPIRequestParams{Request: request, Origin: origin, VerifierTrust: w.cfg.VerifierTrust})
}
