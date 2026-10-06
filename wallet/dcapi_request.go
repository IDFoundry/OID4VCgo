package wallet

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// dcAPIResponseMode is the only Response Mode a DC API request may ask
// for here: HAIP 1.0 requires the encrypted response (dc_api.jwt).
const dcAPIResponseMode = "dc_api.jwt"

// dcAPIParseOp names the DC API parsers in a RequestRejectedError.
const dcAPIParseOp = "parse dc api request"

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
// It takes only the JWS Compact form; ParseDCAPIRequestData takes the
// DC API request as delivered, in any of the three forms.
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
	if wire.ClientID != clientID {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: client_id %q does not match x5c leaf's own x509_hash %q", wire.ClientID, clientID)
	}
	return finishDCAPIRequest(wire, params.Origin, cert, clientID, true)
}

// finishDCAPIRequest checks what every DC API request must carry and
// builds its AuthorizationRequest: response_type vp_token,
// response_mode dc_api.jwt, a nonce and a response encryption key, and,
// for a signed request, origin among its expected_origins. An unsigned
// request's expected_origins is ignored (Appendix A.2).
func finishDCAPIRequest(wire wireRequestObjectPayload, origin string, cert *x509.Certificate, clientID string, signed bool) (AuthorizationRequest, error) {
	switch {
	case wire.ResponseType != vpTokenResponseType:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: response_type %q, want %q", wire.ResponseType, vpTokenResponseType)
	case wire.ResponseMode != dcAPIResponseMode:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: response_mode %q, want %q", wire.ResponseMode, dcAPIResponseMode)
	case signed && len(wire.ExpectedOrigins) == 0:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: expected_origins is required for a signed request")
	case signed && !slices.Contains(wire.ExpectedOrigins, origin):
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: origin %q is not in expected_origins", origin)
	}
	encPub, kid, enc, err := responseEncryption(wire.ClientMetadata)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: %w", err)
	}
	if wire.Nonce == "" {
		// A request from where it claims to be, missing what the answer
		// is bound to: tell the Verifier, as the redirect flow does.
		return AuthorizationRequest{}, &RequestRejectedError{
			Code: "invalid_request", Description: "nonce is required",
			ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
			op: dcAPIParseOp,
		}
	}
	if len(wire.TransactionData) > 0 {
		return AuthorizationRequest{}, &RequestRejectedError{
			Code:                  "invalid_transaction_data",
			Description:           "transaction_data is present but this Wallet recognizes no transaction_data type",
			ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
			op: dcAPIParseOp,
		}
	}
	info, err := parseVerifierInfo(wire.VerifierInfo, wire.DCQLQuery)
	if err != nil {
		return AuthorizationRequest{}, &RequestRejectedError{
			Code: "invalid_request", Description: err.Error(),
			ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
			op: dcAPIParseOp,
		}
	}
	return AuthorizationRequest{
		ClientID: clientID, Nonce: wire.Nonce, Query: wire.DCQLQuery, VerifierCertificate: cert,
		ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
		Origin: origin, VerifierInfo: info,
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

// The DC API protocol identifiers of OpenID4VP's three request forms
// (Appendix A.1), each request's "protocol".
const (
	// DCAPIProtocolUnsigned: the request parameters are data's own
	// members (Appendix A.3.1).
	DCAPIProtocolUnsigned = "openid4vp-v1-unsigned"
	// DCAPIProtocolSigned: data.request is a Request Object in JWS
	// Compact Serialization (Appendix A.3.2.1).
	DCAPIProtocolSigned = "openid4vp-v1-signed"
	// DCAPIProtocolMultiSigned: data.request is a Request Object in JWS
	// JSON Serialization, signed for one or more Client Identifiers
	// (Appendix A.3.2.2).
	DCAPIProtocolMultiSigned = "openid4vp-v1-multisigned"
)

// Limits on what ParseDCAPIRequestData accepts: each signature of a
// multi-signed request costs a certificate chain verification.
const (
	// MaxDCAPIRequestBytes is the largest request data accepted.
	MaxDCAPIRequestBytes = 1 << 20
	// MaxDCAPISignatures is the most signatures a multi-signed request
	// may carry.
	MaxDCAPISignatures = 8
)

// ParseDCAPIRequestDataParams is the input to ParseDCAPIRequestData.
type ParseDCAPIRequestDataParams struct {
	// Protocol is REQUIRED: the request's "protocol", one of the
	// DCAPIProtocol constants.
	Protocol string
	// Data is REQUIRED: the request's "data", as the platform hands it
	// over.
	Data json.RawMessage
	// Origin is REQUIRED: the calling origin the platform reports, as
	// for ParseDCAPIRequestParams.Origin.
	Origin string
	// VerifierTrust decides whether to trust a signed request's
	// certificate chain: REQUIRED for the signed and multi-signed
	// protocols (pass NoVerifierTrust{} to opt out explicitly), unused
	// for the unsigned one.
	VerifierTrust VerifierTrust
}

// ParseDCAPIRequestData parses an OpenID4VP request delivered through
// the Digital Credentials API in any of the three forms a Wallet must
// support (HAIP 1.0 §5.2: "The Wallet MUST support unsigned, signed,
// and multi-signed requests"), and returns it as ParseDCAPIRequest
// does:
//
//   - DCAPIProtocolSigned: ParseDCAPIRequest of data.request.
//   - DCAPIProtocolMultiSigned: data.request's signatures are tried in
//     order, and the first whose x5c chain VerifierTrust accepts and
//     whose signature verifies authenticates the request: its protected
//     header's client_id must be the leaf's x509_hash, and its
//     verifier_info is the request's. client_id and verifier_info may
//     appear only there, never in the payload (Appendix A.3.2.2).
//     Signatures that don't verify are skipped, as long as one does.
//   - DCAPIProtocolUnsigned: data's own members are the request. Its
//     client_id and expected_origins are ignored (Appendix A.2), so the
//     returned AuthorizationRequest has no ClientID or
//     VerifierCertificate: the only thing identifying the Verifier is
//     Origin, which the platform vouches for — show the holder that.
//
// Each is then checked as ParseDCAPIRequest checks a signed request,
// expected_origins excepted for an unsigned one. Answer it the same
// way; the presentations are bound to "origin:" + Origin in every form
// (Appendix A.4).
func ParseDCAPIRequestData(params ParseDCAPIRequestDataParams) (AuthorizationRequest, error) {
	if params.Origin == "" {
		return AuthorizationRequest{}, errors.New("wallet: parse dc api request: Origin is required")
	}
	if len(params.Data) > MaxDCAPIRequestBytes {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: data is %d bytes, more than %d", len(params.Data), MaxDCAPIRequestBytes)
	}
	switch params.Protocol {
	case DCAPIProtocolSigned:
		var data struct {
			Request string `json:"request"`
		}
		if err := json.Unmarshal(params.Data, &data); err != nil || data.Request == "" {
			return AuthorizationRequest{}, errors.New("wallet: parse dc api request: data.request must be a signed Request Object")
		}
		return ParseDCAPIRequest(ParseDCAPIRequestParams{Request: data.Request, Origin: params.Origin, VerifierTrust: params.VerifierTrust})
	case DCAPIProtocolMultiSigned:
		return parseMultiSignedDCAPIRequest(params)
	case DCAPIProtocolUnsigned:
		var wire wireRequestObjectPayload
		if err := json.Unmarshal(params.Data, &wire); err != nil {
			return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: parse data: %w", err)
		}
		return finishDCAPIRequest(wire, params.Origin, nil, "", false)
	default:
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: unsupported protocol %q", params.Protocol)
	}
}

// wireJWSJSON is a JWS in General JWS JSON Serialization (RFC 7515
// §7.2.1).
type wireJWSJSON struct {
	Payload    string `json:"payload"`
	Signatures []struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	} `json:"signatures"`
}

// parseMultiSignedDCAPIRequest is ParseDCAPIRequestData for
// DCAPIProtocolMultiSigned.
func parseMultiSignedDCAPIRequest(params ParseDCAPIRequestDataParams) (AuthorizationRequest, error) {
	var data struct {
		Request wireJWSJSON `json:"request"`
	}
	if err := json.Unmarshal(params.Data, &data); err != nil || data.Request.Payload == "" || len(data.Request.Signatures) == 0 {
		return AuthorizationRequest{}, errors.New("wallet: parse dc api request: data.request must be a Request Object in JWS JSON Serialization")
	}
	if len(data.Request.Signatures) > MaxDCAPISignatures {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: %d signatures, more than %d", len(data.Request.Signatures), MaxDCAPISignatures)
	}
	var errs []error
	for i, sig := range data.Request.Signatures {
		// Each signature over the one payload is a JWS of its own, in
		// Compact Serialization (RFC 7515 §7.2.1, §5.1).
		cert, clientID, payload, err := verifyRequestObject(sig.Protected+"."+data.Request.Payload+"."+sig.Signature, params.VerifierTrust)
		if err != nil {
			errs = append(errs, fmt.Errorf("signature %d: %w", i, err))
			continue
		}
		var header struct {
			ClientID     string          `json:"client_id"`
			VerifierInfo json.RawMessage `json:"verifier_info"`
		}
		raw, err := base64.RawURLEncoding.DecodeString(sig.Protected)
		if err != nil || json.Unmarshal(raw, &header) != nil {
			errs = append(errs, fmt.Errorf("signature %d: malformed protected header", i))
			continue
		}
		if header.ClientID != clientID {
			errs = append(errs, fmt.Errorf("signature %d: client_id %q does not match x5c leaf's own x509_hash %q", i, header.ClientID, clientID))
			continue
		}
		var wire wireRequestObjectPayload
		if err := json.Unmarshal(payload, &wire); err != nil {
			return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: parse payload: %w", err)
		}
		if wire.ClientID != "" || len(wire.VerifierInfo) > 0 {
			return AuthorizationRequest{}, errors.New("wallet: parse dc api request: client_id and verifier_info belong in a multi-signed request's protected headers, not its payload")
		}
		wire.ClientID, wire.VerifierInfo = clientID, header.VerifierInfo
		return finishDCAPIRequest(wire, params.Origin, cert, clientID, true)
	}
	return AuthorizationRequest{}, fmt.Errorf("wallet: parse dc api request: no signature verifies: %w", errors.Join(errs...))
}

// ParseDCAPIRequestData is the package-level ParseDCAPIRequestData with
// this Wallet's Config.VerifierTrust for signed requests. protocol and
// data are the DC API request's; origin is the calling origin the
// platform reports.
func (w *Wallet) ParseDCAPIRequestData(protocol string, data []byte, origin string) (AuthorizationRequest, error) {
	if protocol != DCAPIProtocolUnsigned && w.cfg.VerifierTrust == nil {
		return AuthorizationRequest{}, errors.New("wallet: parse dc api request: Config.VerifierTrust is required (NoVerifierTrust{} opts out explicitly)")
	}
	return ParseDCAPIRequestData(ParseDCAPIRequestDataParams{Protocol: protocol, Data: data, Origin: origin, VerifierTrust: w.cfg.VerifierTrust})
}
