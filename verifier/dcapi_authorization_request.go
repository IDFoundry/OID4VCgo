package verifier

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// dcAPIResponseMode is the Response Mode every BuildDCAPIAuthorizationRequest
// call uses — HAIP 1.0 §5.2's own mandatory encryption for the DC API
// flow ("The Wallet MUST support the Response Mode dc_api.jwt. The
// Verifier MUST use the Response Mode dc_api.jwt."), the DC API's own
// counterpart to BuildAuthorizationRequest's "direct_post.jwt".
const dcAPIResponseMode = "dc_api.jwt"

// BuildDCAPIAuthorizationRequestRequest is the input to
// BuildDCAPIAuthorizationRequest.
type BuildDCAPIAuthorizationRequestRequest struct {
	// Query is REQUIRED: the DCQL query (§6) describing the
	// Credential(s)/claims being requested.
	Query dcql.Query

	// ExpectedOrigins is REQUIRED (Appendix A.2): a non-empty array of
	// Origin(s) this Verifier's own request is valid for. "The Wallet
	// MUST compare values in this parameter to the Origin to detect
	// replay of the request from a malicious Verifier. If the Origin
	// does not match any of the entries in expected_origins, the
	// Wallet MUST return an error." — required specifically for
	// signed requests (this package's only kind), never meaningful
	// for the unsigned requests this package doesn't build.
	ExpectedOrigins []string

	// State is OPTIONAL — accepted for symmetry with
	// BuildAuthorizationRequest, but Appendix A.2's own "since the
	// state parameter is not defined for the DC API, the Verifier
	// cannot expect it to be included in the response" means a caller
	// gets nothing back for setting it; a Wallet is free to ignore it
	// entirely (unrecognized-parameter handling, Appendix A.2's own
	// closing MUST).
	State string
}

// BuildDCAPIAuthorizationRequestResult is returned by a successful
// BuildDCAPIAuthorizationRequest.
type BuildDCAPIAuthorizationRequestResult struct {
	// RequestObject is the signed JWS (JWS Compact Serialization,
	// Appendix A.3.2.1) — what a caller passes as the "request" member
	// of the DC API's own data object. This package doesn't invoke the
	// DC API itself — see the package doc comment.
	RequestObject string

	// ClientID is this Verifier's own "x509_hash:..." Client
	// Identifier.
	ClientID string

	// Nonce is the fresh nonce baked into the Request Object.
	Nonce string

	// ResponseDecryptionKey is the ephemeral P-256 private key
	// generated for this one request's own response encryption — the
	// caller must retain it to decrypt the eventual dc_api.jwt
	// response.
	ResponseDecryptionKey *ecdsa.PrivateKey
}

// BuildDCAPIAuthorizationRequest builds a signed OpenID4VP request for
// use with the Digital Credentials API (Appendix A.3.2.1, JWS Compact
// Serialization): "response_type":"vp_token",
// "response_mode":"dc_api.jwt" (HAIP §5.2's own mandatory encryption),
// the "x509_hash" Client Identifier Prefix (the only one this package
// supports, same as BuildAuthorizationRequest), a fresh "nonce",
// req.Query as "dcql_query", req.ExpectedOrigins as "expected_origins",
// and a "client_metadata" advertising a fresh ephemeral P-256 ECDH-ES
// response-encryption key plus Config.EncValuesSupported.
//
// Unlike BuildAuthorizationRequest, there is no "response_uri" —
// Appendix A.2's own supported-parameter list for the DC API drops it
// entirely, since the response comes back through the DC API's own
// platform transport, never an HTTP POST to a Verifier-controlled
// endpoint.
//
// It doesn't invoke the Digital Credentials API itself, parse a
// response, or do anything past building and signing — see the
// package doc comment for what's still missing (multi-signed JWS JSON
// Serialization requests, Appendix A.3.2.2, and unsigned requests,
// Appendix A.3.1, are both deliberately not offered — this package
// builds signed requests exclusively, the same posture
// BuildAuthorizationRequest already takes for the redirect flow).
func (v *Verifier) BuildDCAPIAuthorizationRequest(req BuildDCAPIAuthorizationRequestRequest) (BuildDCAPIAuthorizationRequestResult, error) {
	if err := req.Query.Validate(); err != nil {
		return BuildDCAPIAuthorizationRequestResult{}, fmt.Errorf("verifier: build dc api authorization request: dcql_query: %w", err)
	}
	if len(req.ExpectedOrigins) == 0 {
		return BuildDCAPIAuthorizationRequestResult{}, fmt.Errorf("verifier: build dc api authorization request: expected_origins must be non-empty")
	}

	nonce, err := randomToken(v.deps.Random)
	if err != nil {
		return BuildDCAPIAuthorizationRequestResult{}, fmt.Errorf("verifier: build dc api authorization request: generate nonce: %w", err)
	}
	clientMetadata, encKey, err := v.buildResponseEncryptionMetadata()
	if err != nil {
		return BuildDCAPIAuthorizationRequestResult{}, fmt.Errorf("verifier: build dc api authorization request: %w", err)
	}

	payload := map[string]any{
		"iss":              v.clientID,
		"aud":              selfIssuedAudience,
		"response_type":    "vp_token",
		"response_mode":    dcAPIResponseMode,
		"client_id":        v.clientID,
		"expected_origins": req.ExpectedOrigins,
		"nonce":            nonce,
		"dcql_query":       req.Query,
		"client_metadata":  clientMetadata,
	}
	if req.State != "" {
		payload["state"] = req.State
	}

	requestObject, err := v.signRequestObject(payload)
	if err != nil {
		return BuildDCAPIAuthorizationRequestResult{}, fmt.Errorf("verifier: build dc api authorization request: %w", err)
	}
	return BuildDCAPIAuthorizationRequestResult{
		RequestObject: requestObject, ClientID: v.clientID, Nonce: nonce, ResponseDecryptionKey: encKey,
	}, nil
}
