package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// ResponseError is a Wallet's own error response (§8.1) — sent instead
// of a vp_token, e.g. when it can't satisfy the Authorization
// Request's own dcql_query.
//
// An error response is unauthenticated: it carries no Holder Binding,
// and anyone who has the request's public encryption key (published in
// its client_metadata) and state can send one. Treat it as information,
// not as the end of the request — a Verifier that closes a request on
// the first error response lets anyone cancel any request it has
// published.
type ResponseError struct {
	// Code is the response's own "error" value (RFC 6749 §5.2 error
	// codes, extended by this specification's own — e.g.
	// "access_denied", "invalid_request").
	Code string

	// Description is the response's own "error_description", if any.
	Description string

	// State is the response's own "state", when present — the same
	// value BuildAuthorizationRequestRequest.State carried, if any.
	State string
}

func (e *ResponseError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("verifier: wallet returned error %q: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("verifier: wallet returned error %q", e.Code)
}

// ParsedResponse is a direct_post.jwt response's own decrypted payload
// (§8.1).
type ParsedResponse struct {
	// VPToken maps each dcql.CredentialQuery.ID to the Presentation(s)
	// matched against it — a compact SD-JWT+KB string for "dc+sd-jwt",
	// a base64url-encoded DeviceResponse for "mso_mdoc" (both formats
	// VerifyResponse verifies — see the package doc comment). A
	// Credential Query with no match at all (legal only when it's
	// non-required) has no entry here (§8.1's own "omit the key
	// entirely" rule).
	//
	// A DC API answer (dc_api.jwt) is parsed by
	// ParseDirectPostJWTResponse too, as HandleDCAPIResponse does; a
	// caller building this struct itself gets no size bound from a JWE
	// decrypt. VerifyResponse is safe either way:
	// sdjwtvc.Parse/oid4vpmdoc.UnmarshalDeviceResponse each reject an
	// oversized entry (sdjwtvc.MaxBytes/oid4vpmdoc.MaxBytes) before
	// doing any real parsing work on it, regardless of which flow
	// populated this field.
	VPToken map[string][]string

	// State is the response's own "state", when present.
	State string
}

// ParseDirectPostJWTResponse decrypts responseJWE — the direct_post.jwt
// response's own "response" form parameter — using decryptionKey (the
// ResponseDecryptionKey a prior BuildAuthorizationRequest call
// returned for this same request) and parses the resulting plaintext
// per §8.1. Returns a *ResponseError when the Wallet reported an error
// instead of a vp_token (see ResponseError for why that alone must not
// end the request).
//
// vp_token is decoded member by member, and refused at the first that
// makes it one no query answers: one of more than
// dcql.MaxCredentialQueries ids, or of more than
// MaxPresentationsPerQuery presentations.
//
// Transactions.HandleResponse calls this for each answer, refusing
// too, at the first, an id that isn't one of the request's query's;
// call it directly only for flows Transactions doesn't cover.
func (v *Verifier) ParseDirectPostJWTResponse(responseJWE string, decryptionKey *ecdsa.PrivateKey) (ParsedResponse, error) {
	return v.parseDirectPostJWTResponse(responseJWE, decryptionKey, nil)
}

// parseDirectPostJWTResponse is ParseDirectPostJWTResponse, refusing,
// when query isn't nil, a vp_token member whose id isn't one of its
// Credential Queries'.
func (v *Verifier) parseDirectPostJWTResponse(responseJWE string, decryptionKey *ecdsa.PrivateKey, query *dcql.Query) (ParsedResponse, error) {
	// A compressed response is refused before decryption: this Verifier
	// never offers compression, and anyone who sees the Request Object
	// can encrypt to its response key, so inflating one would let an
	// unauthenticated sender make it allocate far more than it sent.
	if decryptionKey == nil {
		return ParsedResponse{}, errors.New("verifier: parse direct_post.jwt response: a decryption key is required")
	}
	// From here on, a failure is the response's: a *Error, ReasonMalformed.
	header, err := jwe.DecodeHeader(responseJWE)
	if err != nil {
		return ParsedResponse{}, newError(ReasonMalformed, "parse direct_post.jwt response: decode header", err)
	}
	if _, compressed := header["zip"]; compressed {
		return ParsedResponse{}, newError(ReasonMalformed, "parse direct_post.jwt response: a compressed (zip) response is not accepted", nil)
	}
	// Only a content encryption this Verifier offered in
	// encrypted_response_enc_values_supported (OpenID4VP §8.3).
	// Its value isn't echoed: the header is the sender's.
	if enc, _ := header["enc"].(string); !slices.Contains(v.cfg.EncValuesSupported, oid4vci.JWEEnc(enc)) {
		return ParsedResponse{}, newError(ReasonMalformed, "parse direct_post.jwt response: its enc isn't one this Verifier offered", nil)
	}
	plaintext, err := jwe.Decrypt(decryptionKey, responseJWE)
	if err != nil {
		return ParsedResponse{}, newError(ReasonMalformed, "parse direct_post.jwt response: decrypt", err)
	}

	var wire struct {
		VPToken          json.RawMessage `json:"vp_token"`
		State            string          `json:"state"`
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
	}
	if err := strictjson.Unmarshal(plaintext, &wire); err != nil {
		return ParsedResponse{}, newError(ReasonMalformed, "parse direct_post.jwt response: unmarshal", err)
	}
	vpToken, err := decodeVPToken(wire.VPToken, query)
	if err != nil {
		return ParsedResponse{}, err
	}
	if wire.Error != "" {
		return ParsedResponse{}, &ResponseError{Code: wire.Error, Description: wire.ErrorDescription, State: wire.State}
	}
	if len(vpToken) == 0 {
		return ParsedResponse{}, newError(ReasonMalformed, "parse direct_post.jwt response: vp_token is missing or empty", nil)
	}
	return ParsedResponse{VPToken: vpToken, State: wire.State}, nil
}

// decodeVPToken decodes raw, a vp_token strictjson has checked, as
// encoding/json would into a map[string][]string, member by member: it
// refuses, at the first, an id that isn't one of query's Credential
// Queries (when query isn't nil), more ids than
// dcql.MaxCredentialQueries, and more presentations for one than
// MaxPresentationsPerQuery, each of which VerifyResponse would refuse
// later, so that an answer of many members costs no more than the
// first that refuses it.
func decodeVPToken(raw json.RawMessage, query *dcql.Query) (map[string][]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	malformed := func(err error) error {
		return newError(ReasonMalformed, "parse direct_post.jwt response: vp_token", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil {
		return nil, malformed(err)
	} else if tok != json.Delim('{') {
		return nil, malformed(errors.New("it isn't an object"))
	}
	vpToken := map[string][]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, malformed(err)
		}
		id, _ := tok.(string)
		switch {
		case query != nil && !slices.ContainsFunc(query.Credentials, func(cq dcql.CredentialQuery) bool { return cq.ID == id }):
			return nil, newError(ReasonNotAnswered, "parse direct_post.jwt response: vp_token answers a credential query the request doesn't make", nil)
		case len(vpToken) == dcql.MaxCredentialQueries:
			return nil, malformed(fmt.Errorf("more than %d credential queries answered", dcql.MaxCredentialQueries))
		}
		presentations, err := decodePresentations(dec)
		if err != nil {
			return nil, malformed(err)
		}
		vpToken[id] = presentations
	}
	return vpToken, nil
}

// decodePresentations decodes the next value of dec, one vp_token
// member's, as encoding/json would into a []string, refusing it at
// the first presentation over MaxPresentationsPerQuery.
func decodePresentations(dec *json.Decoder) ([]string, error) {
	tok, err := dec.Token()
	switch {
	case err != nil:
		return nil, err
	case tok == nil:
		return nil, nil // null
	case tok != json.Delim('['):
		return nil, errors.New("a member isn't an array")
	}
	presentations := []string{}
	for dec.More() {
		if len(presentations) == MaxPresentationsPerQuery {
			return nil, fmt.Errorf("more than %d presentations for one credential query", MaxPresentationsPerQuery)
		}
		var p string
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		presentations = append(presentations, p)
	}
	_, err = dec.Token() // ']'
	return presentations, err
}
