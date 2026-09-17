package wallet

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
)

// ProtectedResourceClient performs a sender-constrained request to a
// protected resource with an already-obtained access token —
// satisfied directly by fapigo/client's own
// (*client.Client).ProtectedResource(tokens).Do, which signs a fresh
// DPoP proof per request (retrying once on a DPoP nonce challenge,
// RFC 9449 §9) or, under mTLS sender-constraining, sets a plain Bearer
// header — see that method's own doc comment. Defined here as a
// narrow interface, rather than importing *client.ResourceClient by
// name, so this package doesn't need fapigo/client's own TokenSet/
// Client machinery just to be called or tested; acquiring the access
// token this Do bound to is entirely the caller's job (see the package
// doc comment for what's not covered yet).
type ProtectedResourceClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// CredentialRequest is a Wallet's own outbound Credential Request
// (§8.2). At least one of Keys/JWTProofs (jwt proof type) must be set,
// or Attestation (attestation proof type) — but not both groups,
// matching issuer's own "proofs must contain exactly one proof type"
// rule. di_vp isn't offered here yet (see the package doc comment).
type CredentialRequest struct {
	// CredentialConfigurationID selects the Credential Configuration to
	// request directly — a key in the Issuer's own
	// credential_configurations_supported metadata. REQUIRED unless
	// CredentialIdentifier is set instead — exactly one of the two must
	// be present (§8.2's own MUST on both directions).
	CredentialConfigurationID string

	// CredentialIdentifier is §8.2's own alternative to
	// CredentialConfigurationID: an opaque value from a prior Token
	// Response's own "authorization_details" parameter (RFC 9396 §6.2)
	// — one entry of the matching oid4vci.AuthorizationDetail's own
	// CredentialIdentifiers, for whichever Credential Configuration
	// that entry names. This package builds that Token Response
	// parsing itself only for the Pre-Authorized Code Flow (see
	// PreAuthorizedCodeTokenResult.AuthorizationDetails); for the
	// Authorization Code Flow, acquiring the token — and so parsing its
	// own authorization_details — is fapigo/client's own job, the same
	// "this package never wraps fapigo/client's BeginAuthorization/
	// ExchangeCode" split the package doc comment already draws, so the
	// caller supplies whichever CredentialIdentifiers value it resolved
	// from that response itself.
	CredentialIdentifier string

	// Keys is one crypto.Signer per Credential instance requested —
	// len(Keys) > 1 requests a batch (§8.2's own multi-proof example).
	// RequestCredential signs one jwk-conveyed jwt-type key proof per
	// entry via GenerateProof, binding that Credential instance to that
	// key. Set this, JWTProofs, or Attestation.
	Keys []crypto.Signer

	// JWTProofs is zero or more already-built jwt-type proof JWTs —
	// typically from GenerateProofWithKeyID or GenerateProofWithX5C,
	// for a kid- or x5c-conveyed binding key RequestCredential has no
	// signer-driven way to build itself. Appended to Keys' own
	// generated proofs in the outbound "jwt" proofs array — a request
	// may set Keys, JWTProofs, or both, but not alongside Attestation.
	JWTProofs []string

	// Attestation, if non-empty, selects the attestation proof type
	// instead of Keys (Appendix F.3): a single, already-built Key
	// Attestation JWT — typically from GenerateAttestationProof — is
	// submitted as-is, with no fresh proof of possession of any
	// attested key (Appendix F-5.2). The Credential Issuer issues one
	// Credential per key in the attestation's own attested_keys claim,
	// so this alone can request a batch. Set this, or Keys, but not
	// both.
	Attestation string

	// CredentialIssuer is the Credential Issuer Identifier — the aud
	// claim every generated jwt-type proof carries (see GenerateProof).
	// REQUIRED when Keys is set; unused for Attestation, since a Key
	// Attestation JWT carries no aud claim (Appendix D.1).
	CredentialIssuer string

	// Nonce is the c_nonce every jwt-type proof declares (§8.2) — from
	// a prior RequestNonce call, or "" when the issuer has no Nonce
	// Endpoint. Unused for Attestation: that nonce must already be
	// baked into the signed attestation before this call (see
	// GenerateAttestationProof's own doc comment).
	Nonce string

	// RequestEncryption, if set, encrypts this Credential Request's own
	// outbound body (§10) — see RequestEncryption's own doc comment.
	RequestEncryption *RequestEncryption

	// ResponseEncryption, if set, requests an encrypted Credential
	// Response (§10) — RequestCredential generates a fresh ephemeral
	// key pair per call and decrypts the Response transparently; see
	// ResponseEncryption's own doc comment, including why setting this
	// requires RequestEncryption to also be set.
	ResponseEncryption *ResponseEncryption
}

// credentialRequestBody is the Credential Request's own wire shape
// (§8.2) — CredentialRequest itself carries signing keys, which never
// go on the wire, so this stays a private type RequestCredential
// builds internally.
type credentialRequestBody struct {
	CredentialConfigurationID string                         `json:"credential_configuration_id,omitempty"`
	CredentialIdentifier      string                         `json:"credential_identifier,omitempty"`
	Proofs                    map[string][]string            `json:"proofs"`
	ResponseEncryption        *wireResponseEncryptionRequest `json:"credential_response_encryption,omitempty"`
}

// RequestCredential implements the Credential Endpoint's own client
// side (§8.2/§8.3): it signs one jwt-type key proof per entry in
// req.Keys (via GenerateProof), POSTs the resulting Credential Request
// to endpoint as a sender-constrained request via resource, and parses
// the response — either the completed Credentials (HTTP 200) or,
// if the Credential Issuer instead defers issuance at this very first
// response (HTTP 202, transaction_id/interval — §8.3's own
// deferred-at-first-response case), a polling hint to pass to
// RequestDeferredCredential. See CredentialResult's own doc comment
// for how to tell the two cases apart. A response outside those two
// statuses is returned as a *Error.
func (w *Wallet) RequestCredential(
	ctx context.Context, resource ProtectedResourceClient, endpoint fapi.URL, req CredentialRequest,
) (CredentialResult, error) {
	hasConfigID := req.CredentialConfigurationID != ""
	hasIdentifier := req.CredentialIdentifier != ""
	if hasConfigID == hasIdentifier {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: exactly one of credential_configuration_id or credential_identifier is required")
	}
	hasJWT := len(req.Keys) > 0 || len(req.JWTProofs) > 0
	hasAttestation := req.Attestation != ""
	if hasJWT == hasAttestation {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: exactly one of keys/jwt_proofs or attestation is required")
	}
	if req.ResponseEncryption != nil && req.RequestEncryption == nil {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: response_encryption requires request_encryption to also be set")
	}

	proofs, err := w.buildCredentialProofs(req)
	if err != nil {
		return CredentialResult{}, err
	}

	respEncWire, respDecryptKey, err := prepareResponseEncryption(req.ResponseEncryption)
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: %w", err)
	}

	body, err := json.Marshal(credentialRequestBody{
		CredentialConfigurationID: req.CredentialConfigurationID,
		CredentialIdentifier:      req.CredentialIdentifier,
		Proofs:                    proofs,
		ResponseEncryption:        respEncWire,
	})
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: marshal request: %w", err)
	}
	return w.postCredentialResult(ctx, resource, endpoint, body, req.RequestEncryption, respDecryptKey, "request credential")
}

// buildCredentialProofs builds req's own "proofs" object: one jwt-type
// proof per req.Keys entry (via GenerateProof) plus req.JWTProofs
// as-is, or req.Attestation as-is under the attestation proof type —
// see CredentialRequest's own doc comment for why these two groups are
// mutually exclusive.
func (w *Wallet) buildCredentialProofs(req CredentialRequest) (map[string][]string, error) {
	if req.Attestation != "" {
		return map[string][]string{oid4vci.ProofTypeAttestation: {req.Attestation}}, nil
	}

	proofs := make([]string, 0, len(req.Keys)+len(req.JWTProofs))
	for i, signer := range req.Keys {
		proof, err := w.GenerateProof(signer, req.CredentialIssuer, req.Nonce)
		if err != nil {
			return nil, fmt.Errorf("wallet: request credential: generate proof %d: %w", i, err)
		}
		proofs = append(proofs, proof)
	}
	proofs = append(proofs, req.JWTProofs...)
	return map[string][]string{oid4vci.ProofTypeJWT: proofs}, nil
}
