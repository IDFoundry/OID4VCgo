package wallet

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
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
// (§8.2). Only the jwt proof type is supported — di_vp/attestation
// aren't offered here yet (see the package doc comment).
// credential_identifier-based requests aren't supported either,
// matching issuer's own scope.
type CredentialRequest struct {
	// CredentialConfigurationID selects the Credential Configuration to
	// request — a key in the Issuer's own credential_configurations_supported
	// metadata. REQUIRED.
	CredentialConfigurationID string

	// Keys is one crypto.Signer per Credential instance requested —
	// len(Keys) > 1 requests a batch (§8.2's own multi-proof example).
	// RequestCredential signs one jwt-type key proof per entry via
	// GenerateProof, binding that Credential instance to that key.
	// REQUIRED: at least one.
	Keys []crypto.Signer

	// CredentialIssuer is the Credential Issuer Identifier — the aud
	// claim every generated proof carries (see GenerateProof). REQUIRED.
	CredentialIssuer string

	// Nonce is the c_nonce every proof declares (§8.2) — from a prior
	// RequestNonce call, or "" when the issuer has no Nonce Endpoint.
	Nonce string
}

// credentialRequestBody is the Credential Request's own wire shape
// (§8.2) — CredentialRequest itself carries signing keys, which never
// go on the wire, so this stays a private type RequestCredential
// builds internally.
type credentialRequestBody struct {
	CredentialConfigurationID string              `json:"credential_configuration_id"`
	Proofs                    map[string][]string `json:"proofs"`
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
	if req.CredentialConfigurationID == "" {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: credential_configuration_id is required")
	}
	if len(req.Keys) == 0 {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: at least one key is required")
	}

	proofs := make([]string, 0, len(req.Keys))
	for i, signer := range req.Keys {
		proof, err := w.GenerateProof(signer, req.CredentialIssuer, req.Nonce)
		if err != nil {
			return CredentialResult{}, fmt.Errorf("wallet: request credential: generate proof %d: %w", i, err)
		}
		proofs = append(proofs, proof)
	}

	body, err := json.Marshal(credentialRequestBody{
		CredentialConfigurationID: req.CredentialConfigurationID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs},
	})
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request credential: marshal request: %w", err)
	}
	return w.postCredentialResult(ctx, resource, endpoint, body, "request credential")
}
