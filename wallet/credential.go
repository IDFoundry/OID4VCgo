package wallet

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
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
// a successful (HTTP 200) Credential Response.
//
// A Credential Response that instead defers issuance (HTTP 202,
// transaction_id/interval — §8.3's own deferred-at-first-response
// case) is not supported yet — see the package doc comment. A non-200,
// non-202 response is returned as a *Error.
func (w *Wallet) RequestCredential(
	ctx context.Context, resource ProtectedResourceClient, endpoint fapi.URL, req CredentialRequest,
) (oid4vci.CredentialResponse, error) {
	if req.CredentialConfigurationID == "" {
		return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: credential_configuration_id is required")
	}
	if len(req.Keys) == 0 {
		return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: at least one key is required")
	}

	proofs := make([]string, 0, len(req.Keys))
	for i, signer := range req.Keys {
		proof, err := w.GenerateProof(signer, req.CredentialIssuer, req.Nonce)
		if err != nil {
			return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: generate proof %d: %w", i, err)
		}
		proofs = append(proofs, proof)
	}

	body, err := json.Marshal(credentialRequestBody{
		CredentialConfigurationID: req.CredentialConfigurationID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs},
	})
	if err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: marshal request: %w", err)
	}

	target := endpoint.URL()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := resource.Do(ctx, httpReq)
	if err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: read response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return oid4vci.CredentialResponse{}, parseError(res.StatusCode, respBody)
	}

	var response oid4vci.CredentialResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("wallet: request credential: decode response: %w", err)
	}
	return response, nil
}
