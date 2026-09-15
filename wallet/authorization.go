package wallet

import (
	"fmt"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"

	"github.com/idfoundry/oid4vcigo"
)

// issuerStateDefinition declares the issuer_state authorization
// parameter (OID4VCI 1.0 §4.1.1) to fapigo/client's own extension
// mechanism — a plain opaque string this package never interprets,
// only passes through, so there is no Validate beyond the wire-shape/
// size checks extension.Set already applies. 2048 bytes is generous
// headroom for a value the spec places no length limit on.
var issuerStateDefinition = extension.Definition[string]{
	Name:           "issuer_state",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourcePlainParameter | extension.SourceRequestObject,
	MaxBytes:       2048,
}

// BuildAuthorizationRequest translates a resolved Credential Offer and
// the caller's own chosen scope(s) into a client.BeginAuthorizationRequest
// — ready to pass directly to (*client.Client).BeginAuthorization,
// fapigo/client's own entry point into the Authorization Code Flow.
//
// This package deliberately doesn't wrap BeginAuthorization,
// HandleAuthorizationResponse or ExchangeCode themselves: driving that
// flow, and turning its result into a sender-constrained client via
// (*client.Client).ProtectedResource, is squarely fapigo/client's own
// public API, the same way issuer never wraps fapigo/server's
// Authorization/Token Endpoints. Once ExchangeCode returns a
// client.TokenSet, pass fapiClient.ProtectedResource(tokenSet) as
// RequestCredential's own resource parameter.
//
// scopes is the caller's own resolved scope value(s) for the Credential
// Configuration(s) it wants — typically each
// credential_configurations_supported[id].scope from the Issuer's own
// Metadata (§5.1.2: "Using Scope Parameter"). This package has no
// Metadata-fetching of its own yet, so resolving which scope maps to
// which credential_configuration_id is the caller's job.
//
// If offer carries an authorization_code grant with a non-empty
// IssuerState, it's attached as the issuer_state extension parameter
// per §4.1.1's own MUST: "If the Wallet decides to use the
// Authorization Code Flow and received a value for this parameter, it
// MUST include it in the subsequent Authorization Request to the
// Authorization Server as the issuer_state parameter value."
func BuildAuthorizationRequest(offer oid4vci.CredentialOffer, scopes []string) (client.BeginAuthorizationRequest, error) {
	if len(scopes) == 0 {
		return client.BeginAuthorizationRequest{}, fmt.Errorf("wallet: build authorization request: at least one scope is required")
	}
	req := client.BeginAuthorizationRequest{Scope: scopes}

	if offer.Grants == nil || offer.Grants.AuthorizationCode == nil || offer.Grants.AuthorizationCode.IssuerState == "" {
		return req, nil
	}
	if err := extension.Set(&req.Extensions, issuerStateDefinition, offer.Grants.AuthorizationCode.IssuerState); err != nil {
		return client.BeginAuthorizationRequest{}, fmt.Errorf("wallet: build authorization request: attach issuer_state: %w", err)
	}
	return req, nil
}
