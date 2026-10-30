package oid4vci

import (
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/idfoundry/fapigo/extension"
)

// AuthorizationDetailRARDefinition declares the openid_credential
// authorization details type (§5.1.1, RFC 9396) to fapigo's
// extension.RARRegistry, for an Authorization Server built on
// fapigo/server that takes authorization_details for Credentials:
// register it in server.Config.RAR, and list
// AuthorizationDetailsTypeOpenIDCredential in each Wallet's
// RegisteredClientConfig.AuthorizationDetailsTypes. maxObjects and
// maxBytesPerObject bound one authorization_details array, as
// RARDefinition's MaxObjects and MaxBytesPerObject do.
//
// credential_identifiers are the Authorization Server's to issue
// (§6.2), so the definition's checks are:
//
//   - Validate, on every object: a credential_configuration_id, and
//     credential_identifiers, if any, each non-empty and listed once.
//   - ValidateRequest, on the objects a client sends to start a grant
//     (a pushed authorization request, say): no credential_identifiers.
//     A client choosing them is refused with
//     invalid_authorization_details, so an identifier a Credential
//     Request presents is always one the Authorization Server minted.
//   - ValidateGrant, on a granted object against the requested one it
//     narrows: the same credential_configuration_id; locations and
//     claims no wider than requested (a subset of the requested ones,
//     none where none were requested); and credential_identifiers that
//     the granted object may add where the requested one has none —
//     the Authorization Server minting them at consent — and otherwise
//     may only narrow.
//   - ValidateNarrowing, on the object a token request asks for
//     (exchanging a code or a CIBA auth_req_id, or refreshing) against
//     the granted one it narrows: the same checks, except that it may
//     never add credential_identifiers. It keeps some or all of the
//     grant's identifiers, or drops them, and a grant that holds none
//     admits none. A token request naming an identifier the grant
//     doesn't hold is refused with invalid_authorization_details.
//
// The binding rule for the Credential Issuer: a credential_identifier
// is a handle the Authorization Server minted for one grant, not an
// authority of its own. A Credential Endpoint's Prepare must look up
// what an identifier names together with the grant's Subject — among
// the identifiers recorded for that subject when they were minted —
// and never issue whatever dataset an identifier names on its own.
func AuthorizationDetailRARDefinition(maxObjects, maxBytesPerObject int) extension.RARDefinition[AuthorizationDetail] {
	return extension.RARDefinition[AuthorizationDetail]{
		Type:              AuthorizationDetailsTypeOpenIDCredential,
		MaxObjects:        maxObjects,
		MaxBytesPerObject: maxBytesPerObject,
		Validate:          validateAuthorizationDetail,
		ValidateRequest:   validateRequestedAuthorizationDetail,
		ValidateGrant:     validateGrantedAuthorizationDetail,
		ValidateNarrowing: validateNarrowedAuthorizationDetail,
	}
}

// ErrClientCredentialIdentifiers is what AuthorizationDetailRARDefinition's
// ValidateRequest returns for a client's openid_credential object that
// carries credential_identifiers.
var ErrClientCredentialIdentifiers = errors.New("oid4vci: credential_identifiers are the Authorization Server's to issue (OpenID4VCI 1.0 §6.2), not the client's to request")

func validateAuthorizationDetail(d AuthorizationDetail) error {
	if d.CredentialConfigurationID == "" {
		return errors.New("oid4vci: openid_credential authorization_details: credential_configuration_id is required (OpenID4VCI 1.0 §5.1.1)")
	}
	for i, id := range d.CredentialIdentifiers {
		if id == "" {
			return fmt.Errorf("oid4vci: openid_credential authorization_details: credential_identifiers[%d] is empty", i)
		}
		if slices.Contains(d.CredentialIdentifiers[:i], id) {
			return fmt.Errorf("oid4vci: openid_credential authorization_details: credential_identifiers[%d] is listed twice", i)
		}
	}
	return nil
}

func validateRequestedAuthorizationDetail(d AuthorizationDetail) error {
	if len(d.CredentialIdentifiers) > 0 {
		return ErrClientCredentialIdentifiers
	}
	return nil
}

// validateGrantedAuthorizationDetail judges consent: granted may add
// credential_identifiers where requested has none.
func validateGrantedAuthorizationDetail(requested, granted AuthorizationDetail) error {
	return validateNarrowerAuthorizationDetail(requested, granted, len(requested.CredentialIdentifiers) == 0, "granted", "requested")
}

// validateNarrowedAuthorizationDetail judges a token request's
// narrowing of its grant: narrowed may only keep or drop the grant's
// credential_identifiers, never add one.
func validateNarrowedAuthorizationDetail(granted, narrowed AuthorizationDetail) error {
	return validateNarrowerAuthorizationDetail(granted, narrowed, false, "token request's", "granted")
}

// validateNarrowerAuthorizationDetail reports whether narrower is no
// wider than wider: the same credential_configuration_id, and
// locations, claims and credential_identifiers among wider's. With
// mayAddIdentifiers, narrower's credential_identifiers aren't checked.
// narrowerName and widerName name the two sides in the error.
func validateNarrowerAuthorizationDetail(wider, narrower AuthorizationDetail, mayAddIdentifiers bool, narrowerName, widerName string) error {
	var member string
	switch {
	case narrower.CredentialConfigurationID != wider.CredentialConfigurationID:
		return fmt.Errorf("oid4vci: openid_credential authorization_details: the %s credential_configuration_id isn't the %s one", narrowerName, widerName)
	case !subsetOf(narrower.Locations, wider.Locations, func(a, b string) bool { return a == b }):
		member = "locations"
	case !subsetOf(narrower.Claims, wider.Claims, func(a, b ClaimsDescription) bool { return reflect.DeepEqual(a, b) }):
		member = "claims"
	case !mayAddIdentifiers &&
		!subsetOf(narrower.CredentialIdentifiers, wider.CredentialIdentifiers, func(a, b string) bool { return a == b }):
		member = "credential_identifiers"
	default:
		return nil
	}
	return fmt.Errorf("oid4vci: openid_credential authorization_details: the %s %s aren't among the %s ones", narrowerName, member, widerName)
}

// subsetOf reports whether every element of sub equals one of super.
func subsetOf[T any](sub, super []T, equal func(a, b T) bool) bool {
	for _, s := range sub {
		if !slices.ContainsFunc(super, func(x T) bool { return equal(s, x) }) {
			return false
		}
	}
	return true
}
