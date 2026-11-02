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
//   - Validate, on every object: a credential_configuration_id;
//     credential_identifiers, if present, a non-empty array of
//     non-empty identifiers, each listed once; locations, if present,
//     a non-empty array of non-empty strings; and claims, if present,
//     a non-empty array of claims description objects (Appendix B.1),
//     each path a valid Claims Path Pointer and none described twice
//     (Appendix B.3).
//   - ValidateRequest, on the objects a client sends to start a grant
//     (a pushed authorization request, say): no credential_identifiers.
//     A client choosing them is refused with
//     invalid_authorization_details, so an identifier a Credential
//     Request presents is always one the Authorization Server minted.
//   - ValidateGrant, on a granted object against the requested one it
//     narrows: the same credential_configuration_id; locations and
//     claims no wider than requested (a non-empty subset of the
//     requested ones, none where none were requested — an object
//     without locations is good at any Credential Issuer, and one
//     without claims asks for every claim, so leaving out the
//     requested ones would widen it); and credential_identifiers that
//     the granted object may add where the requested one has none —
//     the Authorization Server minting them at consent — and otherwise
//     may only narrow.
//   - ValidateNarrowing, on the object a token request asks for
//     (exchanging a code or a CIBA auth_req_id, or refreshing) against
//     the granted one it narrows: the same checks — so it keeps some
//     or all of the grant's locations and claims, never none of them —
//     except that it may never add credential_identifiers. It keeps
//     some or all of the grant's identifiers, never none of them: a
//     Token Response's object carries them (§6.2), and a token without
//     them would let the Wallet ask for the configuration's Credential
//     by credential_configuration_id, for whatever dataset the
//     Credential Endpoint picks. A grant that holds none admits none. A
//     token request naming an identifier the grant doesn't hold, or
//     leaving out all of the grant's, is refused with
//     invalid_authorization_details.
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
	// An empty array is present but names nothing: refused, rather than
	// read as absent, which for locations and claims means every one.
	switch {
	case d.CredentialIdentifiers != nil && len(d.CredentialIdentifiers) == 0:
		return errors.New("oid4vci: openid_credential authorization_details: credential_identifiers, when present, must be non-empty (OpenID4VCI 1.0 §6.2)")
	case d.Locations != nil && len(d.Locations) == 0:
		return errors.New("oid4vci: openid_credential authorization_details: locations, when present, must be non-empty")
	case d.Claims != nil && len(d.Claims) == 0:
		return errors.New("oid4vci: openid_credential authorization_details: claims, when present, must be non-empty (OpenID4VCI 1.0 §5.1.1)")
	}
	for i, l := range d.Locations {
		if l == "" {
			return fmt.Errorf("oid4vci: openid_credential authorization_details: locations[%d] is empty", i)
		}
	}
	if err := validateClaimsDescriptions(d.Claims); err != nil {
		return fmt.Errorf("oid4vci: openid_credential authorization_details: %w", err)
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
// narrowing of its grant: narrowed keeps some or all of the grant's
// credential_identifiers, never adds one.
func validateNarrowedAuthorizationDetail(granted, narrowed AuthorizationDetail) error {
	return validateNarrowerAuthorizationDetail(granted, narrowed, false, "token request's", "granted")
}

// validateNarrowerAuthorizationDetail reports whether narrower is no
// wider than wider: the same credential_configuration_id, and
// locations, claims and credential_identifiers among wider's. Where
// wider has locations or claims, narrower must keep at least one of
// them: without locations an object is good at any Credential Issuer,
// and without claims it asks for every claim. Unless mayAddIdentifiers,
// the same holds for credential_identifiers: an object without them
// lets the Wallet name the configuration itself (§8.2), for any of its
// datasets. With mayAddIdentifiers, narrower's credential_identifiers
// aren't checked.
// narrowerName and widerName name the two sides in the error.
func validateNarrowerAuthorizationDetail(wider, narrower AuthorizationDetail, mayAddIdentifiers bool, narrowerName, widerName string) error {
	var member string
	switch {
	case narrower.CredentialConfigurationID != wider.CredentialConfigurationID:
		return fmt.Errorf("oid4vci: openid_credential authorization_details: the %s credential_configuration_id isn't the %s one", narrowerName, widerName)
	case len(wider.Locations) > 0 && len(narrower.Locations) == 0:
		return fmt.Errorf("oid4vci: openid_credential authorization_details: the %s object leaves out the %s locations", narrowerName, widerName)
	case len(wider.Claims) > 0 && len(narrower.Claims) == 0:
		return fmt.Errorf("oid4vci: openid_credential authorization_details: the %s object leaves out the %s claims", narrowerName, widerName)
	case !mayAddIdentifiers && len(wider.CredentialIdentifiers) > 0 && len(narrower.CredentialIdentifiers) == 0:
		return fmt.Errorf("oid4vci: openid_credential authorization_details: the %s object leaves out the %s credential_identifiers", narrowerName, widerName)
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
