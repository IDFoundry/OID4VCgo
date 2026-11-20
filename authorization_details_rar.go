package oid4vci

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"

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
// RARDefinition's MaxObjects and MaxBytesPerObject do. Register it in
// a registry 6 deep (extension.NewRARRegistry's maxDepth):
// [{"claims":[{"path":["name"]}]}] is 5 deep, and a claims
// description's display 6, so a shallower registry refuses objects
// that carry them. ValidateGrant and ValidateNarrowing take time
// linear in the sizes of the two objects they compare.
//
// credential_identifiers are the Authorization Server's to issue
// (§6.2), so the definition's checks are:
//
//   - Validate, on every object: a credential_configuration_id;
//     credential_identifiers, if present, a non-empty array of
//     non-empty identifiers, each listed once; locations, if present,
//     a non-empty array of non-empty strings; and claims, if present,
//     a non-empty array of at most MaxAuthorizationDetailClaims claims
//     description objects (Appendix B.1), each path a valid Claims Path
//     Pointer and none described twice (Appendix B.3).
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
//   - ValidateNarrowing, on each object a token request asks for
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
//     leaving out all of the grant's from an object it asks for, is
//     refused with invalid_authorization_details.
//
// Those checks hold for the objects a token request asks for: one
// that leaves a granted object out altogether — authorization_details
// set to [], or naming another of the grant's objects only — gets a
// token without it, which fapigo/server allows (RFC 9396 §6.1) and
// gives a definition no say in. The token then grants that
// configuration only if the grant holds its scope too, and then for
// every claim, by credential_configuration_id. So never grant a
// configuration's scope beside an object for it: the consent step
// grants one or the other (issuer.Issuer.UndetailedScopes).
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

// MaxAuthorizationDetailClaims is the most claims descriptions one
// openid_credential object may carry: AuthorizationDetailRARDefinition's
// Validate refuses more, whatever the registry's size bounds allow. It
// is dcql.MaxClaimsPerCredential, the most claims a Verifier may ask of
// one credential.
const MaxAuthorizationDetailClaims = 256

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
	if len(d.Claims) > MaxAuthorizationDetailClaims {
		return fmt.Errorf("oid4vci: openid_credential authorization_details: %d claims, more than %d", len(d.Claims), MaxAuthorizationDetailClaims)
	}
	if err := validateClaimsDescriptions(d.Claims); err != nil {
		return fmt.Errorf("oid4vci: openid_credential authorization_details: %w", err)
	}
	identifiers := make(map[string]struct{}, len(d.CredentialIdentifiers))
	for i, id := range d.CredentialIdentifiers {
		if id == "" {
			return fmt.Errorf("oid4vci: openid_credential authorization_details: credential_identifiers[%d] is empty", i)
		}
		if _, listed := identifiers[id]; listed {
			return fmt.Errorf("oid4vci: openid_credential authorization_details: credential_identifiers[%d] is listed twice", i)
		}
		identifiers[id] = struct{}{}
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
	case !stringsWithin(narrower.Locations, wider.Locations):
		member = "locations"
	case !claimsWithin(narrower.Claims, wider.Claims):
		member = "claims"
	case !mayAddIdentifiers && !stringsWithin(narrower.CredentialIdentifiers, wider.CredentialIdentifiers):
		member = "credential_identifiers"
	default:
		return nil
	}
	return fmt.Errorf("oid4vci: openid_credential authorization_details: the %s %s aren't among the %s ones", narrowerName, member, widerName)
}

// stringsWithin reports whether every element of sub is one of super's,
// in time linear in their lengths.
func stringsWithin(sub, super []string) bool {
	if len(sub) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(super))
	for _, s := range super {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// claimsWithin reports whether every claims description in sub equals
// one of super's, as reflect.DeepEqual compares them, in time linear in
// their lengths: super's are indexed by claimKey, and a description
// claimKey can't encode is compared with reflect.DeepEqual against
// super's that it can't encode either, since a description it can
// encode never equals one it can't. Every description
// AuthorizationDetailRARDefinition's Validate accepts can be encoded.
func claimsWithin(sub, super []ClaimsDescription) bool {
	if len(sub) == 0 {
		return true
	}
	keys := make(map[string]struct{}, len(super))
	var unkeyed []ClaimsDescription
	for _, c := range super {
		if key, ok := claimKey(c); ok {
			keys[key] = struct{}{}
		} else {
			unkeyed = append(unkeyed, c)
		}
	}
	for _, c := range sub {
		if key, ok := claimKey(c); ok {
			if _, found := keys[key]; !found {
				return false
			}
			continue
		}
		if !slices.ContainsFunc(unkeyed, func(u ClaimsDescription) bool { return reflect.DeepEqual(c, u) }) {
			return false
		}
	}
	return true
}

// claimKey encodes c so that two descriptions have the same key exactly
// when reflect.DeepEqual reports them equal: a nil Path or Display
// differs from an empty one, Mandatory compares by value, and each path
// element by its dynamic type and value, with -0 equal to 0. It reports
// false for a path element of any type but string, nil, int and
// float64, or a NaN, which equals nothing.
func claimKey(c ClaimsDescription) (string, bool) {
	b := make([]byte, 0, 64)
	if c.Path == nil {
		b = append(b, 'N')
	} else {
		b = append(b, 'P')
		b = strconv.AppendInt(b, int64(len(c.Path)), 10)
		b = append(b, ':')
		for _, elem := range c.Path {
			switch v := elem.(type) {
			case nil:
				b = append(b, 'n')
			case string:
				b = appendLengthPrefixed(append(b, 's'), v)
			case int:
				b = strconv.AppendInt(append(b, 'i'), int64(v), 10)
				b = append(b, ';')
			case float64:
				if math.IsNaN(v) {
					return "", false
				}
				if v == 0 {
					v = 0 // -0 == 0
				}
				b = strconv.AppendUint(append(b, 'f'), math.Float64bits(v), 16)
				b = append(b, ';')
			default:
				return "", false
			}
		}
	}
	switch {
	case c.Mandatory == nil:
		b = append(b, 'u')
	case *c.Mandatory:
		b = append(b, 't')
	default:
		b = append(b, 'f')
	}
	if c.Display == nil {
		b = append(b, 'N')
	} else {
		b = append(b, 'D')
		b = strconv.AppendInt(b, int64(len(c.Display)), 10)
		b = append(b, ':')
		for _, d := range c.Display {
			b = appendLengthPrefixed(appendLengthPrefixed(b, d.Name), d.Locale)
		}
	}
	return string(b), true
}

// appendLengthPrefixed appends s to b after its length, so that the
// encoding of a sequence of strings is unambiguous.
func appendLengthPrefixed(b []byte, s string) []byte {
	b = strconv.AppendInt(b, int64(len(s)), 10)
	return append(append(b, ':'), s...)
}
