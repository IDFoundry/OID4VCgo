package issuer

import (
	"fmt"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
)

// NarrowToAuthorizedClaims leaves in sdjwtClaims and mdocClaims only
// the claims authorized asks for and those configuration configID
// always carries, so a credential holds what the token's authorization
// detail asked for (§5.1.1, Appendix B.1) rather than the whole
// dataset. The Issuer issues what Prepare sets, so call it at the end
// of Prepare:
//
//	req.SDJWTClaims, req.MdocClaims, err = iss.NarrowToAuthorizedClaims(
//		req.ResolvedConfigurationID, req.AuthorizedClaims, req.SDJWTClaims, req.MdocClaims)
//
// and, for a deferred transaction, on the DeferredIssuance's claims with
// the AuthorizedClaims Prepare was given: a DeferredTransactionRecord
// doesn't keep them.
//
// An empty authorized asks for every claim, and both are returned as
// given. Otherwise a path keeps:
//   - in an SD-JWT VC, the member of Claims.Additional its first
//     element names, whole. Narrowing within a member (["address",
//     "locality"] keeping only address's locality) is left to the
//     caller, which builds the member's value. Claims' own fields
//     (vct, iss, nbf, exp, status, cnf and the rest) and the registered
//     iat in Additional always stay. The registered sub identifies the
//     subject, and SD-JWT VC lets it be selectively disclosed, so it
//     stays only as any other member does: when a path names it, or
//     the configuration marks it mandatory.
//   - in an mdoc, the data element it names as a namespace and a data
//     element identifier, its only form for an mdoc (Appendix C); a
//     namespace left with no element is dropped, with its
//     Claims.Decoys.
//
// A path matching no claim selects nothing. A claim configID's
// credential_metadata, or for an SD-JWT VC its TypeMetadata, marks
// mandatory always stays: Appendix B.2 has the Credential Issuer
// "always include this claim", and RequestCredential refuses a
// credential without it.
//
// The results are copies: the maps given, which a caller may share
// between requests, aren't changed. An mdoc for a configuration of the
// mdoc format left with no data element can't be issued, and is
// refused with ErrorCredentialRequestDenied. An unknown configID is an
// error.
func (iss *Issuer) NarrowToAuthorizedClaims(configID string, authorized []oid4vci.ClaimsDescription, sdjwtClaims *sdjwtvc.Claims, mdocClaims *mdoc.Claims) (*sdjwtvc.Claims, *mdoc.Claims, error) {
	cc, ok := iss.cfg.CredentialConfigurationsSupported[configID]
	if !ok {
		return nil, nil, fmt.Errorf("issuer: NarrowToAuthorizedClaims: unknown credential configuration %q", configID)
	}
	if len(authorized) == 0 {
		return sdjwtClaims, mdocClaims, nil
	}
	keep := keptClaims(cc, authorized)
	if sdjwtClaims != nil {
		narrowed := *sdjwtClaims
		narrowed.Additional = keep.sdjwt(sdjwtClaims.Additional)
		sdjwtClaims = &narrowed
	}
	if mdocClaims != nil {
		narrowed := *mdocClaims
		narrowed.NameSpaces, narrowed.Decoys = keep.mdoc(mdocClaims.NameSpaces, mdocClaims.Decoys)
		if len(narrowed.NameSpaces) == 0 && cc.Format == mdoc.CredentialFormat {
			return nil, nil, NewError(ErrorCredentialRequestDenied, "none of the claims the access token authorizes is in this credential")
		}
		mdocClaims = &narrowed
	}
	return sdjwtClaims, mdocClaims, nil
}

// registeredAdditionalClaims are the registered JWT claims in
// Claims.Additional that NarrowToAuthorizedClaims keeps: they describe
// the credential, not its subject. sub isn't one: it identifies the
// subject.
var registeredAdditionalClaims = map[string]bool{"iat": true}

// claimSelection is the claims NarrowToAuthorizedClaims keeps: SD-JWT VC
// top-level members by name, and mdoc data elements by namespace.
type claimSelection struct {
	members  map[string]bool
	elements map[string]map[string]bool
}

// keptClaims is the claims authorized selects in cc's credentials,
// with those cc marks mandatory.
func keptClaims(cc CredentialConfiguration, authorized []oid4vci.ClaimsDescription) claimSelection {
	s := claimSelection{members: map[string]bool{}, elements: map[string]map[string]bool{}}
	for _, c := range authorized {
		s.add(c.Path)
	}
	if cc.CredentialMetadata != nil {
		for _, c := range cc.CredentialMetadata.Claims {
			if c.IsMandatory() {
				s.add(c.Path)
			}
		}
	}
	if cc.TypeMetadata != nil {
		for _, c := range cc.TypeMetadata.Claims {
			if c.Mandatory {
				s.add(c.Path)
			}
		}
	}
	return s
}

// add selects what path names: the top-level member its first element
// names, and the data element it names when it's a namespace and an
// element identifier. The configuration has one format, and a path
// meant for the other selects nothing that exists.
func (s claimSelection) add(path []any) {
	if len(path) == 0 {
		return
	}
	name, ok := path[0].(string)
	if !ok {
		return
	}
	s.members[name] = true
	if len(path) != 2 {
		return
	}
	if element, ok := path[1].(string); ok {
		if s.elements[name] == nil {
			s.elements[name] = map[string]bool{}
		}
		s.elements[name][element] = true
	}
}

// sdjwt is the members of additional s keeps, in a new map.
func (s claimSelection) sdjwt(additional map[string]any) map[string]any {
	if additional == nil {
		return nil
	}
	out := make(map[string]any, len(additional))
	for name, v := range additional {
		if s.members[name] || registeredAdditionalClaims[name] {
			out[name] = v
		}
	}
	return out
}

// mdoc is the data elements of nameSpaces s keeps, and decoys for the
// namespaces left, in new maps.
func (s claimSelection) mdoc(nameSpaces map[string]map[string]any, decoys map[string]int) (map[string]map[string]any, map[string]int) {
	out := make(map[string]map[string]any, len(nameSpaces))
	for namespace, elements := range nameSpaces {
		kept := make(map[string]any, len(elements))
		for id, v := range elements {
			if s.elements[namespace][id] {
				kept[id] = v
			}
		}
		if len(kept) > 0 {
			out[namespace] = kept
		}
	}
	var keptDecoys map[string]int
	for namespace, n := range decoys {
		if _, ok := out[namespace]; !ok {
			continue
		}
		if keptDecoys == nil {
			keptDecoys = make(map[string]int, len(decoys))
		}
		keptDecoys[namespace] = n
	}
	return out, keptDecoys
}
