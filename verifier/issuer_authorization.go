package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"slices"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// IssuerAuthorization is what VerifyResponseRequest.IssuerAuthorized
// decides on: a presentation that otherwise verified, its issuer and
// the type it's being accepted as.
//
// Trust in Roots, or a trusted_authorities match, establishes who the
// issuer is, not what it may issue. SD-JWT VC draft-19 §7.7 requires
// Verifiers to "implement explicit checks for issuer authorization",
// basing acceptance "on both the credential type and the verified
// authority of the issuer". That is this check.
//
// Decide by IssuerAnchor: which of the configured roots verified the
// issuer's chain, compared by key (AnchorIs, AnchorHasKeyIdentifier)
// with the anchors you assign to the issuer or to each of
// MatchedTypes, and refuse a nil one. Names are no evidence of which
// CA that was: any trusted CA can issue a certificate with any subject
// or subject alternative name (so Issuer, under RequireIssuerName),
// and write any issuer name and authority key identifier into the
// certificates it signs (so those of IssuerChain). Where each type's
// issuers have their own anchors, per-type roots
// (X5CIssuerKeyResolver.RootsByVCT, X5ChainIssuerKeyResolver.RootsByDocType)
// make the same separation without a hook, and a Credential Query's
// trusted_authorities with an "aki" entry
// (dcql.AKITrustedAuthoritiesChecker with Roots or Anchors) restricts
// one query to the CAs it names.
type IssuerAuthorization struct {
	// CredentialQueryID is the dcql.CredentialQuery.ID the presentation
	// answered. For an org-iso-mdoc document, which answers no DCQL
	// query, it's the CredentialQueryID the verified document carries:
	// MdocDCAPIRequest.CredentialQueryID through Transactions, the
	// document's type through mdocdcapi alone.
	CredentialQueryID string

	// Format is the credential format: "dc+sd-jwt" or "mso_mdoc".
	Format string

	// Type is the credential's own type: its vct, or its doctype.
	Type string

	// AkaTypes are an SD-JWT VC's aka_vcts, the other types its Issuer
	// says it is of. They're the Issuer's assertion only: draft-19
	// §7.7 says a Verifier "MUST NOT treat the presence of a type in
	// the aka_vcts claim as evidence that the Issuer is authorized to
	// issue credentials of, or derived from, that type".
	AkaTypes []string

	// RequestedTypes are the types the Credential Query accepts: its
	// vct_values, or its doctype_value. A credential can match one
	// through AkaTypes rather than Type; the issuer must then be
	// authorized for the requested type the Verifier relies on, not
	// just for Type.
	RequestedTypes []string

	// Issuer is an SD-JWT VC's iss when the issuer key resolver checked
	// the credential's certificate names it (IssuerNameBinding:
	// X5CIssuerKeyResolver with RequireIssuerName), and "" otherwise. An
	// unchecked iss is whatever the signer wrote. A checked one is
	// whatever the CA that certified the signer wrote: it tells issuers
	// apart only where no other trusted CA can issue a certificate
	// naming that issuer (each CA either holds no key an attacker could
	// use, or is name-constrained to its own issuers' names by
	// constraints of their type: uniformResourceIdentifier ones for a
	// URI iss, since a dNSName constraint doesn't confine a URI, and
	// dNSName ones for a "dns:" iss). Where the roots are several
	// providers', any of them can
	// name another's issuer: decide by IssuerAnchor, and use Issuer to
	// tell apart the issuers under one anchor you trust for all of them.
	Issuer string

	// ClaimedIssuer is an SD-JWT VC's iss as the credential states it,
	// checked or not: for display and logs, never for a decision unless
	// it equals Issuer.
	ClaimedIssuer string

	// MatchedTypes are the RequestedTypes this credential answers: its
	// Type, and any of AkaTypes, that the query asked for. Authorize the
	// issuer for each of them, not just for Type: a credential can match
	// only through aka_vcts.
	MatchedTypes []string

	// IssuerChain is the issuer certificate chain the credential was
	// verified with, as VerifiedCredential.IssuerChain, without its
	// trust anchor. Its names and key identifiers, its last
	// certificate's issuer and authority key identifier among them, are
	// whatever the CAs that signed them wrote: they don't tell one
	// trusted CA from another. Decide by IssuerAnchor.
	IssuerChain [][]byte

	// IssuerAnchor is the trust anchor IssuerChain was verified to, as
	// VerifiedCredential.IssuerAnchor (DER): the configured root that
	// verified the issuer's chain. Compare its key with the anchors you
	// assign to the issuer or type (AnchorIs, AnchorHasKeyIdentifier).
	// nil means no chain was verified against configured roots (the
	// issuer key resolver verifies none): refuse it, unless your SD-JWT
	// VC issuers are trusted without certificates
	// (VerifyResponseRequest.AllowUnanchoredSDJWTVCIssuers), and then
	// identify them by what the resolver checked instead.
	IssuerAnchor []byte

	// Claims are the presentation's disclosed claims, as
	// VerifiedCredential.Claims.
	Claims map[string]any
}

// anchoredChain is a verified credential's IssuerChain and IssuerAnchor.
type anchoredChain struct {
	chain  [][]byte
	anchor []byte
}

// authorizeIssuer runs req.IssuerAuthorized on a verified presentation.
// A refusal is the presentation's: ReasonUntrustedIssuer.
func authorizeIssuer(ctx context.Context, req VerifyResponseRequest, cq dcql.CredentialQuery, claims map[string]any, chain *anchoredChain) error {
	if req.IssuerAuthorized == nil {
		return nil
	}
	a := IssuerAuthorization{CredentialQueryID: cq.ID, Format: cq.Format, IssuerChain: chain.chain, IssuerAnchor: chain.anchor, Claims: claims}
	switch cq.Format {
	case sdjwtvc.CredentialFormat:
		setSDJWTVCTypes(&a, req, cq, claims)
	case mdoc.CredentialFormat:
		// VerifyResponse has already checked the doctype is the
		// requested one.
		if meta, err := cq.MdocMeta(); err == nil {
			a.Type = meta.DoctypeValue
			a.RequestedTypes = []string{meta.DoctypeValue}
			a.MatchedTypes = []string{meta.DoctypeValue}
		}
	}
	if err := req.IssuerAuthorized(ctx, a); err != nil {
		return newError(ReasonUntrustedIssuer, "issuer authorization", err)
	}
	return nil
}

// setSDJWTVCTypes fills in a's issuer and types for an SD-JWT VC
// presentation with the disclosed claims.
func setSDJWTVCTypes(a *IssuerAuthorization, req VerifyResponseRequest, cq dcql.CredentialQuery, claims map[string]any) {
	a.Type, _ = claims["vct"].(string)
	a.ClaimedIssuer, _ = claims["iss"].(string)
	if binder, ok := req.IssuerKeys.(IssuerNameBinding); ok && binder.BindsIssuerName() {
		a.Issuer = a.ClaimedIssuer
	}
	if aka, ok := claims["aka_vcts"].([]any); ok {
		for _, t := range aka {
			if s, ok := t.(string); ok {
				a.AkaTypes = append(a.AkaTypes, s)
			}
		}
	}
	if meta, err := cq.SDJWTVCMeta(); err == nil {
		a.RequestedTypes = meta.VCTValues
	}
	for _, t := range append([]string{a.Type}, a.AkaTypes...) {
		if t != "" && slices.Contains(a.RequestedTypes, t) && !slices.Contains(a.MatchedTypes, t) {
			a.MatchedTypes = append(a.MatchedTypes, t)
		}
	}
}

// IssuerNameBinding is implemented by an SDJWTVCIssuerKeyResolver that
// can refuse a credential whose iss the certificate it verified
// doesn't name. BindsIssuerName reports whether it does, so
// IssuerAuthorization.Issuer is set only for a checked iss.
type IssuerNameBinding interface {
	BindsIssuerName() bool
}

// AnchorIs reports whether anchor, an IssuerAnchor (DER), has the public
// key of one of anchors: whether that root verified the issuer's chain.
// It compares keys, not names or declared key identifiers, which any
// root can copy from another: a root reissued with the same key
// matches, a different root naming itself as another doesn't. A nil or
// unparsable anchor matches none.
func AnchorIs(anchor []byte, anchors ...*x509.Certificate) bool {
	key, ok := anchorKey(anchor)
	if !ok {
		return false
	}
	return slices.ContainsFunc(anchors, func(c *x509.Certificate) bool { return c != nil && key.Equal(c.PublicKey) })
}

// AnchorHasKeyIdentifier reports whether one of keyIDs, each a key
// identifier base64url-encoded as a trusted_authorities "aki" value is
// (dcql.AKITrustedAuthorities), is derived from the public key of
// anchor, an IssuerAnchor (DER): by RFC 5280 §4.2.1.2 method 1 or RFC
// 7093 method 1, as dcql.AKITrustedAuthoritiesChecker with Roots
// matches a CA. The Subject Key Identifier the anchor declares isn't
// matched: another root can declare the same one. A nil or unparsable
// anchor matches none.
func AnchorHasKeyIdentifier(anchor []byte, keyIDs ...string) bool {
	if len(anchor) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(anchor)
	if err != nil {
		return false
	}
	for _, id := range certchain.DerivedKeyIdentifiers(cert) {
		if slices.Contains(keyIDs, base64.RawURLEncoding.EncodeToString(id)) {
			return true
		}
	}
	return false
}

// anchorKey is the public key of anchor, an IssuerAnchor.
func anchorKey(anchor []byte) (interface{ Equal(crypto.PublicKey) bool }, bool) {
	if len(anchor) == 0 {
		return nil, false
	}
	cert, err := x509.ParseCertificate(anchor)
	if err != nil {
		return nil, false
	}
	key, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return key, ok
}
