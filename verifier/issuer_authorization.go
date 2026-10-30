package verifier

import (
	"context"
	"slices"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
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
type IssuerAuthorization struct {
	// CredentialQueryID is the dcql.CredentialQuery.ID the presentation
	// answered.
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
	// unchecked iss is whatever the signer wrote, so an issuer allowed
	// by name here is never one another issuer under the same roots
	// impersonated; without the check, decide from IssuerChain.
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
	// verified with, as VerifiedCredential.IssuerChain, whose doc says
	// how to tell issuers apart by it: not by the leaf's subject.
	IssuerChain [][]byte

	// Claims are the presentation's disclosed claims, as
	// VerifiedCredential.Claims.
	Claims map[string]any
}

// authorizeIssuer runs req.IssuerAuthorized on a verified presentation.
// A refusal is the presentation's: ReasonUntrustedIssuer.
func authorizeIssuer(ctx context.Context, req VerifyResponseRequest, cq dcql.CredentialQuery, claims map[string]any, chain [][]byte) error {
	if req.IssuerAuthorized == nil {
		return nil
	}
	a := IssuerAuthorization{CredentialQueryID: cq.ID, Format: cq.Format, IssuerChain: chain, Claims: claims}
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
