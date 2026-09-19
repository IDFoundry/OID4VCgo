package verifier

import (
	"context"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// TrustedAuthoritiesChecker enforces a Credential Query's own
// TrustedAuthorities restriction (§6.1.1) against issuerChain — the
// verified Presentation's own issuer certificate chain, leaf first (a
// "dc+sd-jwt" Presentation's own JOSE "x5c" header, RFC 7515 §4.1.6, or
// a "mso_mdoc" Presentation's own IssuerAuth "x5chain" COSE header
// parameter, RFC 9360 §2 — the same DER-chain shape
// SDJWTVCIssuerKeyResolver/MdocIssuerKeyResolver themselves each
// receive, x5c/x5chain apart). issuerChain is nil when this Verifier's
// own IssuerKeys/MdocIssuerKeys resolved trust some other way (e.g. a
// DID-based resolver) — a TrustedAuthoritiesType that needs a
// certificate simply can't be satisfied in that case, the same "fail
// closed, not silently skipped" outcome as an unresolvable chain.
//
// Trust in issuerChain's own leaf key is already established by
// IssuerKeys/MdocIssuerKeys by the time this is called — that
// resolver is configured once, statically, so it has no way to vary
// its own trust decision per Credential Query the way
// TrustedAuthorities itself can. This interface exists only to
// enforce that per-query restriction.
//
// REQUIRED on VerifyResponseRequest whenever Query includes a
// Credential Query with a non-empty TrustedAuthorities — VerifyResponse
// rejects that combination outright when this is nil, rather than
// silently skipping the restriction (the same "no implicit weakening"
// pattern issuer.AuthorizedRequest.ClientID's own
// requireClientIDDecision already applies).
//
// Per §6.1.1, TrustedAuthorities is satisfied if ANY ONE entry (of any
// dcql.TrustedAuthoritiesType) is satisfied — an implementation only
// needs to inspect the entries whose Type it understands and may
// ignore the rest. AKITrustedAuthoritiesChecker is this repo's own
// reference implementation, scoped to dcql.TrustedAuthorityAKI only —
// the one type HAIP 1.0 §5 actually requires support for (see that
// constant's own doc comment); a deployment that also needs etsi_tl or
// openid_federation needs its own checker for those, this repo ships
// none.
type TrustedAuthoritiesChecker interface {
	// CheckTrustedAuthorities returns nil if issuerChain is trusted by
	// at least one entry in authorities, or an error naming why not.
	CheckTrustedAuthorities(ctx context.Context, authorities []dcql.TrustedAuthoritiesQuery, issuerChain [][]byte) error
}
