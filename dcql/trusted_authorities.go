package dcql

import "context"

// TrustedAuthoritiesChecker enforces a Credential Query's own
// TrustedAuthorities restriction (§6.1.1) against issuerChain — a
// credential's own issuer certificate chain, leaf first (a "dc+sd-jwt"
// credential's own JOSE "x5c" header, RFC 7515 §4.1.6, or a "mso_mdoc"
// credential's own IssuerAuth "x5chain" COSE header parameter, RFC
// 9360 §2 — the same DER-chain shape a role package's own
// x5c/x5chain-based issuer key resolver already receives, x5c/x5chain
// apart). issuerChain is nil when trust in the credential's issuer was
// established some other way (e.g. a DID-based resolver) — a
// TrustedAuthoritiesType that needs a certificate simply can't be
// satisfied in that case, the same "fail closed, not silently skipped"
// outcome as an unresolvable chain.
//
// This lives in dcql, not wallet or verifier, because both role
// packages need the identical evaluation: wallet.MatchDCQLQuery uses
// it to decide whether a held credential is even eligible to satisfy
// a Credential Query that declares TrustedAuthorities (§6.1.1's own
// restriction on Wallet selection), and verifier.VerifyResponse uses
// it to re-check that restriction on the Presentation actually
// returned — the same "shared evaluation logic only, workflow stays
// role-specific" split this package's own doc comment already draws
// for SatisfiedBySDJWTVCClaims/SatisfiedByMdocClaims.
//
// Trust in issuerChain's own leaf key is established independently by
// whichever role-specific resolver each package already uses (e.g.
// verifier.X5CIssuerKeyResolver's own Roots) — that resolver is
// typically configured once, statically, so it has no way to vary its
// own trust decision per Credential Query the way TrustedAuthorities
// itself can. This interface exists only to enforce that per-query
// restriction, never as a substitute for establishing trust in the
// leaf key itself.
//
// REQUIRED (by both wallet.MatchDCQLQuery and
// verifier.VerifyResponseRequest) whenever a Credential Query declares
// a non-empty TrustedAuthorities — both reject that combination
// outright when this is nil, rather than silently skipping the
// restriction (the same "no implicit weakening" pattern
// issuer.AuthorizedRequest.ClientIdentity's own
// requireClientIdentityDecision already applies).
//
// Per §6.1.1, TrustedAuthorities is satisfied if ANY ONE entry (of any
// TrustedAuthoritiesType) is satisfied — an implementation only needs
// to inspect the entries whose Type it understands and may ignore the
// rest. AKITrustedAuthoritiesChecker is this repo's own reference
// implementation, scoped to TrustedAuthorityAKI only — the one type
// HAIP 1.0 §5 actually requires support for (see that constant's own
// doc comment); a deployment that also needs etsi_tl or
// openid_federation needs its own checker for those, this repo ships
// none.
type TrustedAuthoritiesChecker interface {
	// CheckTrustedAuthorities returns nil if issuerChain is trusted by
	// at least one entry in authorities, or an error naming why not.
	CheckTrustedAuthorities(ctx context.Context, authorities []TrustedAuthoritiesQuery, issuerChain [][]byte) error
}
