// Package dcql implements the Digital Credentials Query Language
// (OID4VP 1.0 §6/§7) — the query object an OID4VP Authorization
// Request's own "dcql_query" parameter carries to describe which
// Credentials, and which claims within them, a Verifier is requesting,
// plus the Claims Path Pointer (§7) addressing scheme a Claims Query's
// own "path" uses.
//
// Query *construction* is the verifier package's own job (it embeds a
// Query when building an Authorization Request). Query *evaluation* —
// matching a Query against a set of held/presented credentials — is
// shared identically by both wallet (does a held credential satisfy
// this Query, for presentation) and verifier (does a returned
// Presentation satisfy what was asked, for verification): this package
// holds that shared evaluation logic once, rather than each role
// package reimplementing it after being caught duplicating it, the same
// "shared logic only, workflow stays role-specific" split the root
// oid4vci package already draws for OID4VCI's own wire types (see
// ARCHITECTURE.md).
//
// # Status
//
// Query/CredentialQuery/CredentialSetQuery/ClaimsQuery/
// TrustedAuthoritiesQuery (§6), SDJWTVCMeta/MdocMeta (Appendix
// B.3.5/B.2.3 — the two Credential Format Identifiers this repo
// actually issues), and the Claims Path Pointer type Path (§7) exist
// now, each with a Validate() checking the spec's own structural
// MUSTs. Path.Select implements §7.1's own JSON-based evaluation
// semantics — the shared low-level primitive
// CredentialQuery.SatisfiedBySDJWTVCClaims/SatisfiedByMdocClaims (§6.4.1's
// own claim-selection rules, including "claim_sets"/§6.4.2's own
// "credential_sets" via CredentialSetQuery) build on. Their own richer
// twins, SelectedSDJWTVCClaimPaths/SelectedMdocClaimPaths, additionally
// report exactly which Claims entries' own Paths the winning
// claim_sets option (or the no-claim_sets case's own Claims) resolved
// — what wallet.PresentSDJWTVCSelective/PresentMdocSelective's own
// minimal-disclosure trimming need to know which Disclosures/namespace
// elements to keep, not just the pass/fail outcome
// SatisfiedBySDJWTVCClaims/SatisfiedByMdocClaims themselves return.
package dcql
