// Package dcql implements the Digital Credentials Query Language
// (OID4VP 1.0 §6/§7) — the query object an OID4VP Authorization
// Request's own "dcql_query" parameter carries to describe which
// Credentials, and which claims within them, a Verifier is requesting,
// plus the Claims Path Pointer (§7) addressing scheme a Claims Query's
// own "path" uses.
//
// Query *construction* is the verifier package's own job (it embeds a
// Query when building an Authorization Request); query *evaluation* —
// matching a Query against a Wallet's own held credentials — belongs to
// the wallet-presentation role, not built yet. This package holds only
// the shared wire shape both sides need identically, the same "shared
// value types only, workflow logic stays role-specific" split the root
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
// semantics — the shared low-level primitive both verifier and the
// future wallet-presentation role build their own, higher-level,
// role-specific decisions on top of; see Path's own doc comment for
// exactly where that split falls.
package dcql
