// Package oid4vci holds value types shared across the issuer, wallet,
// and verifier packages, the way FAPIgo's root fapi package holds
// identifiers, algorithm enums and other data with a single, stable
// meaning on the wire regardless of role — see that package's own doc
// comment and ARCHITECTURE.md's "Shared public value types only where
// semantics match" rule.
//
// CredentialOffer (and Grants/GrantAuthorizationCode/
// GrantPreAuthorizedCode/TxCode), IssuedCredential/CredentialResponse,
// and ProofTypeJWT/ProofTypeAttestation moved here from issuer once
// wallet needed the exact same wire semantics for each — see issuer's
// own git history for why each one was originally issuer-scoped and
// what changed. Each type's own Validate method (where it has one)
// checks only §4/§8's own structural requirements; a role package's
// additional, role-specific constraints (e.g. issuer's own check that
// credential_configuration_ids are actually known to it) stay in that
// role package as a free function over these types, not a method here
// — Go methods can only be defined where a type is declared, and a
// role-specific rule doesn't belong in a package every role imports.
//
// Don't add a type here speculatively — move one in only once a
// second role package needs the exact same semantics, not before.
package oid4vci
