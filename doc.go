// Package oid4vci is reserved for value types shared across the issuer,
// wallet, and verifier packages, the way FAPIgo's root fapi package holds
// identifiers, algorithm enums and other data with a single, stable
// meaning on the wire regardless of role — see that package's own doc
// comment and ARCHITECTURE.md's "Shared public value types only where
// semantics match" rule.
//
// Nothing lives here yet: no role package exists to share a type with.
// Don't add a type here speculatively — move one in only once a second
// role package needs the exact same semantics, not before.
package oid4vci
