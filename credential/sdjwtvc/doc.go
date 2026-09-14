// Package sdjwtvc implements SD-JWT-based Verifiable Credentials
// (draft-ietf-oauth-sd-jwt-vc-11), built on the base SD-JWT selective
// disclosure mechanism (RFC 9901, "Selective Disclosure for JSON Web
// Tokens") — see SPECIFICATIONS.md for exactly which draft/RFC each
// requirement below traces to.
//
// # Building a claims tree
//
// Issue takes a Claims value plus an Additional map[string]any for any
// further public/private claims (draft-11 §3.2.2.3). Mark a claim
// selectively disclosable with SD (for an object property) or
// SDElement (for an array element) — see their doc comments. Wrapping
// SD/SDElement around a value that itself contains more SD/SDElement
// markers produces RFC 9901 §4.2.6 "recursive Disclosures" with no
// special handling required: sealing happens bottom-up, so an inner
// marker's Disclosure is generated before the outer one that reveals
// it.
//
// vct, iss, nbf, exp, cnf, vct#integrity and status are never
// selectively disclosable per draft-11 §3.2.2.2 — Claims keeps them as
// dedicated plaintext fields for exactly that reason; putting one of
// their names in Additional is rejected. sub and iat are the two
// registered claims draft-11 permits (but does not require) to be
// disclosed, so they belong in Additional, optionally wrapped in SD.
//
// # Verifying a presentation
//
// Verify expects the Issuer's already-resolved public key: determining
// *which* key that is — draft-11 §3.5's JWT VC Issuer Metadata or X.509
// mechanisms — is out of scope here and belongs to a caller that has
// network access and issuer trust policy (the future issuer/wallet
// packages), consistent with the base spec's own separation between
// disclosure processing (RFC 9901 §7.1, which needs no key at all) and
// signature verification (§7.1 step 2, which does).
package sdjwtvc
