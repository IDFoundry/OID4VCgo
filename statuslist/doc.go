// Package statuslist implements Token Status List
// (draft-ietf-oauth-status-list-12): a bit-packed, DEFLATE/ZLIB-
// compressed array of Referenced Token statuses, published as a signed
// Status List Token, plus the "status" claim a Referenced Token (such
// as an SD-JWT VC — see credential/sdjwtvc's Claims.Status, or an mdoc
// — see credential/mdoc's package doc comment) uses to point at one.
//
// Both encodings are implemented: JWT/JOSE (§5.1, §6.2 — IssueToken,
// VerifyToken, StatusListRef.Claim/ParseStatusClaim, built on
// internal/jose) and CWT/COSE (§5.2, §6.3 — IssueTokenCWT,
// VerifyTokenCWT, StatusListRef.CWTStatusClaim/ParseCWTStatusClaim,
// built on internal/cose). The CWT profile's own claim keys for ttl,
// status_list and status (65534/65533/65535) are still "TBD (requested
// assignment)" in the IANA CWT Claims Registry as of the draft version
// this targets — see cwt.go's own comment.
//
// # Issuing
//
// New builds a StatusList from a slice of per-token status values, and
// IssueToken/IssueTokenCWT sign it into a Status List Token in the
// corresponding format. StatusListRef.Claim/CWTStatusClaim build the
// "status" claim a Referenced Token embeds to point back at one (idx +
// uri, draft-12 §6.2/§6.3) — the same shape credential/sdjwtvc's
// Claims.Status expects for the JOSE form.
//
// # Checking
//
// Check implements draft-12 §8.3 steps 3-7: verifying the Status List
// Token's signature and claims, decompressing its Status List, and
// reading the status at a given index. Steps 1-2 — locating the status
// claim on an already-validated Referenced Token, and fetching the
// Status List Token from its uri — are the caller's job, the same
// division credential/sdjwtvc draws between disclosure processing and
// key resolution: this package has no HTTP client and no opinion on
// how a Referenced Token itself is validated.
package statuslist
