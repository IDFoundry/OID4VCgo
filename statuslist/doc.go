// Package statuslist implements Token Status List
// (draft-ietf-oauth-status-list-12): a bit-packed, DEFLATE/ZLIB-
// compressed array of Referenced Token statuses, published as a signed
// Status List Token, plus the "status" claim a Referenced Token (such
// as an SD-JWT VC — see credential/sdjwtvc's Claims.Status) uses to
// point at one.
//
// Only the JWT/JOSE encoding (draft-12 §5.1, §6.2) is implemented —
// not the CWT/COSE encoding (§5.2, §6.3), which belongs with
// credential/mdoc's COSE machinery when that package exists.
//
// # Issuing
//
// New builds a StatusList from a slice of per-token status values, and
// IssueToken signs it into a Status List Token. StatusListRef.Claim
// builds the "status" claim a Referenced Token embeds to point back at
// one (idx + uri, draft-12 §6.2) — the same map[string]any shape
// credential/sdjwtvc's Claims.Status expects.
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
