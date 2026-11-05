// Package statuslist implements Token Status List
// (draft-ietf-oauth-status-list-14): a bit-packed, DEFLATE/ZLIB-
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
// corresponding format — or IssueTokenX5C/IssueTokenCWTX5Chain, with the
// signer's certificate chain in the token's x5c/x5chain header, as HAIP
// 1.0 §6.1 requires. StatusListRef.Claim/CWTStatusClaim build the
// "status" claim a Referenced Token embeds to point back at one (idx +
// uri, draft-14 §6.2/§6.3) — the same shape credential/sdjwtvc's
// Claims.Status expects for the JOSE form.
//
// Publisher serves a Status List Token over HTTP: an http.Handler that
// serves a token signed from the current statuses (cached for
// CacheFor), JWT or CWT by the Accept header (its DefaultForm when it
// names neither), with the signer's certificate chain.
//
// # Allocating indices
//
// Allocator hands each Referenced Token its index: drawn uniformly at
// random from a list, never handed out twice, moving to the next list
// once FillLimit of one is taken, and failing with ErrListsFull when
// every list is, so the issuer can provision another. draft-14 has
// the Status Issuer prevent double allocation (§13.3), since tokens
// sharing an index share a status, and recommends random indices over
// sequential ones (§12.4, §12.5.1), which reveal the order and number
// of tokens issued. Allocate one index per credential copy in batch
// issuance (§13.2), and never derive one from anything about the
// holder.
//
// The Allocator keeps its reservations and statuses in an IndexStore,
// which must be durable and reserve atomically; MemoryIndexStore is
// for tests and single processes, and statuslisttest.TestIndexStoreContract
// checks one of your own. Allocator.Statuses is the Publisher.Statuses
// for each list, and Allocator.SetStatus changes a token's status,
// refusing an index never handed out. A list retired for good — one
// no token still in circulation names — can be forgotten with
// IndexStore.Delete. See Allocator's example.
//
// # Sizing a list
//
// A Status List Token grows with its list's size and with how many of
// its statuses aren't VALID, and a Relying Party refuses one over its
// limit — DefaultMaxTokenBytes (1 MiB) unless it raised it
// (VerifyOptions.MaxTokenBytes, Fetcher.MaxBytes, and in a wallet
// walletflow.Config.StatusMaxBytes). Past it, every check of every
// credential on the list fails at once. A 1-bit list of 2^24 entries
// makes a JWT of about 806 KB with 2.5% of them revoked at random and
// 1.20 MB with 5%, and a CWT of about 1.03 MB with 10%: too close to
// the limit, or over it. Prefer lists of 2^20 entries or so, adding a
// list as each fills (Allocator's lists) and starting new ones each
// period, as walletprovider does, so a list stops growing and its
// revocations stop accumulating once its credentials expire. A
// Publisher refuses to sign a token over its MaxTokenBytes, so a list
// that outgrows what Relying Parties read fails at the issuer, not at
// each of them.
//
// # Lists both formats reference
//
// A Relying Party may send no Accept header when it knows which form
// to expect (draft-14 §8.1): an SD-JWT VC's expects a JWT, and an
// mdoc reader may expect a CWT. One URI has one DefaultForm, so a list
// both formats reference is served from two Publishers at two URIs:
// both take the same Statuses, one keeps DefaultForm's zero value
// (FormJWT) and the other sets FormCWT, SD-JWT VCs name the first in
// their status claim, and mdocs the second. A credential keeps one
// index, read the same way in both lists; when a status changes, call
// Invalidate on both, or one serves the old status for up to its
// CacheFor longer. A token's sub is the URI it was fetched from, which
// is why one Publisher can't serve both. A request naming a form still
// gets it at either URI. Separate lists, each with its own Statuses
// and indices, work too, but each is smaller, so a credential's index
// hides among fewer. A list only one format references needs one
// Publisher, with DefaultForm FormCWT if that format is mdoc. See
// Publisher's bothFormats example.
//
// # Checking
//
// Check implements draft-14 §8.3 steps 3-7: verifying the Status List
// Token's signature and claims, decompressing its Status List, and
// reading the status at a given index. CheckX5C/CheckCWTX5Chain do the
// same for a token carrying its signer's certificate chain, verifying
// that chain to a set of trust anchors first.
//
// Checker adds fetching the token (Fetcher: https only, at most
// MaxStatusListRedirects https redirects, the requested media type, a
// size limit), so a verifier checks a credential's status in one call.
// Give it a Cache, shared by every Checker in the process, to fetch a
// list once for as long as its ttl allows rather than once per check:
// each check still checks the kept token with its own Checker's trust
// and clock. A Fetcher reuses its connections either way.
// Locating the reference on an already-validated Referenced Token stays
// with its format: verifier.VerifiedCredential.StatusListRef does it
// for a presented credential.
package statuslist
