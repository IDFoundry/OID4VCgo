// Package dpop verifies an RFC 9449 DPoP proof JWT — the server-side
// counterpart to wallet's own GenerateDPoPProof, which builds one.
// Built for issuer's own future pre-authorized_code Token Request
// handling (§6.1), the one grant type entirely outside fapigo/server's
// scope, the same way it's outside fapigo/client's — see
// wallet.RequestPreAuthorizedCodeToken's own doc comment for that
// boundary's client-side half, and fapigo/server's own internal
// dpop package (a different module's internal package, so not directly
// reusable here) for the reference design this package's own Verify
// mirrors.
//
// Scope matches wallet's own GenerateDPoPProof: no "ath" (access token
// hash) checking, since a Token Request's own DPoP proof is presented
// before any access token exists to hash (RFC 9449 §4.3's own "in
// conjunction with the presentation of an access token" — not this
// case). A caller verifying a DPoP proof presented later, alongside an
// already-issued access token, needs that check and isn't served by
// this package as-is.
package dpop
