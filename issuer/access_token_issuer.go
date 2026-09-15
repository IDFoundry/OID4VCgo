package issuer

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

// AccessTokenParams is the input to AccessTokenIssuer.IssueAccessToken
// for a successful pre-authorized_code exchange.
type AccessTokenParams struct {
	// Scope is the redeemed PreAuthorizedCodeRecord's own Scopes — what
	// the issued token grants access to.
	Scope []string

	// Thumbprint is the RFC 7638 JWK thumbprint of the key the
	// presented DPoP proof was signed with
	// (internal/jwk.JWK.Thumbprint's own output) — bind the issued
	// token to it via whatever confirmation mechanism the token format
	// uses (a JWT access token's own cnf.jkt claim, RFC 7800).
	Thumbprint string

	// Claims are additional claims to embed in a self-contained token
	// format, if any — this package has none of its own to add.
	Claims map[string]json.RawMessage

	// Issuer and Audience are only meaningful to a self-contained token
	// format (e.g. a JWT access token's own iss/aud claims) — an opaque
	// token has no self-contained claims and may ignore both.
	Issuer   string
	Audience string

	Now      time.Time
	Lifetime time.Duration
	Random   io.Reader
}

// AccessTokenIssuer mints an access token for a successful
// pre-authorized_code exchange — entirely this deployment's own
// token-issuance concern (a self-contained JWT, an opaque
// storage-backed value, ...); this package has no opinion on format.
//
// A caller already pairing issuer with a real fapigo/server.Server for
// the Authorization Code Flow (see authorization_server.go's own doc
// comment) can reuse that same signing infrastructure here via a thin
// adapter around its own server.AccessTokenIssuer
// (server.JWTAccessTokens/OpaqueAccessTokens), rather than this
// package importing fapigo/server's own type directly and forcing
// every caller — including one with no paired fapigo/server.Server at
// all — to depend on it:
//
//	type accessTokenAdapter struct{ inner server.AccessTokenIssuer }
//
//	func (a accessTokenAdapter) IssueAccessToken(ctx context.Context, p issuer.AccessTokenParams) (string, string, error) {
//		return a.inner.IssueAccessToken(ctx, server.AccessTokenParams{
//			Scope: p.Scope, Thumbprint: p.Thumbprint, Claims: p.Claims,
//			Issuer: p.Issuer, Audience: p.Audience,
//			Now: p.Now, Lifetime: p.Lifetime, Random: p.Random,
//			// ClientID/Subject are left zero — the Pre-Authorized Code
//			// Flow's own Token Request is typically unauthenticated
//			// (§6.1: client authentication is OPTIONAL) and has no
//			// authenticated end-user identity to set as Subject.
//			// SenderConstrain defaults to its own zero value,
//			// storage.SenderConstrainDPoP — correct here, since HAIP
//			// 1.0 §4 makes DPoP mandatory for this grant.
//		})
//	}
type AccessTokenIssuer interface {
	IssueAccessToken(ctx context.Context, p AccessTokenParams) (accessToken string, key string, err error)
}
