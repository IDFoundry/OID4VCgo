package issuer

// This file is documentation only — no exported types or functions.
// See AuthorizedRequest's own doc comment and the package doc
// comment's own "Status" section for why: this package never verifies
// the access token presented to the Credential/Deferred Credential/
// Notification Endpoint itself — that needs full HTTP request context
// (method, URL, DPoP proof or mTLS certificate) that has nothing to do
// with Credential Request/Response protocol logic — and never imports
// fapigo/resource to do it, the same "don't force every caller to
// depend on one specific verification library" stance
// AccessTokenIssuer's own doc comment draws for fapigo/server (a
// deployment verifying presented tokens some other way pays no cost
// for a dependency this package never needed). What follows is the
// integration recipe for pairing an *Issuer with a real
// fapigo/resource.Verifier, not new production code.
//
// # Adapting Verify's result into AuthorizedRequest
//
// A caller already constructing a *resource.Verifier for this
// deployment's own access tokens (fapigo/resource.NewVerifier — its own
// public API, out of scope here) calls (*resource.Verifier).Verify once
// per incoming Credential/Deferred Credential/Notification Request,
// then adapts its result into AuthorizedRequest with a one-line
// translation:
//
//	authCtx, err := verifier.Verify(ctx, resource.VerifyRequest{
//		Method: r.Method, URL: r.URL, Authorization: r.Header.Get("Authorization"),
//		DPoPProofs: r.Header.Values("DPoP"), PeerCertificate: peerCertificate(r),
//	})
//	if err != nil {
//		// respond per *resource.Error — Verify's own doc comment covers this.
//	}
//	auth := issuer.AuthorizedRequest{ClientID: authCtx.ClientID, Scopes: authCtx.Scopes}
//
// Subject, Claims, ExpiresAt, and Key are all meaningless to a
// Credential Request and dropped — AuthorizedRequest exists to check a
// requested CredentialConfiguration's own Scope against what the token
// grants (§8.2) and a jwt-type proof's "iss" claim against ClientID
// (Appendix F.1), nothing else. Scopes needs no parsing either way:
// AuthorizationContext.Scopes is already a []string (Verify's own
// job), unlike fapigo/server.TokenResult's space-delimited Scope
// string — a token-issuance concern, not a presentation-time one, and
// not what AuthorizedRequest adapts from (see AuthorizedRequest's own
// doc comment).
//
// AuthorizationContext's own NextDPoPNonce (RFC 9449 §8's proactive
// refresh) has nothing to do with AuthorizedRequest either — it's an
// HTTP-response-header concern the caller sets directly on its own
// Credential/Deferred Credential/Notification Response, independent of
// whatever RequestCredential/RequestDeferredCredential/
// RequestNotification itself returns.
