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
// issuer/fapiresource does all of this as an AccessTokenVerifier, for
// CredentialHandler; what follows is what it does, for a handler of
// your own. For an Authorization Server in the same process, build the
// *resource.Verifier with fapigo/serverresource.NewVerifier(serverCfg,
// serverDeps, serverresource.Options{...}), which checks revocation
// against the store the server revokes into and matches its token
// format. Its Options.Nonces turns on DPoP nonce challenges at these
// endpoints (RFC 9449 §9), so a DPoP proof must carry a nonce the
// issuer handed out rather than relying on its iat window and jti
// replay check alone; give it its own nonce store, not the server's.
// CredentialHandler and the other handlers pass the next nonce on in
// the DPoP-Nonce header, and fapigo/client's ResourceClient answers
// the challenge.
//
// A caller already constructing a *resource.Verifier for this
// deployment's own access tokens (fapigo/resource.NewVerifier — its own
// public API, out of scope here) calls (*resource.Verifier).Verify once
// per incoming Credential/Deferred Credential/Notification Request,
// then adapts its result into AuthorizedRequest with a one-line
// translation:
//
//	authCtx, err := verifier.Verify(ctx, resource.VerifyRequestFromHTTP(r, credentialEndpointURL))
//
// URL is the endpoint's absolute URL, not r.URL: a server-side request's
// URL has no scheme or host, so a DPoP proof's htu would never match it.
//	if err != nil {
//		// respond per *resource.Error — Verify's own doc comment covers this.
//	}
//	if authCtx.SubjectKind != resource.SubjectEndUser {
//		// a client credentials token: its Subject is the client's own
//		// client_id, which could equal a holder's (RFC 9068 §5).
//		return resource.NewInsufficientScopeError(authCtx, "a Credential needs an end user's access token")
//	}
//	var client issuer.ClientIdentity = issuer.NoClientIdentity{}
//	if authCtx.ClientID != "" {
//		client = issuer.KnownClientID(authCtx.ClientID)
//	}
//	auth := issuer.AuthorizedRequest{ClientIdentity: client, Subject: authCtx.Subject, Scopes: authCtx.Scopes}
//	if raw, ok := authCtx.Claims["authorization_details"]; ok {
//		if err := json.Unmarshal(raw, &auth.AuthorizationDetails); err != nil {
//			// malformed claim — treat the same as a verification failure.
//		}
//	}
//
// authCtx.Subject binds a deferred transaction to the token's subject
// (AuthorizedRequest.Subject), and it is how the caller finds out what
// to issue: for a token minted by
// ExchangePreAuthorizedCode it is the redeemed
// PreAuthorizedCodeRecord's own Subject (see AccessTokenParams.Subject),
// so look up the credential content by it before building
// CredentialRequest.SDJWTClaims/MdocClaims.
//
// ExpiresAt and Key are meaningless to AuthorizedRequest and dropped —
// AuthorizedRequest exists to check a requested CredentialConfiguration's
// own Scope (or, for a credential_identifier-based request,
// AuthorizationDetails) against what the token grants (§8.2), a
// jwt-type proof's "iss" claim against ClientIdentity (Appendix F.1),
// and who may poll a deferred transaction, nothing else. Of AuthorizationContext.Claims' own arbitrary token
// claims, only "authorization_details" (RFC 9396 §2) is ever worth
// pulling out — see AuthorizedRequest's own doc comment for why it's
// unmarshaled directly into []AuthorizationDetail rather than kept as
// raw JSON. Scopes needs no parsing either way: AuthorizationContext.Scopes
// is already a []string (Verify's own job), unlike
// fapigo/server.TokenResult's space-delimited Scope string — a
// token-issuance concern, not a presentation-time one, and not what
// AuthorizedRequest adapts from (see AuthorizedRequest's own doc
// comment).
//
// AuthorizationContext's own NextDPoPNonce (RFC 9449 §8's proactive
// refresh) has nothing to do with AuthorizedRequest either — it's an
// HTTP-response-header concern the caller sets directly on its own
// Credential/Deferred Credential/Notification Response, independent of
// whatever RequestCredential/RequestDeferredCredential/
// RequestNotification itself returns.
