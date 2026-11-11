// Package verifier implements the OID4VP 1.0 Verifier (Relying Party)
// role, profiled by HAIP 1.0 §5 — the presentation half of HAIP, as
// issuer/wallet implement OID4VCI's own issuance half.
//
// Unlike issuance, the presentation flow builds on none of FAPI 2.0's
// AS/RP OAuth machinery: no PAR, no Token Endpoint, no client
// authentication handshake in the OAuth-grant sense. An OID4VP
// Authorization Request is a JAR-signed Request Object [RFC9101]
// carrying a dcql_query (package dcql), answered with a VP Token —
// via direct_post.jwt for the redirect flow, or dc_api.jwt for the DC
// API flow (Appendix A/HAIP §5.2) — self-contained on top of JOSE
// primitives this repo already owns (internal/jose, internal/jwe,
// internal/jwk.Thumbprint) and the two existing credential format
// packages (credential/sdjwtvc, credential/mdoc) for the actual
// Presentation verification. This package has no FAPIgo dependency at
// all, unlike issuer/wallet's OID4VCI roles.
//
// # Where to start
//
// For the redirect flows, use Transactions: Begin a request, mount its
// RequestObjectHandler and ResponseHandler, and read the result with
// Lookup (cross-device) or Redeem (same-device). For the Digital
// Credentials API, BeginDCAPI a request, hand its Request to the page
// for navigator.credentials.get, and pass the answer the page posts
// back to HandleDCAPIResponse — or, for an ISO mdoc over the
// "org-iso-mdoc" protocol, BeginMdocDCAPI and HandleMdocDCAPIResponse
// (see below). It keeps each request's
// secrets, routes each answer to its request, verifies it, and binds
// the result to the browser that asked — the state handling OpenID4VP
// §8.2 and §13.3 require, which the lower-level functions below leave
// to the caller. Running several replicas: DEPLOYING.md in the
// repository is the checklist (a shared TransactionStore, a
// certrevocation.Refresher, a statuslist.Cache).
//
// Choose the flow by what the result is for. Only the same-device flow
// and the Digital Credentials API bind the result to the browser that
// asked: a cross-device request's QR code can be shown on any page, and
// whoever started the request gets the result of the holder who
// scanned it (OpenID4VP 1.0 §14.2; SECURITY.md, "Relayed cross-device
// requests"). Where the session must belong to the person presenting,
// as for a login, don't offer the cross-device flow.
//
// Several Transactions may share one TransactionStore, each reading
// only its own transactions (TransactionsConfig.Scope). The scope a
// Transactions derives when Scope is unset tells apart only Verifiers
// that differ in client_id, response_uri or RequestURIBase: one Verifier
// serving several Digital Credentials API Transactions with different
// Verify or Accept policies — RequestURIBase unset in each — derives
// the same scope for all of them, so give each its own explicit Scope.
//
// A production TransactionStore keeps transactions outside the process:
// TransactionCodec encodes one, and with a sealing.Sealer
// (sealing.AESGCMSealer) seals what it holds of the holder's — the response
// decryption key and the disclosed claims — so the store's copy reveals
// neither. The record's other fields stay readable and unprotected:
// the store is trusted for their integrity.
// TransactionsConfig.ForgetResultOnRead drops the claims as soon as
// they've been read.
//
// Transactions checks a Digital Credentials API request's origin
// against TransactionsConfig.Origins, its allow-list, normalized as the
// browser serializes an origin. The lower-level VerifyResponse has no
// allow-list: VerifyResponseRequest.Origin must be one of
// ExpectedOrigins, the request's own expected_origins, each spelled
// exactly as the browser gives it, and both come from the caller — so
// take them from the Verifier's configuration, never from the
// response's HTTP request, as Transactions does.
//
// # Status
//
// BuildAuthorizationRequest constructs a signed redirect-flow
// Authorization Request (x509_hash Client Identifier Prefix,
// direct_post.jwt response mode, per §5 and HAIP §5's own profile of
// it). BuildDCAPIAuthorizationRequest constructs a signed DC API
// request instead (Appendix A.3.2.1, JWS Compact Serialization;
// unsigned requests and multi-signed JWS JSON Serialization requests
// aren't offered — see its own doc comment). ParseDirectPostJWTResponse
// decrypts and parses the resulting response (§8.1/§8.3.1) — reusable
// as-is for a dc_api.jwt response too, since both share the exact same
// encrypted-JWT-carrying-a-vp_token shape; only the transport differs
// (an HTTP POST body vs. the DC API's own resolved data object), which
// is a caller concern this package's own byte-in/byte-out functions
// never touch. VerifyResponse implements §8.6's own VP Token Validation
// for both the "dc+sd-jwt" and "mso_mdoc" formats, including all of
// §6's own Credential/Claims selection rules: "multiple" (§6.1),
// "claim_sets" (§6.4.1), and "credential_sets" (§6.4.2) — and for both
// the redirect and DC API flows (VerifyResponseRequest.Origin selects
// which, with ExpectedOrigins, the request's, which Origin must be one
// of: the page's own origin, from the Verifier's configuration, never
// from the response's HTTP request): it checks a Presentation's own Holder Binding proof against
// either this Verifier's own Client Identifier or the DC API's own
// Origin-bound audience ("origin:..." per Appendix A.4), and rebuilds
// the mdoc SessionTranscript via oid4vpmdoc.BuildSessionTranscriptBytes
// or BuildDCAPISessionTranscriptBytes to match. ResponseKeyID reads a
// direct_post.jwt response's key ID, to find its request before
// decrypting it. Each VerifiedCredential carries its status reference
// (Claims["status"], or MdocStatus), which a StatusPolicy checks — its
// Token Status List with package statuslist, an mdoc's identifier list
// with identifierlist — as TransactionsConfig.Status or
// VerifyResponseRequest.Status, before Accept, the Verifier's own
// checks (Chain composes several). Under AssuranceProduction, Status or
// an explicit NoStatusCheck is required: an Accept checking business
// rules alone would otherwise accept revoked credentials. A policy
// passes a credential with no status reference unless its
// RequireReference is set. RequireValidStatus and
// RequireStatusReference do the same as Accepts.
//
// Certificate revocation is checked for a credential's issuer:
// X5CIssuerKeyResolver and X5ChainIssuerKeyResolver require a
// certrevocation.Checker (their Revocation field), and accept an
// issuer's or document signer's certificate only through a verified
// path on which no certificate is revoked — certrevocation.CRLs with
// the issuer CAs' current CRLs, or certrevocation.NoCheck{} to decline
// explicitly. VerifyResponse and NewTransactions refuse either resolver
// without one. A status list signer's certificate is checked when the
// StatusPolicy's statuslist.Checker sets Options.Revocation, which
// AssuranceProduction requires (certrevocation.NoCheck{} declines it
// explicitly), and is otherwise trusted from its chain to the
// configured roots and its validity period alone. A credential's own
// revocation is its status list's.
//
// The issuer key resolvers establish who a credential's issuer is, not
// which types it may issue: where trusted issuers aren't all authorized
// for every requested type, VerifyResponseRequest.IssuerAuthorized
// decides that per presentation (SD-JWT VC draft-19 §7.7).
// Transactions hosts each request's Request Object at its request_uri
// (RequestObjectHandler). Invoking the Digital Credentials API itself,
// in the page, is the caller's: BeginDCAPI and BeginMdocDCAPI give the
// request to hand it, and HandleDCAPIResponse and
// HandleMdocDCAPIResponse take its answer. See ARCHITECTURE.md for
// the full roadmap.
//
// # ISO mdoc over the Digital Credentials API
//
// An mdoc requested over the Digital Credentials API with the
// "org-iso-mdoc" protocol (ISO/IEC TS 18013-7 Annex C) — Safari's only
// one, answered by Apple Wallet or an iOS document provider app, and
// Chrome's too — isn't OpenID4VP. Transactions manages it as it does an
// OpenID4VP one: set TransactionsConfig.MdocDCAPI to
// mdocdcapi.ForTransactions with the Verifier's reader keys, and
// TransactionsConfig.Origins to its pages' origins. BeginMdocDCAPI
// builds the request — one document type and its data elements, an
// MdocDCAPIRequest — and keeps the response decryption key in the
// transaction, sealed as an OpenID4VP request's is, bound to the
// browser and the page's origin:
//
//	begun, err := txs.BeginMdocDCAPI(ctx, verifier.MdocDCAPIRequest{
//		DocType:  "org.iso.18013.5.1.mDL",
//		Elements: map[string]map[string]bool{"org.iso.18013.5.1": {"age_over_18": false}},
//	}, sessionCookie, "https://verifier.example")
//	// Send begun.ID and begun.Request (JSON) to the page, which calls
//	//   const credential = await navigator.credentials.get({mediation: "required",
//	//       digital: {requests: [request]}});
//	// and POSTs credential.data back with begun.ID.
//	view, err := txs.HandleMdocDCAPIResponse(ctx, id, sessionCookie, posted)
//	// view.Result.Credentials[0].Claims["org.iso.18013.5.1"]["age_over_18"]
//
// HandleMdocDCAPIResponse decrypts and verifies the answer against the
// request's own origin and key, checks its status
// (TransactionsConfig.Status), runs Accept, and completes the request
// at most once; Lookup, Close and Forget work as for any request. Package
// mdocdcapi's BuildRequest and VerifyResponse are the lower-level
// functions, which leave keeping the request to the caller.
package verifier
