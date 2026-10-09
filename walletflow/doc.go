// Package walletflow is a holder's wallet as a set of sessions: it
// receives credentials from a Credential Offer (OpenID4VCI 1.0, and
// optionally only from issuers following HAIP 1.0 §4) and presents them
// in answer to an Authorization Request (OpenID4VP 1.0, HAIP 1.0 §5),
// orchestrating the wallet package and
// fapigo/client step by step so an app can stop at each point that needs
// the holder: to show an offer, open the issuer's authorization page,
// ask for a PIN, or choose what to disclose.
//
// The app supplies the platform: a KeyStore whose keys never leave it
// (secure hardware on a phone: walletflow only asks a Key to sign a
// digest), a CredentialStore, optionally a WalletProvider that attests
// the wallet and its keys, and optionally a DeferredStore, an
// AuthorizationStore and a GrantStore, so deferred credentials, an
// authorization in progress and refresh tokens survive a restart
// (Wallet.Deferred, Wallet.ResumeIssuance, Wallet.RefreshCredential).
// At production assurance, receiving credentials needs a KeyStore
// declaring durable custody, and the authorization code grant a Durable
// AuthorizationStore. walletflow owns the protocols: every network
// request, every protocol message, and every check on what comes back.
//
// # Following the issuer's metadata
//
// Under Config.IssuanceProfile's default, ProfileOpenID4VCI, an
// issuance does what the issuer's and its Authorization Server's
// metadata ask, as OpenID4VCI 1.0 has a Wallet do:
//
//   - the grant: of an offer's two, the authorization code grant where
//     the wallet can complete it, else the pre-authorized code (§4.1.1);
//   - client authentication at the token endpoint: a Wallet Attestation
//     where the server takes one (attest_jwt_client_auth) and a
//     WalletProvider can give it, else for a pre-authorized code none,
//     where the server allows that (pre-authorized_grant_anonymous_access_supported,
//     §12.3) — none, too, where both would do, so the server learns
//     nothing of the wallet; the authorization code grant always needs
//     a Wallet Attestation, as fapigo/client has no public client;
//   - the proof: a jwt proof (Appendix F.1), or a key attestation
//     (the attestation proof type, Appendix F.3) where the issuer
//     requires one (key_attestations_required). A credential bound to
//     no key isn't received (ErrProofUnsupported);
//   - a c_nonce where the issuer has a nonce endpoint (§7), and none
//     where it hasn't;
//   - a DPoP-bound access token, or a Bearer one where the server issues
//     that (§13.2).
//
// Some checks are the holder's, and never relax: https outside
// Development, the issuer's and Authorization Server's identifiers
// matching their metadata exactly, an offer's Authorization Server being
// one the issuer lists, PKCE, PAR and the authorization response's iss
// in the authorization code grant, and every credential checked against
// Config.IssuerRoots. ProfileHAIP also refuses an issuer outside HAIP
// 1.0 §4, with ErrProfileViolation: see its doc comment.
//
// An issuance runs:
//
//	s, err := w.StartIssuance(ctx, offerURI)  // show s.Offer()
//	defer s.Close(ctx)
//	// the authorization code grant:
//	authURL, err := s.BeginAuthorization(ctx) // open in a browser
//	err = s.CompleteAuthorization(ctx, redirect)
//	// or the pre-authorized code grant:
//	err = s.RedeemPreAuthorizedCode(ctx, pin)
//	result, err := s.RequestCredentials(ctx)  // stored; poll result.Deferred
//
// A deferred credential outlives its Issuance: after a restart,
// w.Deferred(ctx) lists the pending ones to Poll, kept in the
// DeferredStore with the access token and DPoP key ID that poll them.
//
// and a presentation:
//
//	p, err := w.StartPresentation(ctx, requestLink) // show p.Verifier()
//	queries, sets := p.Queries(), p.CredentialSets()
//	sel := walletflow.Selection{"pid": {credentialID}} // the holder's (or app's) choice,
//	                                                   // or start from p.DefaultSelection(ctx)
//	disclosed, err := p.Preview(ctx, sel)              // holder consents
//	presented, err := p.Respond(ctx, sel)              // or p.Decline(ctx)
//
// The wallet presents exactly the Selection, after checking it answers
// the request (ErrInvalidSelection otherwise): which credential answers
// which query, and which credential_sets option, are the application's
// to decide.
//
// A Digital Credentials API request names its protocol, and that, not
// the platform, decides which entry point answers it: "openid4vp-v1-
// unsigned", "-signed" and "-multisigned" (wallet.DCAPIProtocolUnsigned
// and the rest) are OpenID4VP, answered by StartDCAPIPresentation, and
// "org-iso-mdoc" (mdocdcapi.Protocol) is ISO/IEC TS 18013-7 Annex C,
// answered by StartMdocPresentation. Today Chrome on Android sends
// OpenID4VP, through Credential Manager, and Safari on iOS org-iso-mdoc,
// to a document provider.
//
// Each takes the origin the platform reports for the calling page,
// which the response is bound to: on iOS,
// ISO18013MobileDocumentRequestContext.requestingWebsiteOrigin,
// serialized as scheme://host[:port] with no trailing slash; on Android,
// Credential Manager's CallingAppInfo origin, a web origin for a browser
// on the privileged-browsers list, or "android:apk-key-hash:" and the
// app's signing certificate digest for an app. StartMdocPresentation
// takes web origins only (mdocdcapi.ParseRequest refuses anything else).
// Never take the origin from the request itself.
//
// An OpenID4VP request over the Digital Credentials API (OpenID4VP 1.0
// Appendix A) is a Presentation too, answered through the platform
// rather than the network:
//
//	p, err := w.StartDCAPIPresentation(ctx, protocol, data, origin) // show p.Verifier().Origin
//	presented, err := p.Respond(ctx, sel)                           // or p.Decline(ctx)
//	// return presented.DCAPIResponse to the platform
//
// An mdoc asked for as "org-iso-mdoc" (package mdocdcapi) is presented
// the same way, without OpenID4VP:
//
//	p, err := w.StartMdocPresentation(ctx, data, origin) // show p.Origin(), p.Reader()
//	requests := p.Requests()                             // documents, elements, held mdocs
//	presented, err := p.Respond(ctx, 0, credentialID, elements) // holder consents
//	// return presented.EncryptedResponse to the platform; to decline, cancel there
//
// The reader is recognized when it signs the request with a certificate
// under Config.MdocReaderRoots that Config.MdocReaderLeafPolicy accepts;
// otherwise the holder is shown its origin, or, with
// Config.RequireTrustedMdocReader, the request is refused.
// Its copies are recorded as shown to the origin, as an OpenID4VP
// Verifier over the Digital Credentials API would be ("origin:" +
// origin).
//
// In person, over Bluetooth (ISO/IEC 18013-5 device retrieval, package
// proximity), the holder shows a QR code and the reader that scans it
// connects:
//
//	p, err := w.StartProximityPresentation()  // mdoc peripheral server mode
//	qr := p.QRCode()                           // show it; advertise p.ServiceUUID()
//	ev := p.HandleMessage(ctx, msg)            // each message the transport receives:
//	                                           // send ev.Send; ev.Ended: disconnect
//	reader, requests := p.Reader(), p.Requests() // once the request arrives: ask the holder
//	presented, err := p.Respond(ctx, 0, credentialID, elements) // send presented.Send
//	// or, to decline, send p.Terminate()
//
// The app carries the BLE GATT transport, whole messages in and out;
// walletflow does the rest. The reader is recognized as for
// org-iso-mdoc (Config.MdocReaderRoots, MdocReaderLeafPolicy), and with
// Config.RequireTrustedMdocReader a request from any other reader ends
// the session, with an event whose Err wraps ErrUntrustedVerifier,
// before the holder sees it.
//
// When an issuer offers batch issuance, a credential arrives as several
// copies (Config.BatchSize), each bound to its own key. By default each
// presentation uses a copy no Verifier has seen, so presentations can't
// be linked by the credential, not even by one Verifier; with
// Config.CopyPolicy CopyPerVerifier, a Verifier is shown the copy it has
// seen before, and only a new Verifier a new copy. Each copy records
// which Verifiers saw it, as hashes of their client_ids
// (StoredCredential.ShownTo). Once every copy has been presented, the
// one shown to the fewest Verifiers is reused, which those Verifiers can
// link. With Config.RequestRefresh, the authorization code
// grant asks for a refresh token (offline_access), kept in a GrantStore,
// and w.RefreshCredential(ctx, id) replaces a credential's copies with a
// fresh batch without the holder (OpenID4VCI 1.0 §13.5); when it can't
// (ErrReissueRequired), receive the credential again from a new offer.
//
// Every key walletflow creates is P-256 (ES256). Each issuance uses a
// fresh DPoP key and, where it authenticates with one, a fresh wallet
// instance key (with a fresh Wallet Attestation), deleted by
// Issuance.Close (the DPoP key once no pending deferred credential polls
// with it), so issuers can't link two issuances by them; each credential
// is bound to its own holder key, deleted with it. An issuance that kept
// a refresh grant keeps the key its refreshes need with it instead,
// until the last credential using the grant is deleted: the instance
// key, since every refresh must authenticate with the same one
// (draft-ietf-oauth-attestation-based-client-auth-07 §10.3), or for a
// grant that authenticated no client, the DPoP key its refresh token is
// bound to (RFC 9449 §5).
package walletflow
