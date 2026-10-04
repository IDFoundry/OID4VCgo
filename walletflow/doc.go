// Package walletflow is a holder's wallet as a set of sessions: it
// receives credentials from a Credential Offer (OpenID4VCI 1.0, HAIP
// 1.0 §4) and presents them in answer to an Authorization Request
// (OpenID4VP 1.0, HAIP 1.0 §5), orchestrating the wallet package and
// fapigo/client step by step so an app can stop at each point that needs
// the holder: to show an offer, open the issuer's authorization page,
// ask for a PIN, or choose what to disclose.
//
// The app supplies the platform: a KeyStore whose keys never leave it
// (secure hardware on a phone: walletflow only asks a Key to sign a
// digest), a CredentialStore, a WalletProvider that attests the
// wallet and its keys, and optionally a DeferredStore, an
// AuthorizationStore and a GrantStore, so deferred credentials, an
// authorization in progress and refresh tokens survive a restart
// (Wallet.Deferred, Wallet.ResumeIssuance, Wallet.RefreshCredential).
// At production assurance, receiving credentials needs a Durable
// AuthorizationStore and a KeyStore declaring durable custody. walletflow owns the protocols: every network
// request, every protocol message, and every check on what comes back.
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
// When an issuer offers batch issuance, a credential arrives as several
// copies (Config.BatchSize), each bound to its own key, and each
// presentation uses a copy no Verifier has seen, so presentations can't
// be linked by the credential. Once every copy has been presented, the
// first is reused. With Config.RequestRefresh, the authorization code
// grant asks for a refresh token (offline_access), kept in a GrantStore,
// and w.RefreshCredential(ctx, id) replaces a credential's copies with a
// fresh batch without the holder (OpenID4VCI 1.0 §13.5); when it can't
// (ErrReissueRequired), receive the credential again from a new offer.
//
// Every key walletflow creates is P-256 (ES256). Each issuance uses a
// fresh wallet instance key (with a fresh Wallet Attestation) and a
// fresh DPoP key, deleted by Issuance.Close (the DPoP key once no
// pending deferred credential polls with it), so issuers can't link two
// issuances by them; each credential is bound to its own holder key,
// deleted with it. An issuance that kept a refresh grant keeps its
// instance key with it instead, since every refresh must authenticate
// with the same one (draft-ietf-oauth-attestation-based-client-auth-07
// §10.3), until the last credential using the grant is deleted.
package walletflow
