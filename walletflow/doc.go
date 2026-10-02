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
// digest), a CredentialStore, and a WalletProvider that attests the
// wallet and its keys. walletflow owns the protocols: every network
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
// and a presentation:
//
//	p, err := w.StartPresentation(ctx, requestLink) // show p.Verifier()
//	candidates := p.Candidates()                    // holder chooses
//	disclosed, err := p.Preview(ctx, chosen)        // holder consents
//	presented, err := p.Respond(ctx, chosen)        // or p.Decline(ctx)
//
// Every key walletflow creates is P-256 (ES256). Each issuance uses a
// fresh wallet instance key (with a fresh Wallet Attestation) and a
// fresh DPoP key, deleted by Issuance.Close, so issuers can't link two
// issuances by them; each credential is bound to its own holder key,
// deleted with it.
package walletflow
